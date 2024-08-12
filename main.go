package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	errorapi "gitea_assist/error"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	api "code.gitea.io/gitea/modules/structs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/gorilla/mux"
)

const DEFAULT_TEAM_NAME = "default"

type GiteaAccess struct {
	URL      string
	Username string
	Password string
}

type MergeContext struct {
	Upstream         *git.Repository
	UpstreamCloneURL string
	UpstreamName     string
	UpstreamBranch   string
	UpstreamHash     *plumbing.Hash
	Fork             *git.Repository
	ForkCloneURL     string
	ForkName         string
	ForkBranch       string
	ForkHash         *plumbing.Hash
	ForkIsEmpty      bool
}

type CreateUserOptions struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type DeleteUserOptions struct {
	Username string `json:"username"`
	Purge    bool   `json:"purge"`
}

type RepoOptions struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	Private     bool   `json:"private"`
}

type ModifyRepoOptions struct {
	Name    string                     `json:"name"`
	Owner   string                     `json:"owner"`
	Branch  string                     `json:"branch"`
	Message string                     `json:"message"`
	Files   []*api.ChangeFileOperation `json:"files"`
}

type PatchRepoOptions struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Private     bool   `json:"private,omitempty"`
}

type AddCollaboratorOptions struct {
	Name             string `json:"name"`
	Owner            string `json:"owner"`
	CollaboratorName string `json:"collaborator_name"`
	Permission       string `json:"permission"`
}

type RemoveCollaboratorOptions struct {
	Name             string `json:"name"`
	Owner            string `json:"owner"`
	CollaboratorName string `json:"collaborator_name"`
}

type CreateSSHOptions struct {
	KeyName  string `json:"key_name"`
	Key      string `json:"key"`
	Username string `json:"username"`
}

type ForkOptions struct {
	Owner    string `json:"owner"`
	NewOwner string `json:"newOwner"`
	Repo     string `json:"repo"`
}

type AddHookOptions struct {
	Name    string `json:"name"`
	Owner   string `json:"owner"`
	HookId  string `json:"hook_id"`
	Content string `json:"content"`
}

type OrgOptions struct {
	OrgName string `json:"org_name"`
}

type AtomicCounter struct {
	val int64
}

var access *GiteaAccess
var forkCounter *AtomicCounter
var fullname string
var assistToken string

func init() {
	access, _ = getAccess()
	fullname, _ = getFullname()
	forkCounter = &AtomicCounter{}
	assistToken = assistAdminToken()
}

// Next returns the next number in sequence
func (ac *AtomicCounter) Next() int64 {
	return atomic.AddInt64(&ac.val, 1)
}

// Bare minimum auth middleware in lieu of major restructuring.
// Assumes we are reading a K8S secret mounted with the other secrets
// read in by the init() func at /etc/assist-secret/assist-token
// This can be prepopulated by the mk_password.py file.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that we indicate authorization may vary
		w.Header().Add("Vary", "Authorization")

		// Returns "" empty string if nothing is found.
		authorizationHeader := r.Header.Get("Authorization")

		// If no auth header, set user as anonymous
		if authorizationHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrUnauthorized, message))
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrUnauthorized, message))
			return
		}

		token := headerParts[1]

		// Trim the whitespace from file
		if assistToken != strings.TrimSpace(token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrUnauthorized, message))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func assistAdminToken() string {
	admin, err := os.ReadFile("/etc/assist-secret/assist-token")
	if err != nil {
		log.Fatalf("init()-Error reading assist-token file: %v", err)
	}
	assistToken := strings.TrimSpace(string(admin))
	return assistToken
}

func getAccess() (*GiteaAccess, error) {
	var access *GiteaAccess

	username, err := os.ReadFile("/etc/assist-secret/gitea-username")
	if err != nil {
		log.Fatalf("Error reading username: %v", err)
		return access, err
	}

	password, err := os.ReadFile("/etc/assist-secret/gitea-password")
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
		return access, err
	}

	url, err := os.ReadFile("/etc/assist-config/gitea-api-url")
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
		return access, err
	}

	access = &GiteaAccess{
		URL:      string(url),
		Username: string(username),
		Password: string(password),
	}

	return access, nil
}

func getFullname() (string, error) {
	if fullname, err := os.ReadFile("/etc/assist-config/fullname"); err == nil {
		return string(fullname), nil
	} else {
		log.Fatalf("Error reading fullname: %v", err)
		return "", err
	}

}

func downloadPathFromZip(zipBytes []byte, path string) ([]byte, *errorapi.APIError) {
	reader := bytes.NewReader(zipBytes)
	zipReader, err := zip.NewReader(reader, int64(len(zipBytes)))
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("unable to parse zipfile from bytes for path %v", path))
	}
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	for _, zFile := range zipReader.File {
		if strings.HasPrefix(strings.ToLower(zFile.Name), strings.ToLower(path)) {
			fileReader, err := zFile.Open()
			if err != nil {
				log.Printf("failed to open reader for %v", zFile)
			}
			defer fileReader.Close()

			// We don't use TrimPrefix here because it's case-sensitive and we don't care about case
			trimmedFilePath := zFile.Name[len(path):]
			// Remove leading slash
			trimmedFilePath = strings.TrimPrefix(trimmedFilePath, "/")

			// This may corrupt ZIP archive utilities if not skipped
			// (e.g. this will break for MacOS's Archive Utility)
			if trimmedFilePath == "" {
				continue
			}

			header := &zip.FileHeader{
				Name:     trimmedFilePath,
				Method:   zip.Store,
				Modified: zFile.Modified,
			}

			fileWriter, err := zipWriter.CreateHeader(header)
			if err != nil {
				log.Printf("failed to create header for %v", zFile.Name)
			}

			if _, err := io.Copy(fileWriter, fileReader); err != nil {
				return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to write %v to new zip file", zFile.Name))
			}

		}
	}

	if err = zipWriter.Close(); err != nil {
		log.Printf("failed to close zip writer %v", err)
	}
	return buf.Bytes(), nil
}

func createTokenForUser(giteaBaseURL, adminUsername, adminPassword, username, name string, scopes []string) (*api.AccessToken, error) {
	var token api.AccessToken

	option := api.CreateAccessTokenOption{
		Name:   name,
		Scopes: scopes,
	}

	jsonData, _ := json.Marshal(option)

	req, err := http.NewRequest("POST", giteaBaseURL+"/admin/users/"+username+"/tokens", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create token for user %s", username)
	}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

func deleteTokenForUser(giteaBaseURL, adminUsername, adminPassword, targetUser, tokenId string) error {
	req, err := http.NewRequest("DELETE", giteaBaseURL+"/admin/users/"+targetUser+"/tokens/"+tokenId, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete token with id %s for user %s", tokenId, targetUser)
	}

	return nil
}

// findForks retrieves a list of forks for a given repository URL using
// basic authentication with the provided username and password. The
// function returns a slice of api.Repository representing the forks and
// an error if there's an issue with the HTTP request or response parsing.
func findForks(repoURL, username, password string) ([]api.Repository, *errorapi.APIError) {
	var forks []api.Repository

	client := &http.Client{}
	req, err := http.NewRequest("GET", repoURL+"/forks", nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.SetBasicAuth(string(username), string(password))

	resp, err := client.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&forks)

	if err != nil {
		_, err := io.ReadAll(resp.Body)
		return nil, errorapi.WrapError(errorapi.ErrRequestParseError, fmt.Sprintf("unable to parse response from %s/forks %v", repoURL, err))
	}

	return forks, nil
}

func getRemoteUrlFromRepo(repo *api.Repository) string {
	return repo.SSHURL
}

func getRemoteUrl(giteaBaseURL, adminUsername, adminPassword, owner string, repo string) (string, *errorapi.APIError) {
	client := &http.Client{}
	repoURL := fmt.Sprintf("%s/repos/%s/%s", giteaBaseURL, owner, repo)
	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := client.Do(req)
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("could not retrieve remote url %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var responseError map[string]interface{}

		json.NewDecoder(resp.Body).Decode(&responseError)
		return "", errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to retrieve remote url; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"]))
	}

	var repository api.Repository
	json.NewDecoder(resp.Body).Decode(&repository)

	return getRemoteUrlFromRepo(&repository), nil
}

func transferRepoOwnership(giteaBaseURL, adminUsername, adminPassword, owner, repo, newOwner string) error {
	options := api.TransferRepoOption{
		NewOwner: newOwner,
	}
	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("POST", giteaBaseURL+"/repos/"+owner+"/"+repo+"/transfer", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to transfer repository ownership; HTTP status code: %d", resp.StatusCode)
	}

	return nil
}

func renameRepo(giteaBaseURL, adminUsername, adminPassword, owner, currentRepoName, newRepoName string) error {
	options := api.EditRepoOption{
		Name: &newRepoName,
	}

	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("PATCH", giteaBaseURL+"/repos/"+owner+"/"+currentRepoName, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("failed to rename repository; HTTP status code: %d", resp.StatusCode)
	}

	return nil
}

func createTeam(giteaBaseURL, adminUsername, adminPassword, orgName, teamName, description string) *errorapi.APIError {
	reqURL := fmt.Sprintf("%s/orgs/%s/teams", giteaBaseURL, orgName)

	// Define team details
	options := api.CreateTeamOption{
		Name:                    teamName,
		Description:             description,
		IncludesAllRepositories: true,
		CanCreateOrgRepo:        true,
		Permission:              "write",
		UnitsMap:                map[string]string{"repo.code": "write"},
	}

	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to create team; HTTP status code: %d", resp.StatusCode))
	}

	return nil
}

func getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, teamName string) (int64, error) {
	reqURL := fmt.Sprintf("%s/orgs/%s/teams", giteaBaseURL, orgName)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return -1, err
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()

	var teams []api.Team
	json.NewDecoder(resp.Body).Decode(&teams)

	for _, team := range teams {
		if team.Name == teamName {
			return team.ID, nil
		}
	}

	return -1, fmt.Errorf("team %s not found in organization %s", teamName, orgName)
}

func addUserToTeam(giteaBaseURL, adminUsername, adminPassword, orgName, teamName, userName string) *errorapi.APIError {
	teamID, err := getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, teamName)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	reqURL := fmt.Sprintf("%s/teams/%d/members/%s", giteaBaseURL, teamID, userName)
	req, err := http.NewRequest("PUT", reqURL, bytes.NewBuffer(nil))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		var responseError map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseError)
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to add user to team; HTTP status code: %d, message: %s, url: %v", resp.StatusCode, responseError["message"], reqURL))
	}

	return nil
}

func deleteUserFromTeam(giteaBaseURL, adminUsername, adminPassword, orgName, teamName, userName string) *errorapi.APIError {
	teamID, err := getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, teamName)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	reqURL := fmt.Sprintf("%s/teams/%d/members/%s", giteaBaseURL, teamID, userName)
	req, err := http.NewRequest("DELETE", reqURL, bytes.NewBuffer(nil))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		var responseError map[string]interface{}
		log.Printf("%v %v", resp.StatusCode, reqURL)
		json.NewDecoder(resp.Body).Decode(&responseError)
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to delete user from team; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"]))
	}

	return nil
}

func createWebhook(giteaBaseURL, adminUsername, adminPassword, owner, repo, fullname string) error {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/hooks", giteaBaseURL, owner, repo)

	config := api.CreateHookOptionConfig{
		"content_type": "json",
		"url":          "http://" + fullname + ":9000/onPush",
	}

	options := api.CreateHookOption{
		Type:   "gitea",
		Events: []string{"push"},
		Config: config,
		Active: true,
	}

	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var responseError map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseError)
		return fmt.Errorf("failed to create webhook; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"])
	}

	return nil
}

// cloneRepoIntoDir clones a given Git repository into a specified directory.
// If the parent directory doesn't exist, it's created. The function takes the
// parent directory path, desired repository name for the clone, and the clone
// URL as input. It returns a pointer to the cloned git.Repository and an error
// if there's an issue with directory creation or the cloning process.
func cloneRepoIntoDir(parentDir, repoName, cloneURL string, allowEmpty bool) (*git.Repository, error) {
	// Check if the parent directory exists. If not, create it.
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		err := os.MkdirAll(parentDir, 0755)
		if err != nil {
			return nil, err
		}
	}

	// Form the full path for the repo
	fullPath := filepath.Join(parentDir, repoName)

	// Clone the given repository into the specified path
	repo, err := git.PlainClone(fullPath, false, &git.CloneOptions{
		URL:               cloneURL,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})

	if err == transport.ErrEmptyRemoteRepository && allowEmpty {
		return nil, nil
	}

	if err == nil {
		log.Printf("Cloned %s into %s", cloneURL, fullPath)
	} else {
		log.Printf("Failed to clone %s", cloneURL)
	}

	return repo, err
}

func InitRepoWithRemote(directory, remoteURL, branchName string) (*git.Repository, error) {
	// Initialize a new repository
	repo, err := git.PlainInit(directory, false)
	if err != nil {
		return nil, err
	}

	// Set the remote
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	if err != nil {
		return nil, err
	}

	// Create and set the default branch to the specified branch name
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(branchName))
	err = repo.Storer.SetReference(headRef)
	if err != nil {
		return nil, err
	}

	return repo, nil
}

// getDiffBetweenUpstreamAndFork calculates the diff between an upstream Git
// repository and its fork. It sets the original repo as an "upstream" remote,
// fetches from the upstream, retrieves commits for specified branches, and
// calculates the diff between them. The function operates within a given
// MergeContext (mc) containing details about repositories, branches, etc.
// It returns the calculated diff as an *object.Patch and an error if issues
// arise during the process.
func getDiffBetweenUpstreamAndFork(mc *MergeContext) ([]*object.Patch, error) {
	// Add the original repo as an upstream remote
	_, err := mc.Fork.CreateRemote(&config.RemoteConfig{
		Name: "upstream",
		URLs: []string{mc.UpstreamCloneURL},
	})
	if err != nil && err != git.ErrRemoteExists {
		return nil, err
	}

	// Fetch from the upstream repository
	err = mc.Fork.Fetch(&git.FetchOptions{
		RemoteName: "upstream",
	})
	if err != nil {
		return nil, err
	}

	// Get the commits for the branches
	upstreamRef, err := mc.Fork.Reference(plumbing.ReferenceName("refs/remotes/upstream/"+mc.UpstreamBranch), true)
	if err != nil {
		return nil, err
	}
	upstreamHash := upstreamRef.Hash()

	upstreamCommit, err := mc.Fork.CommitObject(upstreamHash)
	if err != nil {
		return nil, err
	}
	mc.UpstreamHash = &upstreamHash

	var patches []*object.Patch

	if !mc.ForkIsEmpty {
		forkRef, err := mc.Fork.Reference(plumbing.ReferenceName("refs/heads/"+mc.ForkBranch), true)
		if err != nil {
			return nil, err
		}
		forkHash := forkRef.Hash()
		mc.ForkHash = &forkHash

		forkCommit, err := mc.Fork.CommitObject(forkHash)
		if err != nil {
			return nil, err
		}

		// Calculate the diff between the two commits
		diff, err := upstreamCommit.Patch(forkCommit)
		if err != nil {
			return nil, err
		}
		patches = append(patches, diff)
	} else {
		emptyTreeHash := plumbing.NewHash("4b825dc642cb6eb9a060e54bf8d69288fbee4904")
		emptyTree, err := mc.Fork.TreeObject(emptyTreeHash)
		if err != nil {
			log.Printf("Failed to get empty tree: %s", err)
		}

		// Calculate the diff between the two commits
		upstreamTree, err := upstreamCommit.Tree()
		if err != nil {
			return nil, err
		}

		if changes, err := object.DiffTree(emptyTree, upstreamTree); err == nil {
			// Iterate over the changes to collect individual patches
			for _, change := range changes {
				patch, err := change.Patch()
				if err != nil {
					log.Printf("Failed to generate patch: %s", err)
				}
				patches = append(patches, patch)
			}
		} else {
			return nil, err
		}
	}

	log.Printf("Collected diffs between %s and %s", mc.UpstreamName, mc.ForkName)

	return patches, nil
}

// filterPatches filters the given list of file patches based on criteria.
// Currently, all patches are returned without filtering, but there's a TODO
// to filter out patches representing merge conflicts. The function operates
// within the context of a given MergeContext (mc) and returns a slice of
// diff.FilePatch with the filtered patches.
func filterPatches(mc *MergeContext, filePatches []diff.FilePatch) []diff.FilePatch {
	filteredPatches := make([]diff.FilePatch, 0)

	for _, fp := range filePatches {
		// In the degenerate case, we keep all patches.
		// TODO: Add logic to filter out patches representing merge conflicts.
		filteredPatches = append(filteredPatches, fp)
	}

	log.Printf("Filtering out merge conflicts")
	return filteredPatches
}

// readFileContents reads the contents of a specified file from a Git worktree
// and retrieves its mode. The function takes a pointer to the git.Worktree and
// a diff.File representing the file. It returns the contents as a byte slice, a
// pointer to the file mode (os.FileMode), and an error if there's an issue with
// opening, reading, or stat'ing the file.
func readFileContents(wt *git.Worktree, df diff.File) ([]byte, *os.FileMode, error) {
	file, err := wt.Filesystem.Open(df.Path())
	if err != nil {
		log.Fatalf("Failed to open file %s: %s", df.Path(), err)
		return nil, nil, err
	}
	defer file.Close()

	stat, err := wt.Filesystem.Stat(df.Path())
	if err != nil {
		log.Fatalf("Failed to stat file %s: %s", df.Path(), err)
		return nil, nil, err
	}
	mode := stat.Mode()

	contents, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read file %s: %s", df.Path(), err)
		return nil, nil, err
	}
	return contents, &mode, nil
}

// writeContents writes the provided contents to a specified file in a Git worktree
// and sets its mode based on the provided os.FileMode. The function takes a pointer
// to the git.Worktree, a diff.File for the target, the contents as a byte slice,
// and a pointer to the file mode. It returns an error if there's an issue with
// opening or writing to the file.
func writeContents(wt *git.Worktree, df diff.File, contents []byte, mode *os.FileMode) error {
	file, err := wt.Filesystem.OpenFile(df.Path(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, *mode)
	if err != nil {
		log.Fatalf("Failed to open file %s: %s", df.Path(), err)
		return err
	}
	defer file.Close()
	if _, err := file.Write(contents); err != nil {
		log.Fatalf("Failed to write file %s: %s", df.Path(), err)
		return err
	}
	return nil
}

// applyChanges applies file patches to a fork based on a given MergeContext (mc).
// The function reads changes from the upstream worktree and writes to the fork's.
// It handles file deletions, additions, and modifications. After applying patches,
// it commits the changes to the fork with a message indicating a merge from upstream.
// The function returns an error if there's an issue with worktrees, applying patches,
// or committing the changes.
func applyChanges(mc *MergeContext, filePatches []diff.FilePatch) error {
	// Get the worktree for the Fork repository where changes will be applied.
	wtFork, err := mc.Fork.Worktree()
	if err != nil {
		return err
	}
	wtUpstream, err := mc.Upstream.Worktree()
	if err != nil {
		return err
	}

	// Iterate over each FilePatch.
	for _, fp := range filePatches {
		from, to := fp.Files()

		// Handle file deletions.
		if to == nil {
			_, err := wtFork.Remove(from.Path())
			if err != nil {
				return err
			}
		} else {
			contents, mode, err := readFileContents(wtUpstream, to)
			if err != nil {
				log.Fatalf("Failed to read file %s from worktree: %s", to.Path(), err)
			}
			if err = writeContents(wtFork, to, contents, mode); err != nil {
				log.Fatalf("Failed to write new file %s to worktree: %s", to.Path(), err)
			}
			if _, err := wtFork.Add(to.Path()); err != nil {
				log.Fatalf("Failed to add file %s to worktree: %s", to.Path(), err)
				return err
			}
		}
	}

	// Commit the changes to the fork repository.
	var parents []plumbing.Hash = []plumbing.Hash{*mc.UpstreamHash}

	if mc.ForkHash != nil {
		parents = append(parents, *mc.ForkHash)
	}

	options := git.CommitOptions{
		Author: &object.Signature{
			Name:  "Mr McMergybot",
			Email: "merge-botCMXX@renci.org",
			When:  time.Now(),
		},
		Parents: parents,
	}
	if _, err = wtFork.Commit("Merge changes from "+mc.UpstreamName, &options); err != nil {
		log.Printf("Failed to merge %s and %s: %v", mc.UpstreamName, mc.ForkName, err)
		return err
	} else {
		log.Printf("Merged changes from %s into %s", mc.UpstreamName, mc.ForkName)
	}

	return nil
}

// pushFork pushes changes from a fork repository to its remote based on a
// given MergeContext (mc). It uses the provided credentials (creds) for
// authentication. If the fork is up-to-date with the remote, it logs
// "Everything is up-to-date.". On successful push, a confirmation is logged.
// The function returns an error if there's an issue pushing the changes.
func pushFork(mc *MergeContext, access *GiteaAccess) error {
	// Push using default options
	options := &git.PushOptions{
		RemoteName: "origin",
		Auth: &gitHTTP.BasicAuth{
			Username: access.Username,
			Password: access.Password,
		},
	}
	if err := mc.Fork.Push(options); err != nil {
		if err == git.NoErrAlreadyUpToDate {
			log.Println("Everything is up-to-date.")
			return nil
		}
		log.Printf("failed to push to %s", mc.ForkName+"/"+mc.ForkBranch)
		return err
	}
	log.Printf("successfully pushed merge to %s", mc.ForkName+"/"+mc.ForkBranch)
	return nil
}

// processMerge filters and applies a series of file patches to a fork repository
// based on the provided MergeContext (mc). It first filters the patches, then
// applies the changes. The function returns an error if there's an issue during
// the process.
func processMerge(mc *MergeContext, filePatches []diff.FilePatch) error {
	filteredPatches := filterPatches(mc, filePatches)
	return applyChanges(mc, filteredPatches)
}

func createUser(giteaBaseURL, adminUsername, adminPassword, username, password, email string) (bool, *errorapi.APIError) {
	/*
			user := giteaAPI.CreateUserOption{
				Username: username,
				Email:    "jeffw@renci.org",
				Password: password,
			}
		type CreateUser struct {
			Username string `json:"username" binding:"Required;Username;MaxSize(40)"`
			Email    string `json:"email" binding:"Required;Email;MaxSize(254)"`
			Password string `json:"password" binding:"Required;MaxSize(255)"`
		}
	*/
	mustChangePassword := false
	user := api.CreateUserOption{
		Username: username,
		Email:    email,
		Password: password,
		// I have no idea why this wants a pointer to a bool...
		MustChangePassword: &mustChangePassword,
	}

	jsonData, _ := json.Marshal(user)

	req, err := http.NewRequest("POST", giteaBaseURL+"/admin/users", bytes.NewBuffer(jsonData))
	if err != nil {
		return false, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}
	//req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return false, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("create user returned unexpected status: %s", string(body)))
	}
	return true, nil
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestReadError)
		return
	}

	var options CreateUserOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	if options.Username == "" || options.Password == "" || options.Email == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Username, password, and email must be provided"))
		return
	}

	log.Println("Received User Data:", options)
	if success, err := createUser(access.URL, access.Username, access.Password, options.Username, options.Password, options.Email); success {
		// Respond to the client
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User created successfully"))
	} else {
		if err == nil {
			err = errorapi.WrapError(errorapi.ErrInternalServerError, "User creation failed ")
		}
		errorapi.HandleError(w, err)
	}
}

func deleteUser(giteaBaseURL, adminUsername, adminPassword, username string, purge bool) (bool, *errorapi.APIError) {
	url := fmt.Sprintf("%s/admin/users/%s?purge=%t", giteaBaseURL, username, purge)
	req, _ := http.NewRequest("DELETE", url, nil)

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body) //HS: What happens if this fails?
		err := errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Failed to delete user: %s", string(body)))
		log.Println(err.Error())
		return false, err
	}
	return true, nil
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestParseError)
		return
	}

	var options DeleteUserOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestParseError)
		return
	}

	if options.Username == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Username must be provided"))
		return
	}

	log.Println("Received User Data:", options)
	if success, err := deleteUser(access.URL, access.Username, access.Password, options.Username, options.Purge); success {
		// Respond to the client
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User deleted successfully"))
	} else {
		if err == nil {
			err = errorapi.WrapError(errorapi.ErrInternalServerError, "User deletion failed")
		}
		errorapi.HandleError(w, err)
	}
}

func getUser(giteaBaseURL, adminUsername, adminPassword, username string) ([]byte, *errorapi.APIError) {
	url := fmt.Sprintf("%s/users/%s", giteaBaseURL, username)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	// Set Basic Authentication header
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errapi *errorapi.APIError
		if resp.StatusCode == 404 {
			errapi = errorapi.WrapError(errorapi.ErrNotFound, fmt.Sprintf("did not find the user: %s", username))
		} else {
			errapi = errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error getting user, gitea returned status: %d", resp.StatusCode))
		}
		return nil, errapi
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrResponseReadError, err.Error())
	}

	return bodyBytes, nil
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	// Retrieve the username from the query parameters
	username := r.URL.Query().Get("username")
	if username == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Username not provided"))
		return
	}

	if resp, err := getUser(access.URL, access.Username, access.Password, username); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	} else {
		errorapi.HandleError(w, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateUser(w, r)
	case http.MethodGet:
		handleGetUser(w, r)
	case http.MethodDelete:
		handleDeleteUser(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func getSSHKeysForUser(giteaBaseURL, adminUsername, adminPassword, username string) ([]api.PublicKey, *errorapi.APIError) {
	req, err := http.NewRequest("GET", giteaBaseURL+"/users/"+username+"/keys/", nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, errorapi.WrapError(errorapi.ErrResponseReadError, err.Error())
	}

	var publicKeys []api.PublicKey
	err = json.Unmarshal(bodyBytes, &publicKeys)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrResponseReadError, fmt.Sprintf("Gitea response read error while getting user ssh keys: %v", err))
	}

	return publicKeys, nil
}

func handleGetUserSSHKeys(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Username must be provided to list SSH keys"))
		return
	}

	if keys, err := getSSHKeysForUser(access.URL, access.Username, access.Password, username); err == nil {
		jsonData, _ := json.Marshal(keys)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jsonData))
	} else {
		errormsg := fmt.Sprintf("Failed to get user ssh keys with error: %v.", err)
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, errormsg))
	}
}

func deleteSSHKeyForUser(giteaBaseURL, adminUsername, adminPassword, username, name string) *errorapi.APIError {
	keys, reterr := getSSHKeysForUser(giteaBaseURL, adminUsername, adminPassword, username)
	if reterr != nil {
		return errorapi.WrapError(reterr, "Failed to get User SSH Keys")
	}

	var id int64 = -1
	for _, key := range keys {
		if key.Title == name {
			id = key.ID
			break
		}
	}
	if id == -1 {
		return nil // No key found
	}

	url := fmt.Sprintf("%s/admin/users/%s/keys/%d", giteaBaseURL, username, id)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error deleting ssh keys: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error sending delete request %v", err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != 404 {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Delete Keys request returned status: %d", resp.StatusCode))
	}

	return nil
}

func handleDeleteUserSSHKey(w http.ResponseWriter, r *http.Request) {
	keyName := r.URL.Query().Get("key_name")
	username := r.URL.Query().Get("username")
	if keyName == "" || username == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Key name and Username must be provided to delete SSH keys"))
		return
	}

	if err := deleteSSHKeyForUser(access.URL, access.Username, access.Password, username, keyName); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Successfully deleted SSH key"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "Error Deleting SSH Key Pair"))
	}
}

func createSSHKeyForUser(giteaBaseURL, adminUsername, adminPassword, username, key, name string) *errorapi.APIError {
	reterr := deleteSSHKeyForUser(giteaBaseURL, adminUsername, adminPassword, username, name)
	if reterr != nil {
		return errorapi.WrapError(reterr, "Failed to delete existing User SSH Keys")
	}

	data := api.CreateKeyOption{
		Key:      key,
		Title:    name,
		ReadOnly: true,
	}

	jsonData, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", giteaBaseURL+"/admin/users/"+username+"/keys", bytes.NewBuffer(jsonData))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating ssh keys, returned error code: %d", resp.StatusCode))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrResponseReadError, err.Error())
	}

	var publicKeyResponse api.PublicKey
	err = json.Unmarshal(bodyBytes, &publicKeyResponse)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrResponseReadError, fmt.Sprintf("Gitea response read error after creating user ssh keys: %v", err))
	}

	fmt.Println(publicKeyResponse.ID, publicKeyResponse.Key)

	return nil
}

func handleCreateUserSSHKey(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestReadError)
		return
	}

	var options CreateSSHOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestParseError)
		return
	}

	if options.Key == "" || options.KeyName == "" || options.Username == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Key, KeyName, and Username must be provided to create the SSH key"))
		return
	}

	if err := createSSHKeyForUser(access.URL, access.Username, access.Password, options.Username, options.Key, options.KeyName); err == nil {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Successfully created SSH key"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "SSH Key creation failed"))
	}
}

func handleUserSsh(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGetUserSSHKeys(w, r)
	case http.MethodPost:
		handleCreateUserSSHKey(w, r)
	case http.MethodDelete:
		handleDeleteUserSSHKey(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func createRepoForUser(giteaBaseURL, adminUsername, adminPassword, username, name, description string, private bool) (*api.Repository, *errorapi.APIError) {
	data := api.CreateRepoOption{
		Name:        name,
		Description: description,
		Private:     private,
	}

	jsonData, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", giteaBaseURL+"/admin/users/"+username+"/repos", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Failed to create repo for user: %s, returned error code: %d", username, resp.StatusCode))
	}

	var repository api.Repository
	json.NewDecoder(resp.Body).Decode(&repository)

	return &repository, nil
}

func handleCreateRepo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestReadError)
		return
	}

	var options RepoOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestParseError)
		return
	}

	if options.Name == "" || options.Description == "" || options.Owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Name, description, and owner must be provided for the repo"))
		return
	}

	fmt.Println("Received Repo Data:", options)
	if repository, err := createRepoForUser(access.URL, access.Username, access.Password, options.Owner, options.Name, options.Description, options.Private); err == nil {
		remoteUrl := getRemoteUrlFromRepo(repository)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(remoteUrl))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Repo creation failed: %v", err)))
	}
}

func listReposForUser(giteaBaseURL, adminUsername, adminPassword, owner string) ([]api.Repository, *errorapi.APIError) {
	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/users/%s/repos", giteaBaseURL, owner)

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Status returned was not OK: %d", resp.StatusCode))
	}

	// Read the response body from Gitea into a byte slice
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error reading Gitea response %v", err))
	}

	var repoList []api.Repository
	err = json.Unmarshal(bodyBytes, &repoList)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error())
	}

	return repoList, nil
}

func getRepoForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName string) (*api.Repository, *errorapi.APIError) {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s", giteaBaseURL, owner, repoName)

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("get user repo returned unexpected status: %d", resp.StatusCode))
	}

	// Read the response body from Gitea into a byte slice
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, errorapi.WrapError(errorapi.ErrResponseReadError, err.Error())
	}

	var repository api.Repository
	err = json.Unmarshal(bodyBytes, &repository)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	return &repository, nil
}

func downloadRepoForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName, treeishId, path string) ([]byte, *errorapi.APIError) {
	// Build the Gitea API URL for downloading the repo archive
	url := fmt.Sprintf("%s/repos/%s/%s/archive/%s.zip", giteaBaseURL, owner, repoName, treeishId)

	// Build request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("downloading user repo returned unexpected status: %d", resp.StatusCode))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorapi.ErrResponseReadError
	}

	// Gitea does not currently support the `path` option
	// https://github.com/go-gitea/gitea/issues/4478
	archiveBytes, apierr := downloadPathFromZip(bodyBytes, fmt.Sprintf("%v/%v", repoName, path))
	if apierr != nil {
		log.Printf("Error extracting path from zipfile %v", err)
		return nil, apierr
	}
	return archiveBytes, apierr
}

func modifyRepoForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName string, newName *string, newDescription *string, newPrivate *bool) (*api.Repository, *errorapi.APIError) {
	data := api.EditRepoOption{
		Name:        newName,
		Description: newDescription,
		Private:     newPrivate,
	}

	jsonData, _ := json.Marshal(data)

	url := fmt.Sprintf("%s/repos/%s/%s", giteaBaseURL, owner, repoName)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("modifying user repo returned unexpected status: %d", resp.StatusCode))
	}

	var repository api.Repository
	json.NewDecoder(resp.Body).Decode(&repository)

	return &repository, nil
}

func handlePatchRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if repoName == "" || owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name and owner must be provided"))
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestReadError)
		return
	}

	var options PatchRepoOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.ErrRequestParseError)
		return
	}

	fmt.Println("Received Repo Data:", options)
	if repository, err := modifyRepoForUser(access.URL, access.Username, access.Password, owner, repoName, &options.Name, &options.Description, &options.Private); err == nil {
		remoteUrl := getRemoteUrlFromRepo(repository)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(remoteUrl))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "Repo modify failed"))
	}
}

func handleGetRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Owner must be provided"))
		return
	}
	if repoName == "" {
		if repos, err := listReposForUser(access.URL, access.Username, access.Password, owner); err == nil {
			jsonData, _ := json.Marshal(repos)
			w.WriteHeader(http.StatusOK)
			w.Write(jsonData)
		} else {
			errorapi.HandleError(w, errorapi.WrapError(err, "repo list generation failed"))
		}
	} else {
		if repo, err := getRepoForUser(access.URL, access.Username, access.Password, owner, repoName); err == nil {
			jsonData, _ := json.Marshal(*repo)
			w.WriteHeader(http.StatusOK)
			w.Write(jsonData)
		} else {
			errorapi.HandleError(w, errorapi.WrapError(err, "Error getting repo for user"))
		}
	}
}

func getRepoFile(giteaBaseURL, adminUsername, adminPassword, owner, repoName, path, ref string) ([]api.ContentsResponse, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", giteaBaseURL, owner, repoName, path, ref)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, err
	}

	var contentsResponse []api.ContentsResponse
	err = json.Unmarshal(bodyBytes, &contentsResponse)
	if err != nil {
		var single api.ContentsResponse
		err = json.Unmarshal(bodyBytes, &single)
		if err == nil {
			contentsResponse = []api.ContentsResponse{single}
		} else {
			log.Printf("Error reading Gitea response %v", err)
			return nil, err
		}
	}

	return contentsResponse, nil
}

func modifyRepoFilesForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName, branch, message string, files []*api.ChangeFileOperation) (string, *errorapi.APIError) {
	// Build the Gitea API URL for downloading the repo archive
	url := fmt.Sprintf("%s/repos/%s/%s/contents", giteaBaseURL, owner, repoName)

	var actualFiles []*api.ChangeFileOperation

	for _, file := range files {
		if file.Operation == "create" {
			actualFiles = append(actualFiles, file)
		} else {
			// Multiple files may be returned in the case of deleting a directory path
			repoFiles, err := getRepoFile(giteaBaseURL, adminUsername, adminPassword, owner, repoName, file.Path, "")
			if err != nil {
				return "", errorapi.WrapError(errorapi.ErrInternalServerError, fmt.Sprintf("Error getting SHA of '%v' from Gitea %v", file.Path, err))
			}
			if len(repoFiles) > 1 {
				if file.Operation != "delete" {
					log.Printf("Multiple files returned for path %s, cannot update a directory directly", file.Path)
					return "", errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Cannot update directory %s directly", file.Path))
				}
				for _, repoFile := range repoFiles {
					actualFiles = append(actualFiles, &api.ChangeFileOperation{
						Operation: file.Operation,
						Path:      repoFile.Path,
						SHA:       repoFile.SHA,
					})
				}
			} else {
				file.SHA = repoFiles[0].SHA
				actualFiles = append(actualFiles, file)
			}
		}
	}

	data := api.ChangeFilesOptions{
		FileOptions: api.FileOptions{
			BranchName: branch,
			Author:     api.Identity{Name: adminUsername},
			Committer:  api.Identity{Name: adminUsername},
			Message:    message,
		},
		Files: actualFiles,
	}

	jsonData, _ := json.MarshalIndent(data, "", "	")
	log.Printf("%s", jsonData)

	// Build request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error modifying repo from Gitea %v %v", resp.StatusCode, url))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrRequestReadError, err.Error())
	}
	var filesResponse api.FilesResponse
	err = json.Unmarshal(bodyBytes, &filesResponse)
	if err != nil {
		return "", errorapi.WrapError(errorapi.ErrRequestParseError, err.Error())
	}

	return filesResponse.Commit.SHA, nil
}

func handleModifyRepoFiles(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
		return
	}

	var options ModifyRepoOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	if commitHash, err := modifyRepoFilesForUser(access.URL, access.Username, access.Password, options.Owner, options.Name, options.Branch, options.Message, options.Files); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(commitHash))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "Modify repo failed"))
	}
}

func handleDownloadRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	treeishId := r.URL.Query().Get("treeish_id")
	path := r.URL.Query().Get("path")

	if repoName == "" || owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name and owner must be provided"))
		return
	}
	if resp, err := downloadRepoForUser(access.URL, access.Username, access.Password, owner, repoName, treeishId, path); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	} else {
		errorapi.HandleError(w, err)
	}
}

func listCommitsForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName, branch string) ([]api.Commit, *errorapi.APIError) {
	// Build the Gitea API URL for downloading the repo archive
	url := fmt.Sprintf("%s/repos/%s/%s/commits?sha=%s&files=false", giteaBaseURL, owner, repoName, branch)

	// Build request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request %v", http.StatusInternalServerError)
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying Gitea %v", http.StatusInternalServerError)
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error listing commits from Gitea %v", resp.StatusCode)
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("listing commits failed with status code: %d", resp.StatusCode))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, errorapi.WrapError(errorapi.ErrRequestReadError, err.Error())
	}

	var commits []api.Commit
	err = json.Unmarshal(bodyBytes, &commits)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error())
	}

	return commits, nil
}

func handleListCommits(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	branch := r.URL.Query().Get("branch")

	if repoName == "" || owner == "" || branch == "" {
		http.Error(w, "Repo name, owner, and branch must be provided", http.StatusBadRequest)
		return
	}
	if commits, err := listCommitsForUser(access.URL, access.Username, access.Password, owner, repoName, branch); err == nil {
		jsonData, _ := json.Marshal(commits)
		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "failed to list commits for repo"))
	}
}

func deleteRepoForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName string) *errorapi.APIError {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s", giteaBaseURL, owner, repoName)

	// Create a new request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		log.Printf("Error deleting repo from Gitea %v", resp.StatusCode)
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("repo deletion failed with status code: %d", resp.StatusCode))
	}

	return nil
}

func handleDeleteRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")

	if repoName == "" || owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name and owner must be provided"))
		return
	}
	if err := deleteRepoForUser(access.URL, access.Username, access.Password, owner, repoName); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Successfully deleted repository"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "repo deletion failed"))
	}
}

func handleRepo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateRepo(w, r)
	case http.MethodGet:
		handleGetRepo(w, r)
	case http.MethodPatch:
		handlePatchRepo(w, r)
	case http.MethodDelete:
		handleDeleteRepo(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func addCollaboratorToRepo(giteaBaseURL, adminUsername, adminPassword, owner, repoName, collaboratorName, permission string) *errorapi.APIError {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s/collaborators/%s", giteaBaseURL, owner, repoName, collaboratorName)

	// Empty permission string is treated the same as omitting it by the Gitea API here.
	option := api.AddCollaboratorOption{
		Permission: &permission,
	}
	jsonData, _ := json.Marshal(option)

	// Create a new request
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying Gitea %v", http.StatusInternalServerError)
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusNoContent {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error adding contributor from Gitea %d", resp.StatusCode))
	}

	return nil
}

func handleAddCollaborator(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
		return
	}

	var options AddCollaboratorOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	// We won't enforce Permission since Gitea doesn't enforce it.
	if options.Name == "" || options.Owner == "" || options.CollaboratorName == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name, owner, and collaborator name must be provided"))
		return
	}
	if err := addCollaboratorToRepo(access.URL, access.Username, access.Password, options.Owner, options.Name, options.CollaboratorName, options.Permission); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Contributor added successfully"))
	} else {
		errorapi.HandleError(w, err)
	}
}

func removeCollaboratorFromRepo(giteaBaseURL, adminUsername, adminPassword, owner, repoName, collaboratorName string) *errorapi.APIError {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s/collaborators/%s", giteaBaseURL, owner, repoName, collaboratorName)

	// Create a new request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusNoContent {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Removing collaborator returned error code: %d", resp.StatusCode))
	}

	return nil
}

func handleRemoveCollaborator(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
		return
	}

	var options RemoveCollaboratorOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	if options.Name == "" || options.Owner == "" || options.CollaboratorName == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name, owner, and collaborator name must be provided"))
		return
	}
	if err := removeCollaboratorFromRepo(access.URL, access.Username, access.Password, options.Owner, options.Name, options.CollaboratorName); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Contributor removed successfully"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, ""))
	}
}

func handleRepoCollaborator(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		handleAddCollaborator(w, r)
	case http.MethodDelete:
		handleRemoveCollaborator(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func addHookToRepo(giteaBaseURL, adminUsername, adminPassword, owner, repoName, hookId, content string) *errorapi.APIError {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s/hooks/git/%s", giteaBaseURL, owner, repoName, hookId)

	option := api.EditGitHookOption{
		Content: content,
	}
	jsonData, _ := json.Marshal(option)
	// Empty permission string is treated the same as omitting it by the Gitea API here.
	// Create a new request
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	log.Println(url)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Error adding Git hook from Gitea %v", resp.StatusCode))
	}

	return nil
}

func handleAddHook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestReadError, err.Error()))
		return
	}

	var options AddHookOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	defer r.Body.Close()
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestReadError, err.Error()))
		return
	}

	if options.Name == "" || options.Owner == "" || options.HookId == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Repo name, owner, and hook id must be provided"))
		return
	}
	if err := addHookToRepo(access.URL, access.Username, access.Password, options.Owner, options.Name, options.HookId, options.Content); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hook added successfully"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
	}
}

func handleRepoHook(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		handleAddHook(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func forkRepositoryForUser(giteaBaseURL, adminUsername, adminPassword, owner, repo, user string) (*api.Repository, *errorapi.APIError) {
	/*
		reenable this once gitea bug #26234 is fixed

		token, err := createTokenForUser(giteaBaseURL, adminUsername, adminPassword, user, "fork_tok", []string{"write:repository"})
		if err != nil {
			return false, err
		}
	*/

	tmpRepoName := fmt.Sprintf("%s-%d", repo, forkCounter.Next())

	option := api.CreateForkOption{
		Name: &tmpRepoName,
	}
	jsonData, _ := json.Marshal(option)

	req, err := http.NewRequest("POST", giteaBaseURL+"/repos/"+owner+"/"+repo+"/forks", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusAccepted {
		if err := transferRepoOwnership(giteaBaseURL, adminUsername, adminPassword, adminUsername, tmpRepoName, user); err != nil {
			log.Printf("transfer ownership of %s to %s failed: %v", tmpRepoName, user, err)
			return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
		}
		if err := renameRepo(giteaBaseURL, adminUsername, adminPassword, user, tmpRepoName, repo); err != nil {
			log.Printf("rename of repo from %s to %s failed %v", tmpRepoName, repo, err)
			return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
		}
		if err := createWebhook(access.URL, access.Username, access.Password, user, repo, fullname); err != nil {
			log.Printf("create webhook for repo %s failed %v", repo, err)
			return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
		}

		var repository api.Repository
		json.NewDecoder(resp.Body).Decode(&repository)

		return &repository, nil
	} else {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("fork failed with code %v", resp.StatusCode))
	}
}

func handleCreateFork(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
		return
	}

	var options ForkOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	fmt.Println("Forking repo:", options.Repo, "for user:", options.NewOwner)
	if _, err := forkRepositoryForUser(access.URL, access.Username, access.Password, options.Owner, options.Repo, options.NewOwner); err == nil {
		// Note: we can't use getRemoteUrlFromRepo since the returned repo remote is incorrect due to the way we handle forking w/ rename.
		if remoteUrl, err := getRemoteUrl(access.URL, access.Username, access.Password, options.NewOwner, options.Repo); err == nil {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(remoteUrl))
		} else {
			errorapi.HandleError(w, errorapi.WrapError(err, "Repo Creation Failed"))
			deleteRepoForUser(access.URL, access.Username, access.Password, options.NewOwner, options.Repo)
		}
	} else {
		errormsg := "Repo creation failed: "
		if err != nil {
			errormsg += err.Error()
		}
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, errormsg))
	}
}

func handleGetForks(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if name == "" || owner == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Fork name and owner must be provided"))
		return
	}

	repoURL := fmt.Sprintf("%s/repos/%s/%s", access.URL, owner, name)
	if forks, err := findForks(repoURL, access.Username, access.Password); err == nil {
		if bytes, err := json.Marshal(forks); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, err.Error()))
		}
	} else {
		errorapi.HandleError(w, err)
	}
}

func handleFork(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateFork(w, r)
	case http.MethodGet:
		handleGetForks(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func getOrg(giteaBaseURL, adminUsername, adminPassword, orgName string) (*api.Organization, *errorapi.APIError) {

	req, err := http.NewRequest("GET", giteaBaseURL+"/orgs/"+orgName, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to get organization details; HTTP status code: %d", resp.StatusCode))
	}

	var orgDetails api.Organization

	json.NewDecoder(resp.Body).Decode(&orgDetails)

	return &orgDetails, nil
}

func handleGetOrg(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("org_name")
	if name == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Org Name must be provided"))
		return
	}

	if org, err := getOrg(access.URL, access.Username, access.Password, name); err == nil {
		if bytes, err := json.Marshal(org); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		}
	} else {
		errorapi.HandleError(w, err)
	}
}

func createOrg(giteaBaseURL, adminUsername, adminPassword, orgName string) *errorapi.APIError {
	options := api.CreateOrgOption{
		UserName:   orgName,
		Visibility: "public",
	}

	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("POST", giteaBaseURL+"/orgs", bytes.NewBuffer(jsonData))
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to create organization; HTTP status code: %d", resp.StatusCode))
	}

	return nil
}

func handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestReadError, err.Error()))
		return
	}

	var options OrgOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrRequestParseError, err.Error()))
		return
	}

	if options.OrgName == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "orgname must be provided"))
		return
	}

	log.Println("Received Org Data:", options)
	if err := createOrg(access.URL, access.Username, access.Password, options.OrgName); err == nil {
		if err := createTeam(access.URL, access.Username, access.Password, options.OrgName, DEFAULT_TEAM_NAME, "Primary Team for "+options.OrgName); err == nil {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Org created successfully"))
		} else {
			errorapi.HandleError(w, errorapi.WrapError(err, fmt.Sprintf("Org-Team creation failed %v", err)))
		}
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, fmt.Sprintf("Org creation failed %v", err)))
	}
}

func deleteOrg(giteaBaseURL, adminUsername, adminPassword, orgName string, purge bool) *errorapi.APIError {
	if purge {
		repos, err := listReposForUser(giteaBaseURL, adminUsername, adminPassword, orgName)
		if err != nil {
			return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
		}
		for _, repository := range repos {
			deleteRepoForUser(giteaBaseURL, adminUsername, adminPassword, orgName, repository.Name)
		}
	}

	req, err := http.NewRequest("DELETE", giteaBaseURL+"/orgs/"+orgName, nil)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to delete organization; HTTP status code: %d", resp.StatusCode))
	}

	return nil
}

func handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("org_name")
	purge := r.URL.Query().Get("purge") == "true"

	if name == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Org name must be provided as org_name"))
		return
	}

	if err := deleteOrg(access.URL, access.Username, access.Password, name, purge); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Successfully deleted org"))
	} else {
		log.Printf("failed to delete org %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		errorapi.HandleError(w, errorapi.WrapError(err, "failed to delete org"))
	}
}

func handleOrg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateOrg(w, r)
	case http.MethodDelete:
		handleDeleteOrg(w, r)
	case http.MethodGet:
		handleGetOrg(w, r)
	default:
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrMethodNotAllowed, r.Method))
	}
}

func getOrgMembers(giteaBaseURL, adminUsername, adminPassword, orgName string) ([]api.User, *errorapi.APIError) {
	teamID, err := getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, DEFAULT_TEAM_NAME)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, err.Error())
	}

	reqURL := fmt.Sprintf("%s/teams/%d/members", giteaBaseURL, teamID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("error creating request: %v", err))
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errorapi.WrapError(errorapi.ErrGiteaConnectError, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var responseError map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseError)
		return nil, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("failed to get team members; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"]))
	}

	var members []api.User
	json.NewDecoder(resp.Body).Decode(&members)

	return members, nil
}

func handleGetMembers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgName := vars["orgName"]

	if orgName == "" {
		errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, "Orgname not provided"))
		return
	}

	if members, err := getOrgMembers(access.URL, access.Username, access.Password, orgName); err == nil {
		if bytes, err := json.Marshal(members); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			errorapi.HandleError(w, errorapi.WrapError(errorapi.ErrBadRequest, fmt.Sprintf("Unable to parse getMembers result %v", err)))
		}
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "GetMembers Failed"))
	}
}

func handleAddMember(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgName := vars["orgName"]
	userName := vars["userName"]

	if err := addUserToTeam(access.URL, access.Username, access.Password, orgName, DEFAULT_TEAM_NAME, userName); err == nil {
		// Respond to the client
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User added to organization"))
	} else {
		errorapi.HandleError(w, errorapi.WrapError(err, "Add User Failed"))
	}
}

// readinessHandler checks the readiness of the service to handle requests.
// In this implementation, it always indicates that the service is ready by
// returning a 200 OK status. In more complex scenarios, this function could
// check internal conditions before determining readiness.
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is ready to handle requests.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

// livenessHandler checks the health of the service to ensure it's running and
// operational. In this implementation, it always indicates that the service is
// alive by returning a 200 OK status. In more advanced scenarios, this function
// could check internal health metrics before determining liveness.
func livenessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is alive and healthy.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Alive"))
}

// main initializes an HTTP server with endpoints for processing push events,
// checking service readiness, and determining service liveness. The server
// listens on port 9000. Logging is utilized to indicate the server's start
// and to capture any fatal errors.
func main() {
	router := mux.NewRouter()
	// All protected routes must use AuthMiddleware
	protected := router.PathPrefix("/").Subrouter()
	protected.Use(AuthMiddleware)

	protected.HandleFunc("/users", handleUser)
	protected.HandleFunc("/users/ssh", handleUserSsh)
	protected.HandleFunc("/repos", handleRepo)
	protected.HandleFunc("/repos/collaborators", handleRepoCollaborator)
	protected.HandleFunc("/repos/hooks", handleRepoHook)
	protected.HandleFunc("/repos/modify", handleModifyRepoFiles).Methods("POST")
	protected.HandleFunc("/repos/download", handleDownloadRepo).Methods("GET")
	protected.HandleFunc("/repos/commits", handleListCommits).Methods("GET")
	protected.HandleFunc("/forks", handleFork)
	protected.HandleFunc("/orgs", handleOrg)
	protected.HandleFunc("/orgs/{orgName}/members", handleGetMembers).Methods("GET")
	protected.HandleFunc("/orgs/{orgName}/members/{userName}", handleAddMember).Methods("PUT")
	// The router routes will not use the auth middleware
	router.HandleFunc("/readiness", readinessHandler)
	router.HandleFunc("/liveness", livenessHandler)

	srv := &http.Server{
		Handler:      router,
		Addr:         "0.0.0.0:9000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Server started on :9000")
	go func() {
		err := srv.ListenAndServe()
		log.Fatalf(err.Error())
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown

	//Shutdown gracefully
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	log.Print("Received shutdown signal closing server ...")
	srv.Shutdown(ctx)
}
