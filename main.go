package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

type UserOptions struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type RepoOptions struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Owner       string `json:"owner"`
	Private     bool   `json:"private"`
}

type ForkOptions struct {
	Owner    string `json:"owner"`
	NewOwner string `json:"newOwner"`
	Repo     string `json:"repo"`
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

func init() {
	access, _ = getAccess()
	fullname, _ = getFullname()
	forkCounter = &AtomicCounter{}
}

// Next returns the next number in sequence
func (ac *AtomicCounter) Next() int64 {
	return atomic.AddInt64(&ac.val, 1)
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
func findForks(repoURL, username, password string) ([]api.Repository, error) {
	var forks []api.Repository

	client := &http.Client{}
	req, err := http.NewRequest("GET", repoURL+"/forks", nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(string(username), string(password))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("could not retrieve forks %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&forks)

	if err != nil {
		log.Printf("unable to parse response from %s/forks %v", repoURL, err)
		body, err := io.ReadAll(resp.Body)
		log.Printf("body:\n %s", body)
		return nil, err
	}

	return forks, nil
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

func createTeam(giteaBaseURL, adminUsername, adminPassword, orgName, teamName, description string) error {
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
		return fmt.Errorf("failed to create team; HTTP status code: %d", resp.StatusCode)
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

func addUserToTeam(giteaBaseURL, adminUsername, adminPassword, orgName, teamName, userName string) error {
	teamID, err := getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, teamName)
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/teams/%d/members/%s", giteaBaseURL, teamID, userName)
	req, err := http.NewRequest("PUT", reqURL, bytes.NewBuffer(nil))
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
		var responseError map[string]interface{}

		json.NewDecoder(resp.Body).Decode(&responseError)
		return fmt.Errorf("failed to add user to team; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"])
	}

	return nil
}

func createWebhook(giteaBaseURL, adminUsername, adminPassword, owner, repo, fullname string) error {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/hooks", giteaBaseURL, owner, repo)

	config := api.CreateHookOptionConfig{
		"content_type": "json",
		"url":          "http://" + fullname + ":8000/onPush",
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

// processPushEvent handles a push event from a Git repository. Given the event's
// payload and authentication credentials, the function performs several tasks:
//   - Identifies the repository associated with the push.
//   - Clears any previous repository data from a temporary directory.
//   - Locates all forks of the repository and processes each one by:
//     a. Cloning the upstream and fork repositories.
//     b. Creating a merge context for the two repositories.
//     c. Computing and applying diffs between the repositories.
//     d. Pushing merged changes to the fork.
//
// Error situations, such as cloning failures or merge issues, are logged.
func processPushEvent(pushEvent *api.PushPayload, access *GiteaAccess) {
	var forkIsEmpty bool = false

	// 1. Get the repository related to the push event
	languagesURL := pushEvent.Repo.LanguagesURL
	repoURL := strings.ReplaceAll(languagesURL, "/languages", "")
	log.Printf("processing push event on repo with URL %s", repoURL)

	err := os.RemoveAll("/tmp/repos")
	if err != nil {
		log.Printf("failed to clean work directory")
		return
	}

	if forks, err := findForks(repoURL, access.Username, access.Password); err == nil {
		var pushRepo *git.Repository

		for _, fork := range forks {
			log.Printf("found fork %s", fork.Owner.UserName+"/"+fork.Name)
			if pushRepo == nil {
				pushRepo, err = cloneRepoIntoDir("/tmp/repos/", "upstream/"+pushEvent.Repo.Name, pushEvent.Repo.CloneURL, false)
				if err != nil {
					log.Printf("Failed to clone the upstream repository: %v", err)
					return
				}
			}
			forkRepo, err := cloneRepoIntoDir("/tmp/repos/", fork.Owner.UserName+"/"+fork.Name, fork.CloneURL, true)
			if err != nil {
				log.Printf("Failed to clone the fork repository: %v", err)
				continue
			}

			// This happens when the fork is empty, so have to initilize it locally
			if forkRepo == nil {
				if forkRepo, err = InitRepoWithRemote("/tmp/repos/"+fork.Owner.UserName+"/"+fork.Name, fork.CloneURL, pushEvent.Branch()); err != nil {
					log.Printf("Failed to initialize blank fork repository: %v", err)
					continue
				}
				forkIsEmpty = true
			}

			mc := &MergeContext{
				Upstream:         pushRepo,
				UpstreamCloneURL: pushEvent.Repo.CloneURL,
				UpstreamName:     "upstream/" + pushEvent.Repo.Name,
				UpstreamBranch:   pushEvent.Branch(),
				Fork:             forkRepo,
				ForkCloneURL:     fork.CloneURL,
				ForkName:         fork.Owner.UserName + "/" + fork.Name,
				ForkBranch:       pushEvent.Branch(),
				ForkIsEmpty:      forkIsEmpty,
			}
			if patches, err := getDiffBetweenUpstreamAndFork(mc); err == nil {
				var filePatches []diff.FilePatch

				for _, patch := range patches {
					filePatches = append(filePatches, patch.FilePatches()...)
				}
				if err = processMerge(mc, filePatches); err == nil {
					pushFork(mc, access)
				} else {
					log.Printf("failed to process merge of %s into %s: %v", mc.UpstreamName, mc.ForkName, err)
				}
			} else {
				log.Printf("failed to compute upstream and fork diff: %v", err)
			}
		}
	}
}

// webhookHandler handles incoming webhook requests, specifically for push events.
// The function reads the request body, parses the push event, and processes it.
// Any errors in reading or parsing are logged and result in a bad request response.
// After processing the push event, a log confirmation is made.
func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	pushEvent, err := api.ParsePushHook(body)

	if err != nil {
		log.Printf("Error parsing body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	// Process the push event, including finding forks and pulling changes
	processPushEvent(pushEvent, access)

	log.Printf("OK")
}

func createUser(giteaBaseURL, adminUsername, adminPassword, username, password, email string) (bool, error) {
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
	user := api.CreateUserOption{
		Username: username,
		Email:    email,
		Password: password,
	}

	jsonData, _ := json.Marshal(user)

	req, _ := http.NewRequest("POST", giteaBaseURL+"/admin/users", bytes.NewBuffer(jsonData))
	//req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Println("Failed to create user:", string(body))
		return false, nil
	}
	return true, nil
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options UserOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	if options.Username == "" || options.Password == "" || options.Email == "" {
		http.Error(w, "Username password, and email must be provided", http.StatusBadRequest)
		return
	}

	log.Println("Received User Data:", options)
	if success, err := createUser(access.URL, access.Username, access.Password, options.Username, options.Password, options.Email); success {
		// Respond to the client
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User created successfully"))
	} else {
		http.Error(w, "User creation failed", http.StatusBadRequest)
		if err != nil {
			log.Printf("User creation failed %v", err)
		} else {
			log.Printf("User creation failed")
		}
	}
}

func getUser(giteaBaseURL, adminUsername, adminPassword, username string) ([]byte, error) {
	url := fmt.Sprintf("%s/users/%s", giteaBaseURL, username)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set Basic Authentication header
	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error querying gitea: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitea returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading gitea response: %v", err)
	}

	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, err
	}

	return bodyBytes, nil
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	// Retrieve the username from the query parameters
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username not provided", http.StatusBadRequest)
		return
	}

	if resp, err := getUser(access.URL, access.Username, access.Password, username); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateUser(w, r)
	case http.MethodGet:
		handleGetUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func createRepoForUser(giteaBaseURL, adminUsername, adminPassword, username, name, description string, private bool) error {
	data := api.CreateRepoOption{
		Name:        name,
		Description: description,
		Private:     private,
	}

	jsonData, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", giteaBaseURL+"/admin/users/"+username+"/repos", bytes.NewBuffer(jsonData))
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
		return fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}
	return nil
}

func handleCreateRepo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options RepoOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	if options.Name == "" || options.Description == "" || options.Owner == "" {
		http.Error(w, "Name, description, and owner must be provided for the repo", http.StatusBadRequest)
		return
	}

	fmt.Println("Received Repo Data:", options)
	if err := createRepoForUser(access.URL, access.Username, access.Password, options.Owner, options.Name, options.Description, options.Private); err == nil {
		if err := createWebhook(access.URL, access.Username, access.Password, options.Owner, options.Name, fullname); err == nil {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Repo created successfully"))
		} else {
			http.Error(w, "Webhook creation failed", http.StatusBadRequest)
			log.Printf("Webhook creation failed %v", err)
		}
	} else {
		http.Error(w, "Repo creation failed", http.StatusBadRequest)
		log.Printf("Repo creation failed %v", err)
	}

	// Respond to the client
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Repo created successfully"))
}

func getRepoForUser(giteaBaseURL, adminUsername, adminPassword, owner, repoName string) ([]byte, error) {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s", giteaBaseURL, owner, repoName)

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request %v", http.StatusInternalServerError)
		return nil, err
	}
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying Gitea %v", http.StatusInternalServerError)
		return nil, fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		log.Printf("Error fetching repo from Gitea %v", resp.StatusCode)
		return nil, fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}

	// Read the response body from Gitea into a byte slice
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, err
	}

	return bodyBytes, nil
}

func handleGetRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if repoName == "" || owner == "" {
		http.Error(w, "Repo name and owner must be provided", http.StatusBadRequest)
		return
	}
	if resp, err := getRepoForUser(access.URL, access.Username, access.Password, owner, repoName); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleRepo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateRepo(w, r)
	case http.MethodGet:
		handleGetRepo(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func forkRepositoryForUser(giteaBaseURL, adminUsername, adminPassword, owner, repo, user string) error {
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
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusAccepted {
		if err := transferRepoOwnership(giteaBaseURL, adminUsername, adminPassword, adminUsername, tmpRepoName, user); err != nil {
			log.Printf("transfer ownership of %s to %s failed: %v", tmpRepoName, user, err)
			return err
		}
		if err := renameRepo(giteaBaseURL, adminUsername, adminPassword, user, tmpRepoName, repo); err != nil {
			log.Printf("rename of repo from %s to %s failed %v", tmpRepoName, repo, err)
			return err
		}
		if err := createWebhook(access.URL, access.Username, access.Password, user, repo, fullname); err != nil {
			log.Printf("create webhook for repo %s failed %v", repo, err)
			return err
		}
		return nil
	} else {
		return fmt.Errorf("fork failed with code %v", resp.StatusCode)
	}
}

func handleCreateFork(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options ForkOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	fmt.Println("Forking repo:", options.Repo, "for user:", options.NewOwner)
	if err := forkRepositoryForUser(access.URL, access.Username, access.Password, options.Owner, options.Repo, options.NewOwner); err == nil {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(fmt.Sprintf("Repo %s forked successfully for user %s", options.Repo, options.NewOwner)))
	} else {
		http.Error(w, "Fork failed", http.StatusBadRequest)
		if err != nil {
			log.Printf("Repo creation failed %v", err)
		} else {
			log.Printf("Repo creation failed")
		}
	}
}

func handleGetForks(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if name == "" || owner == "" {
		http.Error(w, "Fork name and owner must be provided", http.StatusBadRequest)
		return
	}

	repoURL := fmt.Sprintf("%s/repos/%s/%s", access.URL, owner, name)
	if forks, err := findForks(repoURL, access.Username, access.Password); err == nil {
		if bytes, err := json.Marshal(forks); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			log.Printf("Unable to parse findForks result %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		log.Printf("findForks failed %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleFork(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateFork(w, r)
	case http.MethodGet:
		handleGetForks(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getOrg(giteaBaseURL, adminUsername, adminPassword, orgName string) (*api.Organization, error) {

	req, err := http.NewRequest("GET", giteaBaseURL+"/orgs/"+orgName, nil)
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
		return nil, fmt.Errorf("failed to get organization details; HTTP status code: %d", resp.StatusCode)
	}

	var orgDetails api.Organization

	json.NewDecoder(resp.Body).Decode(&orgDetails)

	return &orgDetails, nil
}

func handleGetOrg(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("org_name")
	if name == "" {
		http.Error(w, "Orgname be provided", http.StatusBadRequest)
		return
	}

	if org, err := getOrg(access.URL, access.Username, access.Password, name); err == nil {
		if bytes, err := json.Marshal(org); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			log.Printf("Unable to parse getOrg result %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		log.Printf("getOrg failed %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func createOrg(giteaBaseURL, adminUsername, adminPassword, orgName string) error {
	options := api.CreateOrgOption{
		UserName:   orgName,
		Visibility: "public",
	}

	jsonData, _ := json.Marshal(options)

	req, err := http.NewRequest("POST", giteaBaseURL+"/orgs", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.SetBasicAuth(string(adminUsername), string(adminPassword))
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create organization; HTTP status code: %d", resp.StatusCode)
	}

	return nil
}

func handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options OrgOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	if options.OrgName == "" {
		http.Error(w, "name must be provided", http.StatusBadRequest)
		return
	}

	log.Println("Received Org Data:", options)
	if err := createOrg(access.URL, access.Username, access.Password, options.OrgName); err == nil {
		if err := createTeam(access.URL, access.Username, access.Password, options.OrgName, options.OrgName, "Primary Team for "+options.OrgName); err == nil {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Org created successfully"))
		} else {
			http.Error(w, "Org-Team creation failed", http.StatusBadRequest)
			log.Printf("Org-Team creation failed %v", err)
		}
	} else {
		http.Error(w, "Org creation failed", http.StatusBadRequest)
		log.Printf("Org creation failed %v", err)
	}
}

func handleOrg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateOrg(w, r)
	case http.MethodGet:
		handleGetOrg(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func getOrgMembers(giteaBaseURL, adminUsername, adminPassword, orgName string) ([]api.User, error) {
	teamID, err := getTeamID(giteaBaseURL, adminUsername, adminPassword, orgName, orgName)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/teams/%d/members", giteaBaseURL, teamID)
	req, err := http.NewRequest("GET", reqURL, nil)
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
		var responseError map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseError)
		return nil, fmt.Errorf("failed to get team members; HTTP status code: %d, message: %s", resp.StatusCode, responseError["message"])
	}

	var members []api.User
	json.NewDecoder(resp.Body).Decode(&members)

	return members, nil
}

func handleGetMembers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgName := vars["orgName"]

	if orgName == "" {
		http.Error(w, "Orgname not provided", http.StatusBadRequest)
		return
	}

	if members, err := getOrgMembers(access.URL, access.Username, access.Password, orgName); err == nil {
		if bytes, err := json.Marshal(members); err == nil {
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		} else {
			log.Printf("Unable to parse getMembers result %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		log.Printf("getMembers failed %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleAddMember(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgName := vars["orgName"]
	userName := vars["userName"]

	if err := addUserToTeam(access.URL, access.Username, access.Password, orgName, orgName, userName); err == nil {
		// Respond to the client
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("User added to organization"))
	} else {
		http.Error(w, "Add user failed", http.StatusInternalServerError)
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
// listens on port 8000. Logging is utilized to indicate the server's start
// and to capture any fatal errors.
func main() {
	//mux := http.NewServeMux()
	r := mux.NewRouter()
	r.HandleFunc("/onPush", webhookHandler)
	r.HandleFunc("/users", handleUser)
	r.HandleFunc("/repos", handleRepo)
	r.HandleFunc("/forks", handleFork)
	r.HandleFunc("/orgs", handleOrg)
	r.HandleFunc("/orgs/{orgName}/members", handleGetMembers).Methods("GET")
	r.HandleFunc("/orgs/{orgName}/members/{userName}", handleAddMember).Methods("PUT")
	r.HandleFunc("/readiness", readinessHandler)
	r.HandleFunc("/liveness", livenessHandler)
	http.Handle("/", r)
	log.Println("Server started on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
