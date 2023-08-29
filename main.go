package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	api "code.gitea.io/gitea/modules/structs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
)

type Creds struct {
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
}

var creds *Creds

func init() {
	creds, _ = getCreds()
}

// getCreds retrieves Gitea credentials (username and password) from
// specified files in the system. It returns a pointer to a Creds
// structure and an error if there's an issue reading the files.
func getCreds() (*Creds, error) {
	var creds *Creds

	username, err := os.ReadFile("/etc/assist-secret/gitea-username")
	if err != nil {
		log.Fatalf("Error reading username: %v", err)
		return creds, err
	}

	password, err := os.ReadFile("/etc/assist-secret/gitea-password")
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
		return creds, err
	}

	creds = &Creds{
		Username: string(username),
		Password: string(password),
	}

	return creds, nil
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
		log.Printf("unable to parse response from /forks %v", err)
		body, err := io.ReadAll(resp.Body)
		log.Printf("body:\n %s", body)
		return nil, err
	}

	return forks, nil
}

// cloneRepoIntoDir clones a given Git repository into a specified directory.
// If the parent directory doesn't exist, it's created. The function takes the
// parent directory path, desired repository name for the clone, and the clone
// URL as input. It returns a pointer to the cloned git.Repository and an error
// if there's an issue with directory creation or the cloning process.
func cloneRepoIntoDir(parentDir, repoName, cloneURL string) (*git.Repository, error) {
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

	log.Printf("Cloned %s into %s", cloneURL, fullPath)

	return repo, err
}

// getDiffBetweenUpstreamAndFork calculates the diff between an upstream Git
// repository and its fork. It sets the original repo as an "upstream" remote,
// fetches from the upstream, retrieves commits for specified branches, and
// calculates the diff between them. The function operates within a given
// MergeContext (mc) containing details about repositories, branches, etc.
// It returns the calculated diff as an *object.Patch and an error if issues
// arise during the process.
func getDiffBetweenUpstreamAndFork(mc *MergeContext) (*object.Patch, error) {
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

	forkRef, err := mc.Fork.Reference(plumbing.ReferenceName("refs/heads/"+mc.ForkBranch), true)
	if err != nil {
		return nil, err
	}
	forkHash := forkRef.Hash()

	forkCommit, err := mc.Fork.CommitObject(forkHash)
	if err != nil {
		return nil, err
	}

	// Calculate the diff between the two commits
	diff, err := upstreamCommit.Patch(forkCommit)
	if err != nil {
		return nil, err
	}

	mc.UpstreamHash = &upstreamHash
	mc.ForkHash = &forkHash

	log.Printf("Collected diffs between %s and %s", mc.UpstreamName, mc.ForkName)

	return diff, nil
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
	options := git.CommitOptions{
		Author: &object.Signature{
			Name:  "Mr McMergybot",
			Email: "merge-botCMXX@renci.org",
			When:  time.Now(),
		},
		Parents: []plumbing.Hash{*mc.UpstreamHash, *mc.ForkHash},
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
func pushFork(mc *MergeContext, creds *Creds) error {
	// Push using default options
	options := &git.PushOptions{
		RemoteName: "origin",
		Auth: &gitHTTP.BasicAuth{
			Username: creds.Username,
			Password: creds.Password,
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
func processPushEvent(pushEvent *api.PushPayload, creds *Creds) {
	// 1. Get the repository related to the push event
	languagesURL := pushEvent.Repo.LanguagesURL
	repoURL := strings.ReplaceAll(languagesURL, "/languages", "")
	log.Printf("processing push event on repo with URL %s", repoURL)

	err := os.RemoveAll("/tmp/repos")
	if err != nil {
		log.Printf("failed to clean work directory")
		return
	}

	if forks, err := findForks(repoURL, creds.Username, creds.Password); err == nil {
		var pushRepo *git.Repository

		for _, fork := range forks {
			log.Printf("found fork %s", fork.Owner.UserName+"/"+fork.Name)
			if pushRepo == nil {
				pushRepo, err = cloneRepoIntoDir("/tmp/repos/", "upstream/"+pushEvent.Repo.Name, pushEvent.Repo.CloneURL)
				if err != nil {
					log.Printf("Failed to clone the upstream repository: %v", err)
					return
				}
			}
			forkRepo, err := cloneRepoIntoDir("/tmp/repos/", fork.Owner.UserName+"/"+fork.Name, fork.CloneURL)
			if err != nil {
				log.Printf("Failed to clone the fork repository: %v", err)
				continue
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
			}
			if diff, err := getDiffBetweenUpstreamAndFork(mc); err == nil {
				if err = processMerge(mc, diff.FilePatches()); err == nil {
					pushFork(mc, creds)
				} else {
					log.Printf("failed to process merge of %s into %s", mc.UpstreamName, mc.ForkName)
				}
			} else {
				log.Printf("failed to compute upstream and fork diff")
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
	processPushEvent(pushEvent, creds)

	log.Printf("OK")
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
	mux := http.NewServeMux()
	mux.HandleFunc("/onPush", webhookHandler)
	mux.HandleFunc("/readiness", readinessHandler)
	mux.HandleFunc("/liveness", livenessHandler)
	log.Println("Server started on :8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
