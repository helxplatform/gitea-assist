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

	"code.gitea.io/gitea/modules/structs"
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
	Origin         *git.Repository
	OriginCloneURL string
	OriginName     string
	OriginBranch   string
	OriginHash     *plumbing.Hash
	Fork           *git.Repository
	ForkCloneURL   string
	ForkName       string
	ForkBranch     string
	ForkHash       *plumbing.Hash
}

var creds *Creds

func init() {
	creds, _ = getCreds()
}

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
		log.Printf("could not retrieve forks %u", err)
		return nil, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&forks)

	if err != nil {
		log.Printf("unable to parse response from /forks %u", err)
		body, err := io.ReadAll(resp.Body)
		log.Printf("body:\n %s", body)
		return nil, err
	}

	return forks, nil
}

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

func getDiffBetweenUpstreamAndFork(mc *MergeContext) (*object.Patch, error) {
	// Add the original repo as an upstream remote
	_, err := mc.Fork.CreateRemote(&config.RemoteConfig{
		Name: "upstream",
		URLs: []string{mc.OriginCloneURL},
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
	upstreamRef, err := mc.Fork.Reference(plumbing.ReferenceName("refs/remotes/upstream/"+mc.OriginBranch), true)
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

	mc.OriginHash = &upstreamHash
	mc.ForkHash = &forkHash

	log.Printf("Collected diffs between %s and %s", mc.OriginName, mc.ForkName)

	return diff, nil
}

// filterPatches filters out the FilePatches that represent merge conflicts.
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

	//err := ioutil.WriteFile(repoPath+"/"+to.Path(), content, 0644)
	contents, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read file %s: %s", df.Path(), err)
		return nil, nil, err
	}
	return contents, &mode, nil
}

func writeContents(wt *git.Worktree, df diff.File, contents []byte, mode *os.FileMode) error {
	file, err := wt.Filesystem.OpenFile(df.Path(), os.O_CREATE|os.O_RDWR, *mode)
	if err != nil {
		log.Fatalf("Failed to open file %s: %s", df.Path(), err)
		return err
	}
	defer file.Close()

	if _, err := file.Write(contents); err != nil {
		log.Fatalf("Failed to read file %s: %s", df.Path(), err)
		return err
	}
	return nil
}

// applyChanges applies the provided FilePatches.
func applyChanges(mc *MergeContext, filePatches []diff.FilePatch) error {
	// Get the worktree for the Fork repository where changes will be applied.
	wtFork, err := mc.Fork.Worktree()
	if err != nil {
		return err
	}
	wtOrigin, err := mc.Origin.Worktree()
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
			contents, mode, err := readFileContents(wtOrigin, to)
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
			Name:  "Mr McMergeybot",
			Email: "merge-botCMXX@renci.org",
			When:  time.Now(),
		},
		Parents: []plumbing.Hash{*mc.OriginHash, *mc.ForkHash},
	}
	if _, err = wtFork.Commit("Merge changes from "+mc.OriginName, &options); err != nil {
		log.Printf("Failed to merge %s and %s: %v", mc.OriginName, mc.ForkName, err)
		return err
	} else {
		log.Printf("Merged changes from %s into %s", mc.OriginName, mc.ForkName)
	}

	return nil
}

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

// processAndApply filters the FilePatches and then applies the changes.
func processMerge(mc *MergeContext, filePatches []diff.FilePatch) error {
	filteredPatches := filterPatches(mc, filePatches)
	return applyChanges(mc, filteredPatches)
}

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
				pushRepo, err = cloneRepoIntoDir("/tmp/repos/", "origin/"+pushEvent.Repo.Name, pushEvent.Repo.CloneURL)
				if err != nil {
					log.Printf("Failed to clone the origin repository: %v", err)
					return
				}
			}
			forkRepo, err := cloneRepoIntoDir("/tmp/repos/", fork.Owner.UserName+"/"+fork.Name, fork.CloneURL)
			if err != nil {
				log.Printf("Failed to clone the fork repository: %v", err)
				continue
			}

			mc := &MergeContext{
				Origin:         pushRepo,
				OriginCloneURL: pushEvent.Repo.CloneURL,
				OriginName:     "origin/" + pushEvent.Repo.Name,
				OriginBranch:   pushEvent.Branch(),
				Fork:           forkRepo,
				ForkCloneURL:   fork.CloneURL,
				ForkName:       fork.Owner.UserName + "/" + fork.Name,
				ForkBranch:     pushEvent.Branch(),
			}
			if diff, err := getDiffBetweenUpstreamAndFork(mc); err == nil {
				if err = processMerge(mc, diff.FilePatches()); err == nil {
					pushFork(mc, creds)
				} else {
					log.Printf("failed to process merge of %s into %s", mc.OriginName, mc.ForkName)
				}
			} else {
				log.Printf("failed to compute upstream and fork diff")
			}
		}
	}
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	pushEvent, err := structs.ParsePushHook(body)

	if err != nil {
		log.Printf("Error parsing body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	// Process the push event, including finding forks and pulling changes
	processPushEvent(pushEvent, creds)

	log.Printf("OK")
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is ready to handle requests.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

func livenessHandler(w http.ResponseWriter, r *http.Request) {
	// Check conditions to determine if service is alive and healthy.
	// For simplicity, we're always returning 200 OK in this example.
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Alive"))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/onPush", webhookHandler)
	mux.HandleFunc("/readiness", readinessHandler)
	mux.HandleFunc("/liveness", livenessHandler)
	log.Println("Server started on :8000")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
