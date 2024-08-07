package v1

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	api "code.gitea.io/gitea/modules/structs"
)

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

func (m *Mux) handleCreateRepo(w http.ResponseWriter, r *http.Request) {
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
	if repository, err := createRepoForUser(access.URL, access.Username, access.Password, options.Owner, options.Name, options.Description, options.Private); err == nil {
		if err := createWebhook(access.URL, access.Username, access.Password, options.Owner, options.Name, fullname); err == nil {
			remoteUrl := getRemoteUrlFromRepo(repository)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(remoteUrl))
		} else {
			http.Error(w, "Webhook creation failed", http.StatusBadRequest)
			log.Printf("Webhook creation failed %v", err)
		}
	} else {
		http.Error(w, "Repo creation failed", http.StatusBadRequest)
		log.Printf("Repo creation failed %v", err)
	}
}

func (m *Mux) handleGetRepo(w http.ResponseWriter, r *http.Request) {
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

func (m *Mux) handlePatchRepo(w http.ResponseWriter, r *http.Request) {
	repoName := r.URL.Query().Get("name")
	owner := r.URL.Query().Get("owner")
	if repoName == "" || owner == "" {
		http.Error(w, "Repo name and owner must be provided", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options PatchRepoOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	fmt.Println("Received Repo Data:", options)
	if repository, err := modifyRepoForUser(access.URL, access.Username, access.Password, owner, repoName, &options.Name, &options.Description, &options.Private); err == nil {
		remoteUrl := getRemoteUrlFromRepo(repository)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(remoteUrl))
	} else {
		http.Error(w, "Repo modify failed", http.StatusBadRequest)
		log.Printf("Repo modify failed %v", err)
	}
}
