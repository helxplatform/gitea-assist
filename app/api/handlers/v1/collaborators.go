package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

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

func addCollaboratorToRepo(giteaBaseURL, adminUsername, adminPassword, owner, repoName, collaboratorName, permission string) error {

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
		log.Printf("Error creating request %v", http.StatusInternalServerError)
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying Gitea %v", http.StatusInternalServerError)
		return fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusNoContent {
		log.Printf("Error adding contributor from Gitea %v", resp.StatusCode)
		return fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}

	return nil
}

func (m *Mux) handleAddCollaborator(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options AddCollaboratorOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	// We won't enforce Permission since Gitea doesn't enforce it.
	if options.Name == "" || options.Owner == "" || options.CollaboratorName == "" {
		http.Error(w, "Repo name, owner, and collaborator name must be provided", http.StatusBadRequest)
		return
	}
	if err := addCollaboratorToRepo(access.URL, access.Username, access.Password, options.Owner, options.Name, options.CollaboratorName, options.Permission); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Contributor added successfully"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func removeCollaboratorFromRepo(giteaBaseURL, adminUsername, adminPassword, owner, repoName, collaboratorName string) error {

	// Build the Gitea API URL for fetching the repo details
	url := fmt.Sprintf("%s/repos/%s/%s/collaborators/%s", giteaBaseURL, owner, repoName, collaboratorName)

	// Create a new request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		log.Printf("Error creating request %v", http.StatusInternalServerError)
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(string(adminUsername), string(adminPassword))

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error querying Gitea %v", http.StatusInternalServerError)
		return fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusNoContent {
		log.Printf("Error removing contributor from Gitea %v", resp.StatusCode)
		return fmt.Errorf("HTTP Error: %d", resp.StatusCode)
	}

	return nil
}

func (m *Mux) handleRemoveCollaborator(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options RemoveCollaboratorOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	if options.Name == "" || options.Owner == "" || options.CollaboratorName == "" {
		http.Error(w, "Repo name, owner, and collaborator name must be provided", http.StatusBadRequest)
		return
	}
	if err := removeCollaboratorFromRepo(access.URL, access.Username, access.Password, options.Owner, options.Name, options.CollaboratorName); err == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Contributor removed successfully"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
