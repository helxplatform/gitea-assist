package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"code.gitea.io/gitea/modules/structs"
	api "code.gitea.io/gitea/modules/structs"
)

type Creds struct {
	Username string
	Password string
}

var creds *Creds

func init() {
	creds, _ = getCreds()
}

func getCreds() (*Creds, error) {
	var creds *Creds

	username, err := os.ReadFile("/etc/secrets/username")
	if err != nil {
		log.Fatalf("Error reading username: %v", err)
		return creds, err
	}

	password, err := os.ReadFile("/etc/secrets/password")
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
		return nil, err
	}
	defer resp.Body.Close()

	return forks, nil
}

func processPushEvent(pushEvent *api.PushPayload, creds *Creds) {
	// 1. Get the repository related to the push event
	repoURL := pushEvent.Repo.HTMLURL

	// 2. Find all forks of the repository (requires Gitea API call)

	// 3. Iterate through the forks and pull the changes from the original repository
	//    (requires Git operations, potentially using a library like go-git)

	// 4. Log or handle any errors or issues that arise

	if forks, err := findForks(repoURL, creds.Username, creds.Password); err != nil {
		for _, fork := range forks {
			fmt.Printf("found %u", fork.Name)
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

	fmt.Fprintf(w, "OK")
}

func main() {
	if creds != nil {
		http.HandleFunc("/onPush", webhookHandler)
		log.Println("Server started on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}
}
