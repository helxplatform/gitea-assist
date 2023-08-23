package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

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

func processPushEvent(pushEvent *api.PushPayload, creds *Creds) {
	// 1. Get the repository related to the push event
	languagesURL := pushEvent.Repo.LanguagesURL
	repoURL := strings.ReplaceAll(languagesURL, "/languages", "")
	log.Printf("processing push event on repo with URL %s", repoURL)

	// 2. Find all forks of the repository (requires Gitea API call)

	// 3. Iterate through the forks and pull the changes from the original repository
	//    (requires Git operations, potentially using a library like go-git)

	// 4. Log or handle any errors or issues that arise

	if forks, err := findForks(repoURL, creds.Username, creds.Password); err == nil {
		for _, fork := range forks {
			log.Printf("found fork %s", fork.Name)
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
	http.HandleFunc("/onPush", webhookHandler)
	http.HandleFunc("/readiness", readinessHandler)
	http.HandleFunc("/liveness", livenessHandler)
	log.Println("Server started on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}
