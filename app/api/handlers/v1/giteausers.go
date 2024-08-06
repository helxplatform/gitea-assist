package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	api "code.gitea.io/gitea/modules/structs"
)

// In core gitea-access
var access *GiteaAccess

type GiteaAccess struct {
	URL      string
	Username string
	Password string
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

func handleUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleCreateUser(w, r)
	case http.MethodGet:
		handleGetUser(w, r)
	case http.MethodDelete:
		handleDeleteUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options CreateUserOptions
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
	if success, err := createUser(
		access.URL,
		access.Username,
		access.Password,
		options.Username,
		options.Password,
		options.Email); success {
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading gitea response: %v", err)
	}

	if err != nil {
		log.Printf("Error reading Gitea response %v", err)
		return nil, err
	}

	return bodyBytes, nil
}

/*
	Example
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
// createUser
func createUser(giteaBaseURL, adminUsername, adminPassword, username, password, email string) (bool, error) {
	mustChangePassword := false
	user := api.CreateUserOption{
		Username: username,
		Email:    email,
		Password: password,
		// I have no idea why this wants a pointer to a bool...
		MustChangePassword: &mustChangePassword,
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

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		http.Error(w, "Failed reading request body", http.StatusInternalServerError)
		return
	}

	var options DeleteUserOptions
	err = json.Unmarshal(body, &options)
	if err != nil {
		http.Error(w, "Failed parsing request body", http.StatusBadRequest)
		return
	}

	if options.Username == "" {
		http.Error(w, "Username must be provided", http.StatusBadRequest)
		return
	}

	log.Println("Received User Data:", options)
	if success, err := deleteUser(access.URL, access.Username, access.Password, options.Username, options.Purge); success {
		// Respond to the client
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User deleted successfully"))
	} else {
		http.Error(w, "User deletion failed", http.StatusBadRequest)
		if err != nil {
			log.Printf("User deletion failed %v", err)
		} else {
			log.Printf("User deletion failed")
		}
	}
}
