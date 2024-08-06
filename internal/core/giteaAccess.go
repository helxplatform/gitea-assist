package core

import (
	"log"
	"os"
)

// var access *GiteaAccess

type GiteaAccess struct {
	URL      string
	Username string
	Password string
}

func NewAccess() (*GiteaAccess, error) {

	username, err := os.ReadFile("/etc/assist-secret/gitea-username")
	if err != nil {
		log.Printf("Error reading username: %v", err)
		return nil, err
	}

	password, err := os.ReadFile("/etc/assist-secret/gitea-password")
	if err != nil {
		log.Printf("Error reading password: %v", err)
		return nil, err
	}

	url, err := os.ReadFile("/etc/assist-config/gitea-api-url")
	if err != nil {
		log.Printf("Error reading password: %v", err)
		return nil, err
	}

	access := &GiteaAccess{
		URL:      string(url),
		Username: string(username),
		Password: string(password),
	}
	return access, nil
}
