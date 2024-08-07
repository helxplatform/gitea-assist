package main

import (
	v1 "gitea_assist/app/api/handlers/v1"
	"gitea_assist/internal/core"
	"log"
	"net/http"
)

func main() {

}

func run() {
	// Setup logger

	// Initialize access
	access, err := core.NewAccess()
	if err != nil {
		log.Fatalf("Error: reading gitea access-secret file %v", err)
	}
	app := v1.New(access)
	srv := http.Server{
		Addr:    "localhost:8585",
		Handler: app.Routes(),
	}
	srv.ListenAndServe()
}
