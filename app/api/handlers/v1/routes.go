package v1

import (
	"net/http"

	"github.com/gorilla/mux"
)

func (m *Mux) Routes() http.Handler {
	router := mux.NewRouter()
	router.HandleFunc("/users", handleUser)
	router.HandleFunc("/onPush", webhookHandler)

	router.HandleFunc("/repos", handleRepo)
	router.HandleFunc("/repos/collaborators", handleRepoCollaborator)
	router.HandleFunc("/repos/modify", handleModifyRepoFiles).Methods("POST")
	router.HandleFunc("/repos/download", handleDownloadRepo).Methods("GET")

	router.HandleFunc("/forks", handleFork)

	router.HandleFunc("/orgs", handleOrg)
	router.HandleFunc("/orgs/{orgName}/members", handleGetMembers).Methods("GET")
	router.HandleFunc("/orgs/{orgName}/members/{userName}", handleAddMember).Methods("PUT")

	router.HandleFunc("/readiness", readinessHandler)
	router.HandleFunc("/liveness", livenessHandler)
	// http.Handle("/", router)
	return router
}
