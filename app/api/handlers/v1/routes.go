package v1

import (
	"net/http"

	"github.com/gorilla/mux"
)

func (m *Mux) Routes() http.Handler {
	router := mux.NewRouter()
	router.Use(AuthMiddleware)
	// router.HandleFunc("/onPush", webhookHandler)

	router.HandleFunc("/users", m.handleGetUser).Methods("GET")
	router.HandleFunc("/users", m.handleCreateUser).Methods("POST")
	router.HandleFunc("/users", m.handleDeleteUser).Methods("DELETE")

	router.HandleFunc("/repos", m.handleGetRepo).Methods("GET")
	router.HandleFunc("/repos", m.handleCreateRepo).Methods("POST")
	router.HandleFunc("/repos", m.handlePatchRepo).Methods("PATCH")
	router.HandleFunc("/repos/collaborators", m.handleRemoveCollaborator).Methods("DELETE")
	router.HandleFunc("/repos/collaborators", m.handleAddCollaborator).Methods("PUT")
	// router.HandleFunc("/repos/modify", handleModifyRepoFiles).Methods("POST")
	// router.HandleFunc("/repos/download", handleDownloadRepo).Methods("GET")

	// router.HandleFunc("/forks", handleFork)

	// router.HandleFunc("/orgs", handleOrg)
	// router.HandleFunc("/orgs/{orgName}/members", handleGetMembers).Methods("GET")
	// router.HandleFunc("/orgs/{orgName}/members/{userName}", handleAddMember).Methods("PUT")

	// router.HandleFunc("/readiness", readinessHandler)
	// router.HandleFunc("/liveness", livenessHandler)

	return router
}
