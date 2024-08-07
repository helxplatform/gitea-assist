package v1

import (
	"log"
	"net/http"
	"os"
	"strings"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure that we indicate authorization may vary
		w.Header().Add("Vary", "Authorization")

		// Returns "" empty string if nothing is found.
		authorizationHeader := r.Header.Get("Authorization")

		// If no auth header, set user as anonymous
		if authorizationHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			http.Error(w, message, http.StatusUnauthorized)
			return
		}

		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			http.Error(w, message, http.StatusUnauthorized)
			return
		}

		token := headerParts[1]

		admin, err := os.ReadFile("/etc/assist-secret/assist-token")
		if err != nil {
			log.Printf("Error reading file: %v", err)
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		// Trim the whitespace from file
		if strings.TrimSpace(string(admin)) != strings.TrimSpace(token) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			message := "invalid or missing auth token"
			http.Error(w, message, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
