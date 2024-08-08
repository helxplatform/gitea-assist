package errorapi

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type APIError struct {
	error
	status int
}

func (e APIError) Error() string {
	msg := e.error.Error()
	// The join method while wrapping concatenates error messages with newlines. Replace newlines with spaces
	return strings.Replace(msg, "\n", " ", -1)
}

func (e APIError) Compare(err APIError) bool {
	return errors.Is(e.error, err.error)
}

var (
	// A list of general error of type APIError
	ErrBadRequest          = &APIError{error: errors.New("bad request"), status: http.StatusBadRequest}
	ErrNotFound            = &APIError{error: errors.New("not found"), status: http.StatusNotFound}
	ErrInternalServerError = &APIError{error: errors.New("internal server error"), status: http.StatusInternalServerError}
	ErrRequestReadError    = &APIError{error: errors.New("error reading request body"), status: http.StatusBadRequest}
	ErrResponseReadError   = &APIError{error: errors.New("error reading response body"), status: http.StatusBadRequest}
	ErrRequestParseError   = &APIError{error: errors.New("request parse error"), status: http.StatusBadRequest}
	ErrMethodNotAllowed    = &APIError{error: errors.New("method not allowed"), status: http.StatusMethodNotAllowed}
	ErrGiteaConnectError   = &APIError{error: errors.New("error connecting to gitea"), status: http.StatusBadRequest}
	ErrUnauthorized        = &APIError{error: errors.New("unauthorized attempt to login"), status: http.StatusUnauthorized}
	// Making a slice for all predefined errors for ease of comparison in HandleError below
	allErrors = []APIError{*ErrBadRequest, *ErrNotFound, *ErrInternalServerError, *ErrRequestReadError, *ErrMethodNotAllowed, *ErrRequestParseError}
)

// This function provides capability to "modify" the message of an existing error
// but still keep the original type when comparing
// For example:
// repoError := WrapError(ErrNotFound, "Repo") :: Creates a new error specific to repo
// But now, repoError.Compare(ErrNotFound) will return true because of the Join method of errors package
func WrapError(e *APIError, msg string) *APIError {
	err := errors.Join(fmt.Errorf("%v", msg), e.error)
	return &APIError{error: err, status: e.status}
}

func HandleError(w http.ResponseWriter, err *APIError) {
	for _, sperr := range allErrors {
		if err.Compare(sperr) {
			http.Error(w, err.Error(), err.status)
			log.Println("ERROR:: %s STATUS:: %d", err.Error(), err.status)
			return
		}
	}
	http.Error(w, ErrInternalServerError.Error(), ErrInternalServerError.status)
}
