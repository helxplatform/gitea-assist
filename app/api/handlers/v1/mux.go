package v1

import "gitea_assist/internal/core"

type Mux struct {
	access core.GiteaAccess
}

func New(access *core.GiteaAccess) *Mux {
	return &Mux{
		access: *access,
	}
}
