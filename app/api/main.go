package main

import (
	"fmt"
	"gitea_assist/app/internal/core"
	"log"
)

func main() {

}

func run() {
	access, err := core.NewAccess()
	if err != nil {
		log.Fatalf("Error: reading gitea access-secret file %v", err)
	}
	fmt.Println(access)
}
