# gitea-assist (Gitea Webhook Processor)

This application is designed to automatically process Gitea push webhooks. When a push event is received for a repository, the application will:
1. Clone the repository associated with the push event.
2. Find all forks of this repository.
3. For each fork:
   - Clone the fork.
   - Calculate the difference between the fork and the origin repository.
   - Merge changes from the origin repository into the fork.
   - Push the merged changes to the fork.

## Dependencies

The application uses several Go libraries:
- Standard Go libraries like `encoding/json`, `io`, `log`, `net/http`, `os`, `path/filepath`, and `strings`.
- Gitea modules for structs (`code.gitea.io/gitea/modules/structs`).
- Go-git libraries (`github.com/go-git/go-git/v5` and its sub-modules) for Git operations.

## Configuration

The application reads Gitea credentials from the following files:
- `/etc/assist-secret/gitea-username` for the username.
- `/etc/assist-secret/gitea-password` for the password.

The application expects a Bearer Token for use of gitea functionality which is supplied by:
- `/etc/assist-secret/assist-token` for the assist auth token.

Ensure these files are present and contain the necessary credentials for accessing Gitea repositories. These can be created by using the mk_passwd.py script

## Endpoints

- `/onPush`: Endpoint to receive Gitea push webhooks.
- `/readiness`: A readiness endpoint that returns 200 OK, indicating the service is ready to handle requests.
- `/liveness`: A liveness endpoint that returns 200 OK, indicating the service is alive and healthy.
- `/users`: Endpoint to handle users in Gitea instance
- `/users/ssh`: Endpoint to manage ssh keys for Gitea
- `/repos`: Endpoint to manage repo list
	
An example curl command needed to hit any of the endpoints is:
`curl -H "Authorization: Bearer <assist-token_from_secret>" -X GET "http://<server_ip>:9000/users?username=<user_name>"`

## Running the Application

To run the application, simply execute:
```
go run main.go
```

This will start an HTTP server on port 9000.

## Kubernetes Secret Creator for Gitea Credentials (mk_passwd.py)

### Overview
This script automates the creation of a Kubernetes secret named 
`gitea-assist-creds`, which stores Gitea credentials. By default, it generates 
a random 12-character password and sets the username to `gitea_admin`. 
However, you can specify custom values for both.

### Usage

- **Default (random password, `gitea_admin` username and `assist-token`):**
  ```
  ./mk_passwd.py
  ```

- **Specify a password:**
  ```
  ./mk_passwd.py --password <your_predefined_password>
  ```

- **Specify a username:**
  ```
  ./mk_passwd.py --username <your_predefined_username>
  ```

- **Specify both password, username and token:**
  ```
  ./mk_passwd.py --password <your_predefined_password> --username <your_predefined_username> --token <your_predefined_token>
  ```

### Behavior
The script checks if the `gitea-assist-creds` secret exists. If not, it 
creates the secret with the given or default credentials. If the secret 
exists, a notification is printed, and no changes are made.
