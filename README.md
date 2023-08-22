## Kubernetes Secret Creator for Gitea Credentials (mk_passwd.py)

### Overview
This script automates the creation of a Kubernetes secret named 
`gitea-assist-creds`, which stores Gitea credentials. By default, it generates 
a random 12-character password and sets the username to `gitea_admin`. 
However, you can specify custom values for both.

### Usage

- **Default (random password, `gitea_admin` username):**
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

- **Specify both password and username:**
  ```
  ./mk_passwd.py --password <your_predefined_password> --username <your_predefined_username>
  ```

### Behavior
The script checks if the `gitea-assist-creds` secret exists. If not, it 
creates the secret with the given or default credentials. If the secret 
exists, a notification is printed, and no changes are made.
