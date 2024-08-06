#!/usr/bin/env python

import subprocess
import secrets
import string
import argparse

# Argument parser setup
parser = argparse.ArgumentParser(description="Create a Kubernetes secret with a random or predefined password and username.")
parser.add_argument('--password', type=str, help='Predefined password to use. If not provided, a random password will be generated.')
parser.add_argument('--username', type=str, default='gitea_admin', help='Username to use. Defaults to "gitea_admin".')
parser.add_argument('--token', type=str, help='Gitea-Assist token for Authentication Bearer [token] exchange with the API itself.')

args = parser.parse_args()

# Generate a random password of length 12 if no predefined password is provided
alphabet = string.ascii_letters + string.digits 
password = args.password if args.password else ''.join(secrets.choice(alphabet) for i in range(12))
username = args.username
token    = args.token if args.token else ''.join(secrets.choice(alphabet) for i in range(15))

# Name of the secret
secret_name = "gitea-assist-creds"

# Check if the secret already exists
get_secret_command = ["kubectl", "get", "secret", secret_name]
get_secret_process = subprocess.run(get_secret_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# If the secret does not exist, create it
if get_secret_process.returncode != 0:
    create_secret_command = [
        "kubectl",
        "create",
        "secret", 
        "generic", 
        secret_name, 
        "--from-literal=gitea-password={}".format(password),
        "--from-literal=gitea-username={}".format(username),
        "--from-literal=assist-token={}".format(token)
    ]
    subprocess.run(create_secret_command, check=True)
else:
    print("Secret '{}' already exists. Not creating.".format(secret_name))
