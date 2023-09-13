#!/usr/bin/env python

import argparse
import requests
import json

def main():
    parser = argparse.ArgumentParser(description="Test repo forking via API.")
    parser.add_argument("repo", help="Name of the repository to fork")
    parser.add_argument("owner", help="Original owner of the repository")
    parser.add_argument("new_owner", help="Owner of the new forked repository")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/forks"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "Repo": args.repo,
        "Owner": args.owner,
        "NewOwner": args.new_owner
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()

