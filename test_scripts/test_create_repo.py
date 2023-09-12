#!/usr/bin/env python

import argparse
import requests
import json

def main():
    parser = argparse.ArgumentParser(description="Test repo creation via API.")
    parser.add_argument("repo_name", help="Name of the repository to create")
    parser.add_argument("owner", help="Owner of the repository")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/repos"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "Name": args.repo_name,
        "Description": "A test repository",
        "Owner": args.owner,
        "Private": False
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
