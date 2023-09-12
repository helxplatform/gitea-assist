#!/usr/bin/env python

import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="Test getting repo details via API.")
    parser.add_argument("repo_name", help="Name of the repository")
    parser.add_argument("owner", help="Owner of the repository")
    parser.add_argument("--server", default="localhost:8000", help="Server hostname with port (default: localhost:8000)")
    
    args = parser.parse_args()

    url = f"http://{args.server}/repos?name={args.repo_name}&owner={args.owner}"
    
    response = requests.get(url)
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
