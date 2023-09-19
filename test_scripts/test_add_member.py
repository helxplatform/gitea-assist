#!/usr/bin/env python

import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="Test adding a member to an organization via API.")
    parser.add_argument("org_name", help="Name of the organization to add the user to")
    parser.add_argument("user_name", help="Name of the user to add to the organization")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/orgs/{args.org_name}/members/{args.user_name}"
    
    response = requests.put(url)
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
