#!/usr/bin/env python

import argparse
import requests
import json

def main():
    parser = argparse.ArgumentParser(description="Test user deletion via API.")
    parser.add_argument("username", help="Username of the user")
    parser.add_argument("--purge", action="store_true", help="Completely purge the user from the system (repositories, membership, etc.)")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:9000/users"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "username": args.username,
        "purge": args.purge
    }

    response = requests.delete(url, headers=headers, data=json.dumps(data))
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
