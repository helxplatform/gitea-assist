#!/usr/bin/env python

import argparse
import requests
import json

def main():
    parser = argparse.ArgumentParser(description="Test organization creation via API.")
    parser.add_argument("org_name", help="Name of the organization to create")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/orgs"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "org_name": args.org_name
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()

