#!/usr/bin/env python

import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="Test getting organization details via API.")
    parser.add_argument("org_name", help="Name of the organization to retrieve")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/orgs?org_name={args.org_name}"
    
    response = requests.get(url)
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()

