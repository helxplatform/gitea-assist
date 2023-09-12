#!/usr/bin/env python

import argparse
import requests
import json

def main():
    parser = argparse.ArgumentParser(description="Test user creation via API.")
    parser.add_argument("username", help="Username for the new user")
    parser.add_argument("password", help="Password for the new user")
    parser.add_argument("email", help="Email for the new user")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/users"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "Username": args.username,
        "Password": args.password,
        "Email": args.email
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
