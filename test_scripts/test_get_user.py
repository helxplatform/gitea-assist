#!/usr/bin/env python

import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="Test getting user details via API.")
    parser.add_argument("username", help="Username to retrieve")
    parser.add_argument("--server", default="localhost", help="Server hostname with port (default: localhost)")
    
    args = parser.parse_args()

    url = f"http://{args.server}:8000/users?username={args.username}"
    
    response = requests.get(url)
    
    print(response.status_code)
    print(response.text)

if __name__ == "__main__":
    main()
