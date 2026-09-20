#!/usr/bin/env python3

import json
import requests

ADDRESS = "http://localhost:5000"


def get(uri, headers={}, params={}):
    return requests.get(f"{ADDRESS}/{uri}", headers=headers, params=params)


def post(uri, headers={}, data={}):
    return requests.post(f"{ADDRESS}/{uri}", headers=headers, data=data)


# Create a new user
create_user_response = post(
    "user",
    data={
        "name": "chris",
        "secret": "hunter22",
    },
)
assert create_user_response.status_code == 201, create_user_response.text
create_user_data = create_user_response.json()
assert "error" not in create_user_data, str(create_user_data)

# Note the access token for the new user
access_token_value = create_user_data["secrets"][0]["access_tokens"][0]["value"]

# Read the user without providing an access token
read_public_user_response = get("user/chris")
assert read_public_user_response.status_code == 200, read_public_user_response.text
read_public_user_data = read_public_user_response.json()
assert read_public_user_data["name"] == "chris", str(read_public_user_data)

# Read the user while providing an access token
read_private_user_response = get(
    "user/chris",
    headers={"authorization": f"bearer {access_token_value}"},
)
assert read_private_user_response.status_code == 200, read_private_user_response.text
read_private_user_data = read_public_user_response.json()
assert read_private_user_data["name"] == "chris", str(read_private_user_data)
assert "secrets" in read_private_user_data, str(read_private_user_data)
