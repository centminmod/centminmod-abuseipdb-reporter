#!/usr/bin/env python3
import time
import requests
import argparse
import configparser
import os
import sys
import re

# Get the current directory of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Read settings from an external .ini file
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, 'cf-ipaccess-expiry.ini'))

CLOUDFLARE_API_TOKEN = config.get('Settings', 'CLOUDFLARE_API_TOKEN', fallback='your_cloudflare_api_token')
CLOUDFLARE_ACCOUNT_ID = config.get('Settings', 'CLOUDFLARE_ACCOUNT_ID', fallback='your_account_id')
MAX_AGE_MINUTES = config.getint('Settings', 'MAX_AGE_MINUTES', fallback=360)

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_ACCESS_RULES_ENDPOINT = f"{CLOUDFLARE_API_BASE}/accounts/{CLOUDFLARE_ACCOUNT_ID}/firewall/access_rules/rules"

# Get the current epoch timestamp
current_timestamp = int(time.time())

headers = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json"
}

# Fetch existing Access Rules
response = requests.get(CLOUDFLARE_ACCESS_RULES_ENDPOINT, headers=headers)
response_json = response.json()

if response_json.get('success') == False:
    print("Error: Failed to fetch Access Rules from Cloudflare. Please check your API token and permissions.")
    print("Response JSON:", response_json)
    sys.exit(1)

access_rules = response_json["result"]

# Define the valid modes
valid_modes = ['block', 'challenge', 'whitelist', 'js_challenge', 'managed_challenge']

def add_rule(ip, mode, notes):
    if not ip:
        print("Error: Please provide a valid IP address with the -ip argument.")
        return

    if mode not in valid_modes:
        print(f"Error: Invalid mode '{mode}'. Valid modes are: {', '.join(valid_modes)}")
        return

    data = {
        'mode': mode,
        'configuration': {
            'target': 'ip',
            'value': ip
        },
        'notes': notes
    }

    response = requests.post(CLOUDFLARE_ACCESS_RULES_ENDPOINT, headers=headers, json=data)
    response_json = response.json()

    if response.status_code == 200:
        print(f"Added Access Rule for IP {ip} with mode {mode} and notes '{notes}'")
        print("Cloudflare API response:", response_json)
    else:
        print(f"Failed to add Access Rule for IP {ip} (Status Code: {response.status_code})")
        print("Cloudflare API response:", response_json)

def delete_old_rules(ip=None, all=False):
    # Iterate through Access Rules and delete older entries or specific IP
    for rule in access_rules:
        notes = rule["notes"]
        rule_id = rule["id"]
        rule_ip = rule["configuration"]["value"]

        if ip is not None and rule_ip != ip:
            continue

        if not all:
            try:
                # Extract epoch timestamp from the notes field
                rule_timestamp = int(notes.split(" ")[-1])
            except ValueError:
                print(f"Skipping Access Rule with ID {rule_id} due to non-matching notes format.")
                continue

            # Calculate the age of the Access Rule (in minutes)
            age_minutes = (current_timestamp - rule_timestamp) // 60
        else:
            age_minutes = 0

        # If the Access Rule is older than MAX_AGE_MINUTES, the specific IP or -all flag is set, delete it
        if ip is not None or age_minutes > MAX_AGE_MINUTES or all:
            delete_url = f"{CLOUDFLARE_ACCESS_RULES_ENDPOINT}/{rule_id}"
            delete_response = requests.delete(delete_url, headers=headers)
            delete_response_json = delete_response.json()

            if delete_response.status_code == 200:
                print(f"Deleted Access Rule with ID {rule_id} (IP: {rule_ip}, Age: {age_minutes} minutes)")
                print("Cloudflare API response:", delete_response_json)
            else:
                print(f"Failed to delete Access Rule with ID {rule_id} (Status Code: {delete_response.status_code})")
                print("Cloudflare API response:", delete_response_json)

def list_rules(ip=None, all=False, mode=None):   
    # Check if mode is valid, if it's provided
    if mode and mode not in valid_modes:
        print(f"Invalid mode '{mode}'. Valid modes are: {', '.join(valid_modes)}")
        return
    
    # Iterate through Access Rules and display them or specific IP
    for rule in access_rules:
        notes = rule["notes"]
        rule_id = rule["id"]
        rule_ip = rule["configuration"]["value"]
        rule_mode = rule["mode"]

        # Filter by IP, if provided
        if ip is not None and rule_ip != ip:
            continue

        # Filter by mode, if provided and valid
        if mode and rule_mode != mode:
            continue

        # Check if the notes field has an epoch timestamp
        has_epoch_timestamp = False
        regex_pattern = r'Blocked by abuseipdb-reporter\.py at epoch timestamp \d{10}'
        regex_match = re.search(regex_pattern, notes)

        if regex_match:
            try:
                rule_timestamp = int(notes.split(" ")[-1])
                age_minutes = (current_timestamp - rule_timestamp) // 60
                has_epoch_timestamp = True
            except ValueError:
                pass

        # Only list Access Rules with an epoch timestamp in the notes field or all flag is set or mode is provided
        if all or mode or has_epoch_timestamp:
            print("Access Rule:")
            print("ID:", rule_id)
            print("IP:", rule_ip)
            print("Mode:", rule_mode)
            print("Notes:", rule["notes"])
            print("----------")

# Argument parsing
parser = argparse.ArgumentParser(description='Cloudflare Access Rules Manager')
parser.add_argument('-delete', action='store_true', help='Delete old access rules or specific IP')
parser.add_argument('-list', action='store_true', help='List all access rules or specific IP')
parser.add_argument('-add', action='store_true', help='Add a new access rule for a specific IP')
parser.add_argument('-ip', type=str, help='IP address to filter or add')
parser.add_argument('-all', action='store_true', help='Bypass the epoch timestamp filter to match all access rule IP entries')
parser.add_argument('-mode', type=str, help='Filter by mode when listing access rules (block, challenge, whitelist, js_challenge, managed_challenge)')
parser.add_argument('-addmode', type=str, help='Mode when adding a new access rule (block, challenge, whitelist, js_challenge, managed_challenge)')
parser.add_argument('-notes', type=str, help='Notes when adding a new access rule')
args = parser.parse_args()

if args.delete or args.list or args.add:
    if args.delete:
        delete_old_rules(args.ip, args.all)
    elif args.list:
        list_rules(args.ip, args.all, args.mode)
    elif args.add:
        add_rule(args.ip, args.addmode, args.notes)
else:
    if args.ip:
        print("Please provide an action (-delete, -list, or -add) along with the -ip argument.")
        print("-list can be paired with -mode")
    else:
        print("Please provide an argument: -delete, -list, -add, or -ip or -all")