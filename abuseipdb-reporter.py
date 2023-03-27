#!/usr/bin/env python3
import requests
import json
import sys
import argparse
import socket
import re

# Set the DEBUG variable here (True or False)
# True doesn't send to AbuseIPDB. Only logs to file
# False, will send to AbuseIPDB
DEBUG = True
# Set your API key and default log file path here
# https://www.abuseipdb.com/account/api
API_KEY = 'YOUR_API_KEY'
DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'

# Set privacy masks
hostname = socket.gethostname()
full_hostname = socket.getfqdn()
short_hostname = socket.gethostname()

# Define dummy mask hostname and IP
mask_hostname = "MASKED_HOSTNAME"
mask_ip = "0.0.0.0"

# Parse command line arguments
parser = argparse.ArgumentParser(description='AbuseIPDB reporter script.')
parser.add_argument('-log', dest='log_file', default=DEFAULT_LOG_FILE, help='Path to the log file.')
parser.add_argument('arguments', nargs='*', help='Arguments passed by CSF/LFD')
args = parser.parse_args()

# Check if the required arguments are provided
if len(args.arguments) < 8:
    print("Error: Missing required arguments.")
    print("Usage: {} [-log LOG_FILE] IP PORTS INOUT MESSAGE LOGS TRIGGER".format(sys.argv[0]))
    sys.exit(1)

# Assign values to variables after checking for required arguments
ports = args.arguments[1]
inOut = args.arguments[3]
message = args.arguments[5]
logs = args.arguments[6]
trigger = args.arguments[7]

def get_public_ip():
    try:
        response = requests.get("https://geoip.centminmod.com/v4")
        data = response.json()
        return data['ip']
    except requests.RequestException:
        print("Error: Unable to fetch public IP from custom GeoIP API.")
        sys.exit(1)

public_ip = get_public_ip()

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/report'
ports = args.arguments[1]
inOut = args.arguments[3]
message = args.arguments[5]
logs = args.arguments[6]
trigger = args.arguments[7]

# Mask sensitive information in logs
masked_logs = re.sub(r'\b{}\b'.format(short_hostname), mask_hostname, logs).replace(full_hostname, mask_hostname).replace(socket.getfqdn().split('.')[0], mask_hostname)

# Update the comment string to use the masked_logs
comment = message + "; Ports: " + ports + "; Direction: " + inOut + "; Trigger: " + trigger + "; Logs: " + masked_logs

# Mask sensitive information
masked_comment = comment.replace(public_ip, mask_ip).replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname)

headers = {
     'Accept': 'application/json',
     'Key': API_KEY
}
# String holding parameters to pass in json format
# https://www.abuseipdb.com/categories
querystring = {
    'ip': args.arguments[0],
    'categories': '14',
    'comment': masked_comment
}

if DEBUG:
    with open(args.log_file, 'a') as f:
        f.write("DEBUG MODE: No actual report sent.\n")
        f.write("URL: {}\n".format(url))
        f.write("Headers: {}\n".format(headers))
        f.write("IP: {}\n".format(args.arguments[0]))
        f.write("Categories: 14\n")
        f.write("Comment: {}\n".format(masked_comment))
        f.write("----\n")
    print("DEBUG MODE: No actual report sent. Data saved to '{}'.".format(args.log_file))
else:
    response = requests.post(url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)

    if response.status_code == 200:
        print(json.dumps(decodedResponse['data'], sort_keys=True, indent=4))
    elif response.status_code == 429:
        print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
    elif response.status_code == 422:
        print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
    elif response.status_code == 302:
        print('Unsecure protocol requested. Redirected to HTTPS.')
    elif response.status_code == 401:
        print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
    else:
        print('Unexpected server response. Status Code: {}'.format(response.status_code))
