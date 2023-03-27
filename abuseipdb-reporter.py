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

# Get the values from the csf.conf file
with open('/etc/csf/csf.conf') as f:
    csf_conf = f.read()

# Use non-greedy matching to capture the IP addresses in the config file
cluster_sendto = re.search(r'CLUSTER_SENDTO\s*=\s*(.*?)\n', csf_conf, re.DOTALL)
cluster_recvfrom = re.search(r'CLUSTER_RECVFROM\s*=\s*(.*?)\n', csf_conf, re.DOTALL)
cluster_master = re.search(r'CLUSTER_MASTER\s*=\s*(.*?)\n', csf_conf, re.DOTALL)

if cluster_sendto:
    # Split the IP addresses by comma and remove any empty strings
    sendto_ips = [ip.strip() for ip in cluster_sendto.group(1).split(',') if ip.strip()]
else:
    sendto_ips = []

if cluster_recvfrom:
    recvfrom_ips = [ip.strip() for ip in cluster_recvfrom.group(1).split(',') if ip.strip()]
else:
    recvfrom_ips = []

if cluster_master:
    master_ips = [ip.strip() for ip in cluster_master.group(1).split(',') if ip.strip()]
else:
    master_ips = []

# Mask sensitive information in logs and the comment string
masked_logs = logs.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname).replace(socket.getfqdn().split('.')[0], mask_hostname)

# Replace IP addresses in the message string with the mask IP
ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
masked_message = ip_pattern.sub(mask_ip, message)

# Create the comment string
comment = masked_message + "; Ports: " + ports + "; Direction: " + inOut + "; Trigger: " + trigger + "; Logs: " + masked_logs

# Replace sensitive information in the comment string with the masked values
masked_comment = comment.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname).replace(args.arguments[0], mask_ip)

headers = {
     'Accept': 'application/json',
     'Key': API_KEY
}
# String holding parameters to pass in json format
# https://www.abuseipdb.com/categories
categories = '14'
if 'LF_SSHD' in trigger:
    categories = '22'
elif 'LF_DISTATTACK' in trigger:
    categories = '4'
elif 'LF_SMTPAUTH' in trigger:
    categories = '18'
elif 'LF_FTPD' in trigger:
    categories = '5'
elif 'LF_MODSEC' in trigger:
    categories = '21'

querystring = {
    'ip': args.arguments[0],
    'categories': categories,
    'comment': masked_comment
}

if DEBUG:
    with open(args.log_file, 'a') as f:
        f.write("DEBUG MODE: No actual report sent.\n")
        f.write("URL: {}\n".format(url))
        f.write("Headers: {}\n".format(headers))
        f.write("IP: {}\n".format(args.arguments[0]))
        f.write("Categories: {}\n".format(categories))
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
