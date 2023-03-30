#!/usr/bin/env python3
####################################################################
# created for CentOS, AlmaLinux, RockyLinux RPM OSes
# specifically for Centmin Mod LEMP stacks centminmod.com
# by George Liu (eva2000)
# https://github.com/centminmod/centminmod-abuseipdb-reporter
#
# script is used with CSF Firewall BLOCK_REPORT to send CSF Firewall
# LFD block actions to AbuseIPDB database via their API
# https://www.abuseipdb.com/csf
#
# To send data to AbuseIPDB, set DEBUG = False
# To check data without sending to AbuseIPDB, set DEBUG = True
#
# When DEBUG = True set, instead of sending data passed from CSF
# BLOCK_REPORT set script (this script), the data will be logged to
# DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'
# This log file contains for each entry 2 sets of data, the raw CSF
# sent data and data intended to be sent to AbuseIPDB. You can compare
# the two sets of data for troubleshooting and diagnostic purposes
#
# By default CSF Firewall passes the full /var/log/messages
# log file lines that lead up to and related to the CSF block
# action and that full log files is sent to AbuseIPDB up to up
# max 1024 characters. You can control how much of that data is
# sent to AbuseIPDB via variable LOG_MODE. Set to defaul to full
# you can change it to LOG_MODE = 'compact' to only sent the 1st
# log file line instead of the full log file.
####################################################################
import requests
import json
import sys
import argparse
import socket
import re
import subprocess
import configparser
import os
import atexit

VERSION = "0.1.4"
# Set the DEBUG and LOG_API_REQUEST variables here (True or False)
# DEBUG doesn't send to AbuseIPDB. Only logs to file
# LOG_API_REQUEST, when True, logs API requests to file
# LOG_MODE can be 'full' or 'compact' - compact shows 1st line of log file only
DEBUG = True
LOG_API_REQUEST = True
LOG_MODE = 'full'
# JSON_LOG_FORMAT can be set to False to write to DEFAULT_LOG_FILE
# or True to write to DEFAULT_JSONLOG_FILE defined log path below
JSON_LOG_FORMAT = False
# Set your API key and default log file path here
# https://www.abuseipdb.com/account/api
API_KEY = 'YOUR_API_KEY'
DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'
DEFAULT_JSONLOG_FILE = '/var/log/abuseipdb-reporter-debug-json.log'
DEFAULT_APILOG_FILE = '/var/log/abuseipdb-reporter-api.log'

# Set privacy masks
hostname = socket.gethostname()
full_hostname = socket.getfqdn()
short_hostname = socket.gethostname()

# Define dummy mask hostname and IP
mask_hostname = "MASKED_HOSTNAME"
mask_ip = "0.0.0.x"

# Get the absolute path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Read settings from the settings.ini file in the same directory as the script
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, 'abuseipdb-reporter.ini'))

# Override default settings if present in the settings file
if config.has_option('settings', 'DEBUG'):
    DEBUG = config.getboolean('settings', 'DEBUG')

if config.has_option('settings', 'LOG_API_REQUEST'):
    LOG_API_REQUEST = config.getboolean('settings', 'LOG_API_REQUEST')

if config.has_option('settings', 'LOG_MODE'):
    LOG_MODE = config.get('settings', 'LOG_MODE')

if config.has_option('settings', 'JSON_LOG_FORMAT'):
    JSON_LOG_FORMAT = config.getboolean('settings', 'JSON_LOG_FORMAT')

if config.has_option('settings', 'API_KEY'):
    API_KEY = config.get('settings', 'API_KEY')

if config.has_option('settings', 'DEFAULT_LOG_FILE'):
    DEFAULT_LOG_FILE = config.get('settings', 'DEFAULT_LOG_FILE')

if config.has_option('settings', 'DEFAULT_JSONLOG_FILE'):
    DEFAULT_JSONLOG_FILE = config.get('settings', 'DEFAULT_JSONLOG_FILE')

if config.has_option('settings', 'DEFAULT_APILOG_FILE'):
    DEFAULT_APILOG_FILE = config.get('settings', 'DEFAULT_APILOG_FILE')

if config.has_option('settings', 'mask_hostname'):
    mask_hostname = config.get('settings', 'mask_hostname')

if config.has_option('settings', 'mask_ip'):
    mask_ip = config.get('settings', 'mask_ip')

# Parse command line arguments
parser = argparse.ArgumentParser(description='AbuseIPDB reporter script.')
parser.add_argument('-log', dest='log_file', default=DEFAULT_LOG_FILE, help='Path to the log file.')
parser.add_argument('arguments', nargs='*', help='Arguments passed by CSF/LFD')
args = parser.parse_args()

def log_message(log_file, message):
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write("Log file created.\n")
    with open(log_file, 'a+') as f:
        f.write(message + '\n')

# Check if the required arguments are provided
if len(args.arguments) < 8:
    print("Error: Missing required arguments.")
    print("Usage: {} [-log LOG_FILE] IP PORTS INOUT MESSAGE LOGS TRIGGER".format(sys.argv[0]))
    log_message(args.log_file, "Error: Missing required arguments.")
    log_message(args.log_file, "Usage: {} [-log LOG_FILE] IP PORTS INOUT MESSAGE LOGS TRIGGER".format(sys.argv[0]))
    sys.exit(1)

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/report'
# Assign values to variables after checking for required arguments
ports = args.arguments[1]
inOut = args.arguments[3]
message = args.arguments[5]
logs = args.arguments[6]
trigger = args.arguments[7]

print("Ports:", ports)
print("In/Out:", inOut)
print("Message:", message)
print("Logs:", logs)
print("Trigger:", trigger)

def get_all_public_ips():
    try:
        cmd = "ip addr show | grep 'inet .*global' | awk '{print $2}' | cut -d '/' -f1"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        ips = output.strip().split('\n')
        return ips
    except subprocess.CalledProcessError:
        print("Error: Unable to fetch all public IPs.")
        log_message(args.log_file, "Error: Unable to fetch all public IPs.")
        sys.exit(1)

public_ips = get_all_public_ips()

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

# Replace the reported IP address in the logs with the mask IP
ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
time_pattern = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

if LOG_MODE == 'full':
    filtered_logs = '\n'.join([log for log in logs.split('\n') if ip_pattern.search(log) is not None])
    filtered_logs = '\n'.join([re.sub(r'^(\S+\s+\S+\s+)(\S+\s+)(\S+\s+)', r'\1\2', log) for log in filtered_logs.split('\n') if time_pattern.search(log) is not None and ip_pattern.search(log) is not None])
elif LOG_MODE == 'compact':
    filtered_logs = logs.split('\n')[0]  # Extract the first line
    filtered_logs = re.sub(r'^(\S+\s+\S+\s+)(\S+\s+)(\S+\s+)', r'\1\2', filtered_logs)  # Remove the 4th field
    filtered_logs = '\n'.join([filtered_logs for log in filtered_logs.split('\n') if time_pattern.search(log) is not None and ip_pattern.search(log) is not None])
else:
    print("Error: Invalid LOG_MODE. Supported modes: 'full' or 'compact'.")
    sys.exit(1)

# Create a regex pattern to match any content within the square brackets, preceded by the word "user"
username_pattern = r'(\buser )\[(.*?)\]'
# Replace the matched text in the filtered_logs variable with "user [USERNAME]"
filtered_logs = re.sub(username_pattern, r'\1[USERNAME]', filtered_logs)

# Create a regex pattern to match any content within the square brackets, preceded by the word "account"
any_content_pattern = r'(\baccount )\[(.*?)\]'
# Replace the matched text in the filtered_logs variable with "account [REDACTED]"
filtered_logs = re.sub(any_content_pattern, r'\1[REDACTED]', filtered_logs)

# Replace sensitive information in the filtered logs
masked_logs = filtered_logs.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname).replace(socket.getfqdn().split('.')[0], mask_hostname)

for ip in public_ips:
    masked_logs = masked_logs.replace(ip, mask_ip)

# Extract the destination IP from the log message and apply the change only if the trigger is 'PS_LIMIT'
if trigger == 'PS_LIMIT':
    dst_ip_match = re.search(r'DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', logs)

    if dst_ip_match:
        dst_ip = dst_ip_match.group(1)
        # Replace the destination IP with the masked IP in the masked_logs variable
        masked_logs = masked_logs.replace(dst_ip, mask_ip)

masked_message = message.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname)

for ip in public_ips:
    masked_message = masked_message.replace(ip, mask_ip)

# Create a regex pattern to match the desired text
pattern = r"Cluster member (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((.*?)\) said,"
# Remove the matched text from the masked_message variable
masked_message = re.sub(pattern, "", masked_message)

# Create the comment string
comment = masked_message + "; Ports: " + ports + "; Direction: " + inOut + "; Trigger: " + trigger + "; Logs: " + masked_logs

# Replace sensitive information in the comment string with the masked values
masked_comment = comment.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname)

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
elif 'PS_LIMIT' in trigger:
    categories = '14'
elif 'LF_DISTSMTP' in trigger:
    categories = '18'

querystring = {
    'ip': args.arguments[0],
    'categories': categories,
    'comment': masked_comment
}

def is_log_file_valid(file_path):
    if not os.path.exists(file_path):
        return False

    with open(file_path, 'rb') as f:
        f.seek(-2, os.SEEK_END)
        last_chars = f.read().decode()

    return last_chars == "\n]"


if DEBUG:
    log_data = {
        "sentVersion": VERSION,
        "sentURL": url,
        "sentHeaders": headers,
        "sentIP": args.arguments[0],
        "sentCategories": categories,
        "sentComment": masked_comment,
        "notsentPorts": ports,
        "notsentInOut": inOut,
        "notsentMessage": message,
        "notsentLogs": logs,
        "notsentTrigger": trigger
    }

    if JSON_LOG_FORMAT:
        if is_log_file_valid(DEFAULT_JSONLOG_FILE):
            # Remove the last closing bracket ']'
            with open(DEFAULT_JSONLOG_FILE, 'rb+') as f:
                f.seek(-2, os.SEEK_END)
                f.truncate()
            # Append the new log entry followed by a comma and a newline
            with open(DEFAULT_JSONLOG_FILE, 'a') as f:
                f.write(",\n" + json.dumps(log_data, indent=2) + "\n]")
        else:
            # Create a new log file with a single log entry
            with open(DEFAULT_JSONLOG_FILE, 'w') as f:
                f.write("[\n" + json.dumps(log_data, indent=2) + "\n]")

        print("DEBUG MODE: No actual report sent. JSON data saved to '{}'.".format(DEFAULT_JSONLOG_FILE))
    else:
        with open(args.log_file, 'a') as f:
            f.write("############################################################################\n")
            f.write("Version: {}\n".format(VERSION))
            f.write("DEBUG MODE: data intended to be sent to AbuseIPDB\n")
            f.write("URL: {}\n".format(url))
            f.write("Headers: {}\n".format(headers))
            f.write("IP: {}\n".format(args.arguments[0]))
            f.write("Categories: {}\n".format(categories))
            f.write("Comment: {}\n".format(masked_comment))
            f.write("---------------------------------------------------------------------------\n")
            f.write("DEBUG MODE: CSF passed data not sent to AbuseIPDB\n")
            f.write("Ports: {}\n".format(ports))
            f.write("In/Out: {}\n".format(inOut))
            f.write("Message: {}\n".format(message))
            f.write("Logs: {}\n".format(logs))
            f.write("Trigger: {}\n".format(trigger))
            f.write("############################################################################\n")
            f.write("--------\n")
        print("DEBUG MODE: No actual report sent. Data saved to '{}'.".format(args.log_file))
else:
    response = requests.post(url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    if LOG_API_REQUEST:
        with open(DEFAULT_APILOG_FILE, 'a') as f:
            f.write("############################################################################\n")
            f.write("Version: {}\n".format(VERSION))
            f.write("API Request Sent:\n")
            f.write("URL: {}\n".format(url))
            f.write("Headers: {}\n".format(headers))
            f.write("IP: {}\n".format(args.arguments[0]))
            f.write("Categories: {}\n".format(categories))
            f.write("Comment: {}\n".format(masked_comment))
            f.write("############################################################################\n")
            f.write("--------\n")

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