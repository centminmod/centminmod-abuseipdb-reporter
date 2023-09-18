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
try:
    import requests
except ImportError:
    print("The 'requests' package is not installed. Please install it by running:")
    print("pip3 install requests")
    exit(1)
import logging
import logging.handlers
import json
import sys
import argparse
import socket
import re
import subprocess
import configparser
import os
import atexit
import time
import datetime
import fcntl
from urllib.parse import quote

VERSION = "0.5.3"
# Set the DEBUG and LOG_API_REQUEST variables here (True or False)
# DEBUG doesn't send to AbuseIPDB. Only logs to file
# LOG_API_REQUEST, when True, logs API requests to file
# LOG_MODE can be 'full' or 'compact' - compact shows 1st line of log file only
DEBUG = True
LOG_API_REQUEST = True
LOG_MODE = 'compact'
# JSON_LOG_FORMAT can be set to False to write to DEFAULT_LOG_FILE
# or True to write to DEFAULT_JSONLOG_FILE defined log path below
JSON_LOG_FORMAT = False
JSON_APILOG_FORMAT = False
# Set IGNORE_CLUSTER_SUBMISSIONS = True to ignore Cluster member reports
# for submission to AbuseIPDB API. Set to IGNORE_CLUSTER_SUBMISSIONS = False
# to sent Cluster member reports to AbuseiPDB API as well
IGNORE_CLUSTER_SUBMISSIONS = True
# Set your API key and default log file path here
# https://www.abuseipdb.com/account/api
API_KEY = 'YOUR_API_KEY'
DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'
DEFAULT_JSONLOG_FILE = '/var/log/abuseipdb-reporter-debug-json.log'
DEFAULT_APILOG_FILE = '/var/log/abuseipdb-reporter-api.log'
DEFAULT_JSONAPILOG_FILE = '/var/log/abuseipdb-reporter-api-json.log'
DEBUG_ALL_LOG_FILE = '/var/log/abuseipdb-detailed.log'

# Local IP submission cache
CACHE_FILE = "ip_cache.json"
# cache for 15 minutes in seconds
CACHE_DURATION = 900

# Set the replacement words to mask data that references
# usernames and account usernames. If set in .ini file you can remove
# single quotes
USERNAME_REPLACEMENT = '[USERNAME]'
ACCOUNT_REPLACEMENT = '[REDACTED]'
EMAIL_REPLACEMENT = 'EMAIL'

# Set privacy masks
ETHERNET_MASK = True
hostname = socket.gethostname()
full_hostname = socket.getfqdn()
short_hostname = socket.gethostname()

# Define dummy mask hostname and IP
mask_hostname = "MASKED_HOSTNAME"
mask_ip = "0.0.0.x"

# default LFD trigger AbuseIPDB categories assigned
# https://www.abuseipdb.com/categories
LF_DEFAULT_CATEGORY = '14'
LF_PERMBLOCK_COUNT_CATEGORY = '14'
LF_SSHD_CATEGORY = '22'
LF_DISTATTACK_CATEGORY = '4'
LF_SMTPAUTH_CATEGORY = '18'
LF_DISTFTP_CATEGORY = '5'
LF_FTPD_CATEGORY = '5'
LF_MODSEC_CATEGORY = '21'
PS_LIMIT_CATEGORY = '14'
LF_DISTSMTP_CATEGORY = '18'
CT_LIMIT_CATEGORY = '4'
LF_DIRECTADMIN_CATEGORY = '21'
LF_CUSTOMTRIGGER_CATEGORY = '21'
LF_HTACCESS_CATEGORY = '21'
LF_IMAPD_CATEGORY = '18'
LF_POP3D_CATEGORY = '18'

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = DEBUG_ALL_LOG_FILE

# Set up the logger
logger = logging.getLogger('AbuseIPDBReporter')
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

logger.info("Script started.")

# Get the absolute path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Read settings from the settings.ini file in the same directory as the script
config = configparser.ConfigParser()
config.read(os.path.join(script_dir, 'abuseipdb-reporter.ini'))
logger.info(f"Read {script_dir}/abuseipdb-reporter.ini.")

# Override default settings if present in the settings file
if config.has_option('settings', 'DEBUG'):
    DEBUG = config.getboolean('settings', 'DEBUG')
    logger.debug(f"DEBUG set to {DEBUG} from .ini file")

if config.has_option('settings', 'ETHERNET_MASK'):
    ETHERNET_MASK = config.getboolean('settings', 'ETHERNET_MASK')
    logger.debug(f"ETHERNET_MASK set to {ETHERNET_MASK} from .ini file")

if config.has_option('settings', 'LOG_API_REQUEST'):
    LOG_API_REQUEST = config.getboolean('settings', 'LOG_API_REQUEST')
    logger.debug(f"LOG_API_REQUEST set to {LOG_API_REQUEST} from .ini file")

if config.has_option('settings', 'LOG_MODE'):
    LOG_MODE = config.get('settings', 'LOG_MODE')
    logger.debug(f"LOG_MODE set to {LOG_MODE} from .ini file")

if config.has_option('settings', 'JSON_LOG_FORMAT'):
    JSON_LOG_FORMAT = config.getboolean('settings', 'JSON_LOG_FORMAT')
    logger.debug(f"JSON_LOG_FORMAT set to {JSON_LOG_FORMAT} from .ini file")

if config.has_option('settings', 'IGNORE_CLUSTER_SUBMISSIONS'):
    IGNORE_CLUSTER_SUBMISSIONS = config.getboolean('settings', 'IGNORE_CLUSTER_SUBMISSIONS')
    logger.debug(f"IGNORE_CLUSTER_SUBMISSIONS set to {IGNORE_CLUSTER_SUBMISSIONS} from .ini file")

if config.has_option('settings', 'API_KEY'):
    API_KEY = config.get('settings', 'API_KEY')
    logger.debug(f"API_KEY set from .ini file")

if config.has_option('settings', 'DEFAULT_LOG_FILE'):
    DEFAULT_LOG_FILE = config.get('settings', 'DEFAULT_LOG_FILE')
    logger.debug(f"DEFAULT_LOG_FILE set to {DEFAULT_LOG_FILE} from .ini file")

if config.has_option('settings', 'DEFAULT_JSONLOG_FILE'):
    DEFAULT_JSONLOG_FILE = config.get('settings', 'DEFAULT_JSONLOG_FILE')
    logger.debug(f"DEFAULT_JSONLOG_FILE set to {DEFAULT_JSONLOG_FILE} from .ini file")

if config.has_option('settings', 'DEFAULT_APILOG_FILE'):
    DEFAULT_APILOG_FILE = config.get('settings', 'DEFAULT_APILOG_FILE')
    logger.debug(f"DEFAULT_APILOG_FILE set to {DEFAULT_APILOG_FILE} from .ini file")

if config.has_option('settings', 'JSON_APILOG_FORMAT'):
    JSON_APILOG_FORMAT = config.getboolean('settings', 'JSON_APILOG_FORMAT')
    logger.debug(f"JSON_APILOG_FORMAT set to {JSON_APILOG_FORMAT} from .ini file")

if config.has_option('settings', 'DEFAULT_JSONAPILOG_FILE'):
    DEFAULT_JSONAPILOG_FILE = config.get('settings', 'DEFAULT_JSONAPILOG_FILE')
    logger.debug(f"DEFAULT_JSONAPILOG_FILE set to {DEFAULT_JSONAPILOG_FILE} from .ini file")

if config.has_option('settings', 'DEBUG_ALL_LOG_FILE'):
    DEBUG_ALL_LOG_FILE = config.get('settings', 'DEBUG_ALL_LOG_FILE')
    logger.debug(f"DEBUG_ALL_LOG_FILE set to {DEBUG_ALL_LOG_FILE} from .ini file")

if config.has_option('settings', 'mask_hostname'):
    mask_hostname = config.get('settings', 'mask_hostname')
    logger.debug(f"mask_hostname set to {mask_hostname} from .ini file")

if config.has_option('settings', 'mask_ip'):
    mask_ip = config.get('settings', 'mask_ip')
    logger.debug(f"mask_ip set to {mask_ip} from .ini file")

if config.has_option('settings', 'USERNAME_REPLACEMENT'):
    USERNAME_REPLACEMENT = config.get('settings', 'USERNAME_REPLACEMENT')
    logger.debug(f"USERNAME_REPLACEMENT set to {USERNAME_REPLACEMENT} from .ini file")

if config.has_option('settings', 'ACCOUNT_REPLACEMENT'):
    ACCOUNT_REPLACEMENT = config.get('settings', 'ACCOUNT_REPLACEMENT')
    logger.debug(f"ACCOUNT_REPLACEMENT set to {ACCOUNT_REPLACEMENT} from .ini file")

if config.has_option('settings', 'EMAIL_REPLACEMENT'):
    EMAIL_REPLACEMENT = config.get('settings', 'EMAIL_REPLACEMENT')
    logger.debug(f"EMAIL_REPLACEMENT set to {EMAIL_REPLACEMENT} from .ini file")

if config.has_option('settings', 'CACHE_FILE'):
    CACHE_FILE = config.get('settings', 'CACHE_FILE')
    logger.debug(f"CACHE_FILE set to {CACHE_FILE} from .ini file")

if config.has_option('settings', 'CACHE_DURATION'):
    CACHE_DURATION = config.get('settings', 'CACHE_DURATION')
    CACHE_DURATION = float(CACHE_DURATION)
    logger.debug(f"CACHE_DURATION set to {CACHE_DURATION} from .ini file")

if config.has_option('settings', 'LF_DEFAULT_CATEGORY'):
    LF_DEFAULT_CATEGORY = config.get('settings', 'LF_DEFAULT_CATEGORY')
    logger.debug(f"LF_DEFAULT_CATEGORY set to {LF_DEFAULT_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_PERMBLOCK_COUNT_CATEGORY'):
    LF_PERMBLOCK_COUNT_CATEGORY = config.get('settings', 'LF_PERMBLOCK_COUNT_CATEGORY')
    logger.debug(f"LF_PERMBLOCK_COUNT_CATEGORY set to {LF_PERMBLOCK_COUNT_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_SSHD_CATEGORY'):
    LF_SSHD_CATEGORY = config.get('settings', 'LF_SSHD_CATEGORY')
    logger.debug(f"LF_SSHD_CATEGORY set to {LF_SSHD_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_DISTATTACK_CATEGORY'):
    LF_DISTATTACK_CATEGORY = config.get('settings', 'LF_DISTATTACK_CATEGORY')
    logger.debug(f"LF_DISTATTACK_CATEGORY set to {LF_DISTATTACK_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_SMTPAUTH_CATEGORY'):
    LF_SMTPAUTH_CATEGORY = config.get('settings', 'LF_SMTPAUTH_CATEGORY')
    logger.debug(f"LF_SMTPAUTH_CATEGORY set to {LF_SMTPAUTH_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_DISTFTP_CATEGORY'):
    LF_DISTFTP_CATEGORY = config.get('settings', 'LF_DISTFTP_CATEGORY')
    logger.debug(f"LF_DISTFTP_CATEGORY set to {LF_DISTFTP_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_FTPD_CATEGORY'):
    LF_FTPD_CATEGORY = config.get('settings', 'LF_FTPD_CATEGORY')
    logger.debug(f"LF_FTPD_CATEGORY set to {LF_FTPD_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_MODSEC_CATEGORY'):
    LF_MODSEC_CATEGORY = config.get('settings', 'LF_MODSEC_CATEGORY')
    logger.debug(f"LF_MODSEC_CATEGORY set to {LF_MODSEC_CATEGORY} from .ini file")

if config.has_option('settings', 'PS_LIMIT_CATEGORY'):
    PS_LIMIT_CATEGORY = config.get('settings', 'PS_LIMIT_CATEGORY')
    logger.debug(f"PS_LIMIT_CATEGORY set to {PS_LIMIT_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_DISTSMTP_CATEGORY'):
    LF_DISTSMTP_CATEGORY = config.get('settings', 'LF_DISTSMTP_CATEGORY')
    logger.debug(f"LF_DISTSMTP_CATEGORY set to {LF_DISTSMTP_CATEGORY} from .ini file")

if config.has_option('settings', 'CT_LIMIT_CATEGORY'):
    CT_LIMIT_CATEGORY = config.get('settings', 'CT_LIMIT_CATEGORY')
    logger.debug(f"CT_LIMIT_CATEGORY set to {CT_LIMIT_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_DIRECTADMIN_CATEGORY'):
    LF_DIRECTADMIN_CATEGORY = config.get('settings', 'LF_DIRECTADMIN_CATEGORY')
    logger.debug(f"LF_DIRECTADMIN_CATEGORY set to {LF_DIRECTADMIN_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_CUSTOMTRIGGER_CATEGORY'):
    LF_CUSTOMTRIGGER_CATEGORY = config.get('settings', 'LF_CUSTOMTRIGGER_CATEGORY')
    logger.debug(f"LF_CUSTOMTRIGGER_CATEGORY set to {LF_CUSTOMTRIGGER_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_HTACCESS_CATEGORY'):
    LF_HTACCESS_CATEGORY = config.get('settings', 'LF_HTACCESS_CATEGORY')
    logger.debug(f"LF_HTACCESS_CATEGORY set to {LF_HTACCESS_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_IMAPD_CATEGORY'):
    LF_IMAPD_CATEGORY = config.get('settings', 'LF_IMAPD_CATEGORY')
    logger.debug(f"LF_IMAPD_CATEGORY set to {LF_IMAPD_CATEGORY} from .ini file")

if config.has_option('settings', 'LF_POP3D_CATEGORY'):
    LF_POP3D_CATEGORY = config.get('settings', 'LF_POP3D_CATEGORY')
    logger.debug(f"LF_POP3D_CATEGORY set to {LF_POP3D_CATEGORY} from .ini file")

# Parse command line arguments
parser = argparse.ArgumentParser(description='AbuseIPDB reporter script.')
parser.add_argument('-log', dest='log_file', default=DEFAULT_LOG_FILE, help='Path to the log file.')
parser.add_argument('arguments', nargs='*', help='Arguments passed by CSF/LFD')
args = parser.parse_args()

def lock_file(file):
    fcntl.flock(file.fileno(), fcntl.LOCK_EX)

def unlock_file(file):
    fcntl.flock(file.fileno(), fcntl.LOCK_UN)

def log_message(log_file, message):
    try:
        # Ensure the directory containing the log file exists
        log_directory = os.path.dirname(log_file)
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)

        # Check if log file exists; if not, create it
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("Log file created.\n")

        # Append the message to the log file
        with open(log_file, 'a+') as f:
            f.write(message + '\n')
    except IOError as e:
        error_msg = f"Failed to write to log file {log_file}. Error: {e}"
        print(error_msg)  # Print to console for immediate feedback
        with open("/var/log/abuseipdb-reporter-log-message-function.log", 'a+') as error_log:
            error_log.write(error_msg + '\n')

print(f"\nReceived arguments: {args.arguments}\n")

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

logger.debug(f"Received Ports: {ports}")
print("Received Ports:", ports)

logger.debug(f"Received In/Out: {inOut}")
print("Received In/Out:", inOut)

logger.debug(f"Received Message: {message}")
print("Received Message:", message)

logger.debug(f"Received Logs: {logs}")
print("Received Logs:", logs)

logger.debug(f"Received Trigger: {trigger}")
print("Received Trigger:", trigger, '\n')


def load_excluded_ips(filename):
    with open(filename, 'r') as f:
        return set(line.strip() for line in f)

def load_cache():
    if os.path.isfile(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            try:
                data = json.load(f)
                logger.debug("Loaded cache data before conversion: %s", data)
                print("Loaded cache data before conversion:", data)
                # Convert timestamp values to float
                data = {ip: float(timestamp) for ip, timestamp in data.items()}
                logger.debug("Loaded cache data after conversion: %s", data)
                print("Loaded cache data after conversion:", data)
                return data
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON from cache file. Returning an empty cache.")
                logger.error("Corrupted cache file detected. Recreating it.")
                # Clear or recreate the cache file
                with open(CACHE_FILE, 'w') as f:
                    f.write("{}")
                return {}
    else:
        return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)
        f.write('\n')  # Ensure the file ends with a newline

def clean_cache(cache):
    current_time = time.time()
    cleaned_cache = {ip: timestamp for ip, timestamp in cache.items() if current_time - timestamp < CACHE_DURATION}
    logger.debug("Cleaned cache: %s", cleaned_cache)
    print("Cleaned cache:", cleaned_cache)
    return cleaned_cache

def ip_in_cache(ip, cache):
    in_cache = ip in cache
    logger.debug("IP in cache: %s", in_cache)
    print("IP in cache:", in_cache)
    return in_cache

def update_cache(ip, cache):
    cache[ip] = time.time()
    logger.debug("Updated cache: %s", cache)
    save_cache(cache)
    logger.debug("Saved the updated cache to file.")

def get_all_public_ips():
    try:
        cmd = "ip -6 -4 addr show | grep -e 'inet ' -e 'inet6 ' | awk '{print $2}' | cut -d '/' -f1"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        ips = output.strip().split('\n')
        return ips
    except subprocess.CalledProcessError:
        logger.error("Error: Unable to fetch all public IPs.")
        print("Error: Unable to fetch all public IPs.")
        log_message(args.log_file, "Error: Unable to fetch all public IPs.")
        sys.exit(1)

def rename_with_timestamp(filepath):
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    new_filepath = f"{filepath}.{timestamp}"
    os.rename(filepath, new_filepath)
    return new_filepath

public_ips = get_all_public_ips()

# Check for exclusion file that lists one IP address per line
# for skipping API submissions
exclusion_file = 'abuseipdb-exclusions.txt'
excluded_ips = set()

if os.path.exists(exclusion_file):
    excluded_ips = load_excluded_ips(exclusion_file)

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
ip_v4_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
ip_v6_pattern = re.compile(r'\b(?:(?:(?:[A-Fa-f0-9]{1,4}:){6}|::(?:[A-Fa-f0-9]{1,4}:){5}|(?:[A-Fa-f0-9]{1,4})?::(?:[A-Fa-f0-9]{1,4}:){4}|(?:(?:[A-Fa-f0-9]{1,4}:){0,1}[A-Fa-f0-9]{1,4})?::(?:[A-Fa-f0-9]{1,4}:){3}|(?:(?:[A-Fa-f0-9]{1,4}:){0,2}[A-Fa-f0-9]{1,4})?::(?:[A-Fa-f0-9]{1,4}:){2}|(?:(?:[A-Fa-f0-9]{1,4}:){0,3}[A-Fa-f0-9]{1,4})?::[A-Fa-f0-9]{1,4}:|(?:(?:[A-Fa-f0-9]{1,4}:){0,4}[A-Fa-f0-9]{1,4})?::)(?:[A-Fa-f0-9]{1,4}:[A-Fa-f0-9]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))|(?:(?:[A-Fa-f0-9]{1,4}:){0,5}[A-Fa-f0-9]{1,4})?::[A-Fa-f0-9]{1,4}|(?:(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4})?::)\b')
time_pattern = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

if LOG_MODE == 'full':
    filtered_logs = '\n'.join([log for log in logs.split('\n') if ip_v4_pattern.search(log) is not None or ip_v6_pattern.search(log) is not None])
    filtered_logs = '\n'.join([re.sub(r'^(\S+\s+\S+\s+)(\S+\s+)(\S+\s+)', r'\1\2', log) for log in filtered_logs.split('\n') if time_pattern.search(log) is not None and (ip_v4_pattern.search(log) is not None or ip_v6_pattern.search(log) is not None)])
elif LOG_MODE == 'compact':
    filtered_logs = logs.split('\n')[0]  # Extract the first line
    filtered_logs = re.sub(r'^(\S+\s+\S+\s+)(\S+\s+)(\S+\s+)', r'\1\2', filtered_logs)  # Remove the 4th field
    filtered_logs = '\n'.join([filtered_logs for log in filtered_logs.split('\n') if time_pattern.search(log) is not None and (ip_v4_pattern.search(log) is not None or ip_v6_pattern.search(log) is not None)])
else:
    print("Error: Invalid LOG_MODE. Supported modes: 'full' or 'compact'.")
    sys.exit(1)

# Create a regex pattern to match hostnames without a domain
short_hostname_pattern = r'\b(?:{}|{}|{})\b'.format(socket.gethostname(), socket.getfqdn().split('.')[0], short_hostname)
# Replace the matched hostnames in the filtered_logs variable with the masked hostname
filtered_logs = re.sub(short_hostname_pattern, mask_hostname, filtered_logs)

# Get the first part of the hostname before a single dot
first_part_hostname = socket.gethostname().split('.')[0]
# Create a regex pattern to match the first part of hostnames with a single dot
first_part_hostname_pattern = r'\b({})\b'.format(first_part_hostname)
# Replace the matched first part of the hostname in the filtered_logs variable with the masked hostname
filtered_logs = re.sub(first_part_hostname_pattern, mask_hostname, filtered_logs)

# Create a regex pattern to match the timestamp and the hostname
timestamp_and_hostname_pattern = r'((?:\b\w{{3}}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\s+))(?:{}|{}|{}|{})\b'.format(socket.gethostname(), socket.getfqdn().split('.')[0], short_hostname, first_part_hostname)
# Replace the timestamp and matched hostnames in the filtered_logs variable with the timestamp and the masked hostname
filtered_logs = re.sub(timestamp_and_hostname_pattern, r'\1{}'.format(mask_hostname), filtered_logs)

# Create a regex pattern to match any instances of MASKED_HOSTNAME
masked_hostname_pattern = r'\b({})\b'.format(mask_hostname)
# Remove any instances of MASKED_HOSTNAME in the filtered_logs variable
filtered_logs = re.sub(masked_hostname_pattern, '', filtered_logs)

# Create a regex pattern to match any content within the square brackets, preceded by the word "user"
username_pattern = r'(\buser )\[(.*?)\]'
# Replace the matched text in the filtered_logs variable with "user [USERNAME]"
filtered_logs = re.sub(username_pattern, r'\1{}'.format(USERNAME_REPLACEMENT), filtered_logs)

# Create a regex pattern to match any content within the square brackets, preceded by the word "account"
any_content_pattern = r'(\baccount )\[(.*?)\]'
# Replace the matched text in the filtered_logs variable with "account [REDACTED]"
filtered_logs = re.sub(any_content_pattern, r'\1{}'.format(ACCOUNT_REPLACEMENT), filtered_logs)

# Replace sensitive information in the filtered logs
masked_logs = filtered_logs.replace(short_hostname, mask_hostname).replace(full_hostname, mask_hostname).replace(socket.getfqdn().split('.')[0], mask_hostname)

for ip in public_ips:
    masked_logs = masked_logs.replace(ip, mask_ip)

# Create a regex pattern to match the desired text for any username
any_username_pattern = r'((?:\buser=|Failed password for (?:invalid user )?|Invalid user ))(\S+)'
# Replace the matched text in the masked_logs variable with "user [USERNAME]"
masked_logs = re.sub(any_username_pattern, r'\1{}'.format(USERNAME_REPLACEMENT), masked_logs)

# regex pattern for email address username matches
email_pattern = r'user=<([^>]+)>'
# Replace the email addresses with the specified replacement text
masked_logs = re.sub(email_pattern, r'user=<{}>'.format(EMAIL_REPLACEMENT), masked_logs)
# Print the modified log for debugging
# print('Modified log:', masked_logs)

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

# Replace the matched text in the masked_message variable with "user [USERNAME]"
masked_message = re.sub(username_pattern, r'\1{}'.format(USERNAME_REPLACEMENT), masked_message)
# Replace the matched text in the masked_message variable with "account [REDACTED]"
masked_message = re.sub(any_content_pattern, r'\1{}'.format(ACCOUNT_REPLACEMENT), masked_message)

# This pattern will match the `MAC=...` pattern in your logs
pattern = r'(MAC=)([0-9A-Fa-f]{2}[:-])+'
# Replace MAC addresses with a 'masked' string
masked_logs = re.sub(pattern, r'\1xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx', masked_logs)

if ETHERNET_MASK:
    # This pattern will match the `IN=... OUT=...` pattern in your logs
    pattern = r'(IN=)(\w+)( OUT=)'
    # Replace ethernet device names with a 'masked' string
    masked_logs = re.sub(pattern, r'\1ethX\3', masked_logs)

if LOG_MODE == 'full':
    # Truncate masked_logs to no more than 500 characters
    masked_logs = masked_logs[:500]
elif LOG_MODE == 'compact':
    # Truncate masked_logs to no more than 150 characters
    masked_logs = masked_logs[:150]
else:
    # Truncate masked_logs to no more than 150 characters
    masked_logs = masked_logs[:150]

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
categories = LF_DEFAULT_CATEGORY
if 'LF_SSHD' in trigger:
    categories = LF_SSHD_CATEGORY
elif 'LF_DISTATTACK' in trigger:
    categories = LF_DISTATTACK_CATEGORY
elif 'LF_SMTPAUTH' in trigger:
    categories = LF_SMTPAUTH_CATEGORY
elif 'LF_DISTFTP' in trigger:
    categories = LF_DISTFTP_CATEGORY
elif 'LF_FTPD' in trigger:
    categories = LF_FTPD_CATEGORY
elif 'LF_MODSEC' in trigger:
    categories = LF_MODSEC_CATEGORY
elif 'PS_LIMIT' in trigger:
    categories = PS_LIMIT_CATEGORY
elif 'LF_DISTSMTP' in trigger:
    categories = LF_DISTSMTP_CATEGORY
elif 'CT_LIMIT' in trigger:
    categories = CT_LIMIT_CATEGORY
elif 'LF_DIRECTADMIN' in trigger:
    categories = LF_DIRECTADMIN_CATEGORY
elif 'LF_CUSTOMTRIGGER' in trigger:
    categories = LF_CUSTOMTRIGGER_CATEGORY
elif 'LF_PERMBLOCK_COUNT' in trigger:
    categories = LF_PERMBLOCK_COUNT_CATEGORY
elif 'LF_HTACCESS' in trigger:
    categories = LF_HTACCESS_CATEGORY
elif 'LF_IMAPD' in trigger:
    categories = LF_IMAPD_CATEGORY
elif 'LF_POP3D' in trigger:
    categories = LF_POP3D_CATEGORY

url_encoded_ip = quote(args.arguments[0])

querystring = {
    'ip': args.arguments[0], 
    'categories': categories,
    'comment': masked_comment
}
logger.debug(f"Constructed querystring: {querystring}")

def is_log_file_valid(filepath):
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            return isinstance(data, list)  # Check if the data is a list
    except:
        return False

def contains_cluster_member_pattern(message):
    pattern = r"Cluster member (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \((.*?)\) said,"
    return re.search(pattern, message) is not None

if DEBUG:
    log_data = {
        "sentVersion": VERSION,
        "sentURL": url,
        "sentHeaders": headers,
        "sentIP": args.arguments[0],
        "sentIPencoded": url_encoded_ip,
        "sentCategories": categories,
        "sentComment": masked_comment,
        "notsentPorts": ports,
        "notsentInOut": inOut,
        "notsentMessage": message,
        "notsentLogs": logs,
        "notsentTrigger": trigger
    }

    if JSON_LOG_FORMAT:
        logger.debug(f"Attempting to write to {DEFAULT_JSONLOG_FILE} in JSON format.")
        with open(DEFAULT_JSONLOG_FILE, 'ab+') as f:  # Open the file in append + read mode in BINARY
            lock_file(f)
            logger.debug(f"File {DEFAULT_JSONLOG_FILE} locked for writing.")
            
            # Check the size of the file
            f.seek(0, os.SEEK_END)  # Move to end of file
            filesize = f.tell()  # Get current position, which is the filesize
            
            try:
                if filesize >= 2 and is_log_file_valid(DEFAULT_JSONLOG_FILE):
                    logger.debug(f"File {DEFAULT_JSONLOG_FILE} is valid. Appending log entry.")
                    f.seek(-2, os.SEEK_END)  # Move two bytes back from end to overwrite the closing bracket ']'
                    f.truncate()
                    # Ensure we are writing bytes (using .encode())
                    f.write((",\n" + json.dumps(log_data, indent=2) + "\n]").encode('utf-8'))
                else:
                    logger.warning(f"File {DEFAULT_JSONLOG_FILE} is not valid or too small. Initializing or re-initializing file.")
                    f.truncate(0)  # Clear the file contents
                    # Ensure we are writing bytes (using .encode())
                    f.write(("[\n" + json.dumps(log_data, indent=2) + "\n]").encode('utf-8'))
            except Exception as e:
                logger.error(f"Error while writing to the log file {DEFAULT_JSONLOG_FILE}: {str(e)}")
                with open('/var/log/abuseipdb-invalid-log.log', 'a') as error_f:
                    error_f.write(f'{datetime.datetime.now()}: Error while writing to the log file {DEFAULT_JSONLOG_FILE}: {str(e)}\n')
            finally:
                unlock_file(f)  # Always ensure to release the lock
                logger.debug(f"File {DEFAULT_JSONLOG_FILE} unlocked after writing.")

        logger.debug(f"Not Sent Ports: {ports}")
        logger.debug(f"Not Sent In/Out: {inOut}")
        logger.debug(f"Not Sent Message: {masked_message}")
        logger.debug(f"Not Sent Logs: {masked_logs}")
        logger.debug(f"Not Sent Trigger: {trigger}")
        logger.debug(f"DEBUG MODE: No actual report sent. JSON data saved to '{DEFAULT_JSONLOG_FILE}'.")
        print("Not Sent Ports:", ports)
        print("Not Sent In/Out:", inOut)
        print("Not Sent Message:", masked_message)
        print("Not Sent Logs:", masked_logs)
        print("Not Sent Trigger:", trigger, '\n')
        print("DEBUG MODE: No actual report sent. JSON data saved to '{}'.".format(DEFAULT_JSONLOG_FILE))
    else:
        logger.debug(f"Attempting to write to {args.log_file} file.")
        with open(args.log_file, 'a') as f:
            f.write("############################################################################\n")
            f.write("Version: {}\n".format(VERSION))
            f.write("DEBUG MODE: data intended to be sent to AbuseIPDB\n")
            f.write("URL: {}\n".format(url))
            f.write("Headers: {}\n".format(headers))
            f.write("IP: {}\n".format(args.arguments[0]))
            f.write("IPencoded: {}\n".format(url_encoded_ip))
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
        logger.debug(f"Not Sent Ports: {ports}")
        logger.debug(f"Not Sent In/Out: {inOut}")
        logger.debug(f"Not Sent Message: {masked_message}")
        logger.debug(f"Not Sent Logs: {masked_logs}")
        logger.debug(f"Not Sent Trigger: {trigger}")
        logger.debug(f"DEBUG MODE: No actual report sent. Data saved to '{args.log_file}'.")
        print("Not Sent Ports:", ports)
        print("Not Sent In/Out:", inOut)
        print("Not Sent Message:", masked_message)
        print("Not Sent Logs:", masked_logs)
        print("Not Sent Trigger:", trigger, '\n')
        print("DEBUG MODE: No actual report sent. Data saved to '{}'.".format(args.log_file))
else:
    current_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.debug(f"Sending Ports: {ports}")
    logger.debug(f"Sending In/Out: {inOut}")
    logger.debug(f"Sending Message: {masked_message}")
    logger.debug(f"Sending Logs: {masked_logs}")
    logger.debug(f"Sending Trigger: {trigger}")
    print("Sending Ports:", ports)
    print("Sending In/Out:", inOut)
    print("Sending Message:", masked_message)
    print("Sending Logs:", masked_logs)
    print("Sending Trigger:", trigger, '\n')

    try:
        # Load and clean the cache
        cache = load_cache()
        if not cache:
            save_cache(cache)
        logger.debug("Loaded cache: %s", cache)
        print("Loaded cache:", cache)
        cache = clean_cache(cache)
        logger.debug("Current cache: %s", cache)
        print("Current cache:", cache)
    except Exception as e:
        logger.error(f"Error while loading or cleaning the cache: {str(e)}")

    if not (IGNORE_CLUSTER_SUBMISSIONS and contains_cluster_member_pattern(message)):
        # Define IP
        ip = args.arguments[0]
        logger.debug(f"Processing IP: {ip}")
    
        # If IP is in exclusions, do not report
        if ip in excluded_ips:
            print("IP: {} is in exclusions. Skipping report.".format(ip))
            logger.info(f"IP: {ip} is in exclusions. Skipping report.")
            sys.exit()
        # Check if the IP address is in the cache before sending the report
        if not ip_in_cache(args.arguments[0], cache):
            logger.debug(f"IP {ip} not found in cache. Preparing to send report.")
            response = requests.post(url, headers=headers, params=querystring)
            decodedResponse = json.loads(response.text)
            logger.info(f"Reported IP {ip} with categories {categories} and comment: {comment}")
            logger.debug(f"API response: {decodedResponse}")

            if LOG_API_REQUEST:
                log_data = {
                    "sentVersion": VERSION,
                    "sentURL": url,
                    "sentHeaders": headers,
                    "sentIP": args.arguments[0],
                    "sentIPencoded": url_encoded_ip,
                    "sentCategories": categories,
                    "sentComment": masked_comment,
                    "notsentTrigger": trigger,
                    "apiResponse": decodedResponse,
                    "notsentTimestamp": current_timestamp
                }

                if JSON_APILOG_FORMAT:
                    logger.debug(f"Attempting to write to {DEFAULT_JSONAPILOG_FILE} in JSON format.")
                    with open(DEFAULT_JSONAPILOG_FILE, 'ab+') as f:  # Open the file in append + read mode in BINARY
                        lock_file(f)
                        logger.debug(f"File {DEFAULT_JSONAPILOG_FILE} locked for writing.")
                        
                        # Check the size of the file
                        f.seek(0, os.SEEK_END)  # Move to end of file
                        filesize = f.tell()  # Get current position, which is the filesize
                        
                        try:
                            if filesize >= 2 and is_log_file_valid(DEFAULT_JSONAPILOG_FILE):
                                logger.debug(f"File {DEFAULT_JSONAPILOG_FILE} is valid. Appending log entry.")
                                f.seek(-2, os.SEEK_END)  # Move two bytes back from end to overwrite the closing bracket ']'
                                f.truncate()
                                # Ensure we are writing bytes (using .encode())
                                f.write((",\n" + json.dumps(log_data, indent=2) + "\n]").encode('utf-8'))
                            else:
                                logger.warning(f"File {DEFAULT_JSONAPILOG_FILE} is not valid or too small. Initializing or re-initializing file.")
                                f.truncate(0)  # Clear the file contents
                                # Ensure we are writing bytes (using .encode())
                                f.write(("[\n" + json.dumps(log_data, indent=2) + "\n]").encode('utf-8'))
                        except Exception as e:
                            logger.error(f"Error while writing to the log file {DEFAULT_JSONAPILOG_FILE}: {str(e)}")
                            with open('/var/log/abuseipdb-invalid-log.log', 'a') as error_f:
                                error_f.write(f'{datetime.datetime.now()}: Error while writing to the log file {DEFAULT_JSONAPILOG_FILE}: {str(e)}\n')
                        finally:
                            unlock_file(f)  # Always ensure to release the lock
                            logger.debug(f"File {DEFAULT_JSONAPILOG_FILE} unlocked after writing.")
                else:
                    ip = args.arguments[0]
                    logger.debug(f"Processing IP: {ip}")
                    logger.debug(f"Attempting to write to {DEFAULT_APILOG_FILE} file.")
                    with open(DEFAULT_APILOG_FILE, 'a') as f:
                        f.write("############################################################################\n")
                        f.write("Version: {}\n".format(VERSION))
                        f.write("API Request Sent:\n")
                        f.write("URL: {}\n".format(url))
                        f.write("Headers: {}\n".format(headers))
                        f.write("IP: {}\n".format(ip))
                        f.write("IPencoded: {}\n".format(url_encoded_ip))
                        f.write("Categories: {}\n".format(categories))
                        f.write("Comment: {}\n".format(masked_comment))
                        f.write("API Response: {}\n".format(json.dumps(decodedResponse, indent=2)))
                        f.write("Timestamp: {}\n".format(current_timestamp))
                        f.write("############################################################################\n")
                        f.write("--------\n")

            if response.status_code == 200:
                print(json.dumps(decodedResponse['data'], sort_keys=True, indent=4))
                logger.debug(f"API Response Data: {json.dumps(decodedResponse['data'], sort_keys=True, indent=4)}")
                # Update the cache with the new IP address and timestamp, then save it
                update_cache(args.arguments[0], cache)
                save_cache(cache)

            if response.status_code == 200:
                print(json.dumps(decodedResponse['data'], sort_keys=True, indent=4))
            elif response.status_code == 429:
                logger.error(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
                print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
            elif response.status_code == 422:
                logger.error(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
                print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
            elif response.status_code == 302:
                logger.warning('Unsecure protocol requested. Redirected to HTTPS.')
                print('Unsecure protocol requested. Redirected to HTTPS.')
            elif response.status_code == 401:
                logger.error(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
                print(json.dumps(decodedResponse['errors'][0], sort_keys=True, indent=4))
            else:
                logger.error('Unexpected server response. Status Code: {}'.format(response.status_code))
                print('Unexpected server response. Status Code: {}'.format(response.status_code))
        else:
            logger.warning("IP address already reported within the last 15 minutes. Skipping submission.")
            print("IP address already reported within the last 15 minutes. Skipping submission.")
logger.info("Script completed.")