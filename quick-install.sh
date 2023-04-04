#!/bin/bash
######################################################################
# This script is a Bash script that sets up an AbuseIPDB reporter 
# for CSF Firewall. It checks for the installation and configuration
# of CSF Firewall, Python 3 and requests module. If these are not 
# installed or configured properly, the script installs them.
#
# The script then adds an AbuseIPDB blocklist line to 
# /etc/csf/csf.blocklist and sets BLOCK_REPORT in /etc/csf/csf.conf.
# It also creates an abuseipdb-reporter.ini file and sets up some 
# configurations for the reporter. Additionally, it provides an option 
# to uninstall the AbuseIPDB reporter.
#
# The script takes an API key as a command-line argument
######################################################################
DIR='/home'
DIRNAME='centminmod-abuseipdb-reporter'
INI_FILE="${DIR}/${DIRNAME}/abuseipdb-reporter.ini"
DEBUG='y'

error_exit() { echo >&2 "$@"; exit 1; }

debug_log() { [ "${DEBUG}" = 'y' ] && echo "DEBUG: $@"; }

[ "$(id -u)" -ne 0 ] && error_exit "This script must be run as root."
command -v csf >/dev/null || error_exit "CSF Firewall not installed. Install and configure CSF Firewall first."
[ -f "/etc/csf/csf.blocklist" ] || error_exit "CSF Firewall not configured properly. /etc/csf/csf.blocklist file missing."
systemctl is-active --quiet csf || error_exit "CSF Firewall not running. Start and enable CSF service."
systemctl is-active --quiet lfd || error_exit "lfd not running. Start and enable lfd service."

debug_log "Checking Python 3 and requests module installation"
if ! (command -v python3 >/dev/null && python3 -c "import requests" >/dev/null 2>&1); then
    yum -y install python3 || error_exit "Failed to install Python 3."
    python3 -m ensurepip || error_exit "Failed to install pip."
    python3 -m pip install requests || error_exit "Failed to install requests module."
fi
debug_log "Python 3 and requests module installation checked"

abuse_blocklist_line="ABUSEIPDB|86400|10000|https://api.abuseipdb.com/api/v2/blacklist?key=YOUR_API_KEY&plaintext"
grep -q "${abuse_blocklist_line}" /etc/csf/csf.blocklist || echo -e "\n${abuse_blocklist_line}" >> /etc/csf/csf.blocklist || error_exit "Failed to add AbuseIPDB blocklist line to /etc/csf/csf.blocklist."

# Parse arguments
while getopts "a:u" opt; do
    case ${opt} in
        a)
            api_key="$OPTARG"
            ;;
        u)
            uninstall=1
            ;;
        \?)
            error_exit "Usage: $0 [-a API_KEY] [-u]"
            ;;
    esac
done

debug_log "Processing command-line arguments"
if [ -n "${uninstall}" ]; then
    debug_log "Uninstalling"
    sed -i "/${abuse_blocklist_line//\//\\/}/d" /etc/csf/csf.blocklist || error_exit "Failed to remove AbuseIPDB blocklist line from /etc/csf/csf.blocklist."
    sed -i "s|^BLOCK_REPORT = \"/home/${DIRNAME}/abuseipdb-reporter.py\"$|BLOCK_REPORT = \"\"|" /etc/csf/csf.conf || error_exit "Failed to revert BLOCK_REPORT in /etc/csf/csf.conf."
    rm -rf "${DIR}/${DIRNAME}" || error_exit "Failed to remove ${DIR}/${DIRNAME} directory."
    echo "AbuseIPDB reporter uninstalled successfully."
    exit 0
fi

[ -z "${api_key}" ] && error_exit "API key not provided. Usage: $0 -a API_KEY"
sed -i "s|YOUR_API_KEY|${api_key}|" /etc/csf/csf.blocklist || error_exit "Failed to replace API key in /etc/csf/csf.blocklist."

debug_log "Cloning repository"
[ ! -d "/home/${DIRNAME}" ] && git clone "https://github.com/centminmod/${DIRNAME}" || error_exit "Failed to clone ${DIRNAME} repository."
cd "/home/${DIRNAME}"

debug_log "Creating abuseipdb-reporter.ini"
cat > "${INI_FILE}" <<EOF || error_exit "Failed to create abuseipdb-reporter.ini."
[settings]
DEBUG = True
LOG_API_REQUEST = True
LOG_MODE = compact
JSON_LOG_FORMAT = True
JSON_APILOG_FORMAT = True
IGNORE_CLUSTER_SUBMISSIONS = True
API_KEY = ${api_key}
EOF

debug_log "Setting BLOCK_REPORT in /etc/csf/csf.conf"
sed -i "s/^BLOCK_REPORT = \"\"$/BLOCK_REPORT = \"/home/${DIRNAME}/abuseipdb-reporter.py\"/" /etc/csf/csf.conf || error_exit "Failed to set BLOCK_REPORT in /etc/csf/csf.conf."

echo "AbuseIPDB reporter setup completed with DEBUG=True, LOG_MODE=compact, JSON_LOG_FORMAT=True, JSON_APILOG_FORMAT=True, and IGNORE_CLUSTER_SUBMISSIONS=True."

