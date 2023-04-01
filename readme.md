# CSF Firewall + AbuseIPDB Integration

Tailored for Centmin Mod LEMP stack based servers that install CSF Firewall by default with a specific focus on data privacy and prevention of sensitive data leaked to public AbuseIPDB database reports. Though technically should work with any servers that use CSF Firewall.

Based on CSF Firewall and AbuseIPDB integration guide at https://www.abuseipdb.com/csf. However, that guides provided Perl, Shell and Python scripts will all leak some private sensitive data about your servers in their default state for some situations i.e. if you enable [CSF Cluster mode](#csf-cluster-mode), your CSF Cluster members' real IP addresses are leaked. The `abuseipdb-reporter.py` python script I created and outlined below will privacy mask all sensitive info like usernames, Linux users, CSF Cluster mode members' real IP addresses and also detect and mask any registered server public IP addresses.

This guide will show you how to set up CSF Firewall so that attempted intrusions against your system are automatically blocked by CSF's Login Failure Daemon (lfd) logged actions. It is also possible to use CSF Firewall to pre-emptively block bad IP addresses using [CSF Firewall's blocklist feature and AbuseIPDB's collated blocklist database](#setup).

* [Dependencies](#dependencies)
* [Setup](#setup)
* [Configuration](#configuration)
  * [abuseipdb-reporter.ini](#abuseipdb-reporterini)
  * [Log Inspection](#log-inspection)
  * [Example](#example)
  * [JSON log format](#json-log-format)
    * [Parsing JSON formatted logs](#parsing-json-formatted-logs)
      * [Convert JSON Format Back To Non-JSON Format](#convert-json-format-back-to-non-json-format)
* [CSF Cluster Mode](#csf-cluster-mode)
  * [JSON log format CSF Cluster](#json-log-format-csf-cluster)
* [Additional Tools](#additional-tools)

## Dependencies

Python 3.x required as well as `requests` module:


Centmin Mod users on CentOS 7.x, can install Python 3.x via `addons/python36_install.sh`

```
/usr/local/src/centminmod/addons/python36_install.sh
pip3 install requests
```

Or if on EL8+, can install Python 3 via

```
yum -y install python3
pip3 install requests
```

## Setup

1. Create an AbuseIPDB API key

Register an account with AbuseIPDB, and [create an API key](https://www.abuseipdb.com/account/api). The API is free to use, but you do have to [create an account](https://www.abuseipdb.com/register).

2. Integrating AbuseIPDB Blocklist Into CSF Firewall

AbuseIPDB API has daily API usage limits for free and paid plans outlined at https://www.abuseipdb.com/pricing. For webmaster verified free plan the daily API usage limits are outlined in below table. The `blacklist` quota is what the blocklists will consume. While the below steps to report bad IP addresses will consume the `reports` quota of 3,000/day on webmaster verified free plan.

| Endpoint      | Usage / Daily Limit | Utilization Rate |
|---------------|---------------------|------------------|
| check         | 0 / 3,000           | 0%               |
| reports       | 0 / 500             | 0%               |
| blacklist     | 0 / 10              | 0%              |
| report        | 0 / 3,000           | 0%               |
| check-block   | 0 / 1,000           | 0%               |
| bulk-report   | 0 / 10              | 0%               |
| clear-address | 0 / 10              | 0%               |

To use the CSF Firewall blocklist feature with AbuseIPDB database blocklist, do the following:

Edit `/etc/csf/csf.blocklists` and add blocklist for AbuseIPD and change `YOUR_API_KEY` to your API Key from step 1.

```
# AbuseIPDB blacklist
# Details: https://docs.abuseipdb.com/#blacklist-endpoint
ABUSEIPDB|86400|10000|https://api.abuseipdb.com/api/v2/blacklist?key=YOUR_API_KEY&plaintext
```

The `/var/log/lfd.log`, will now show the AbuseIPDB blocklists loaded

```
Mar 27 08:28:28 host lfd[572547]: Retrieved and blocking blocklist ABUSEIPDB IP address ranges
Mar 27 08:28:28 host lfd[572547]: IPSET: loading set new_ABUSEIPDB with 4087 entries
Mar 27 08:28:28 host lfd[572547]: IPSET: switching set new_ABUSEIPDB to bl_ABUSEIPDB
Mar 27 08:28:28 host lfd[572547]: IPSET: loading set new_6_ABUSEIPDB with 3 entries
Mar 27 08:28:28 host lfd[572547]: IPSET: switching set new_6_ABUSEIPDB to bl_6_ABUSEIPDB
Mar 27 08:33:28 host lfd[572611]: Retrieved and blocking blocklist BDE IP address ranges
Mar 27 08:33:28 host lfd[572611]: IPSET: loading set new_BDE with 269 entries
Mar 27 08:33:28 host lfd[572611]: IPSET: switching set new_BDE to bl_BDE
Mar 27 08:33:28 host lfd[572611]: IPSET: loading set new_6_BDE with 1 entries
Mar 27 08:33:28 host lfd[572611]: IPSET: switching set new_6_BDE to bl_6_BDE
```

3. Reporting to AbuseIPDB

Setup the `abuseipdb-reporter.py` python script on your Centmin Mod LEMP stack server. You can save it to any location you want. For this example, saved to `/root/tools/abuseipdb-reporter.py`.

Ensure `/root/tools/abuseipdb-reporter.py` is executable using `chmod`:

```
chmod +x /root/tools/abuseipdb-reporter.py
```

Or clone this repo:

```
cd /home
git clone https://github.com/centminmod/centminmod-abuseipdb-reporter
cd /home/centminmod-abuseipdb-reporter
```

## Configuration

Edit the `/root/tools/abuseipdb-reporter.py` or `/home/centminmod-abuseipdb-reporter/abuseipdb-reporter.py` script's variables:

* `DEBUG = True` - When set to `True`, debug mode is enabled and no actual CSF Firewall block actions will be sent to AbuseIPDB via API endpoint url. Instead block actions will be saved to a local log file `/var/log/abuseipdb-reporter-debug.log`. You can use this mode for troubleshooting or testing before you eventually set `DEBUG = False` to enable actual CSF Firewall block actions to be sent to AbuseIPDB via API endpoint url.
* `API_KEY = 'YOUR_API_KEY'` - Set `YOUR_API_KEY` to your AbuseIPDB API key
* `JSON_LOG_FORMAT = False` - Set to `False` by default to save `DEBUG = True` debug log to specified `DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'`. When set to `True` will save in JSON format to specified `DEFAULT_JSONLOG_FILE = '/var/log/abuseipdb-reporter-debug-json.log'` log file instead. The JSON log format makes parsing and filtering the debug log easier [JSON format demo](#json-log-format) and [CSF Cluster JSON format demo](#json-log-format-csf-cluster).
* `USERNAME_REPLACEMENT = '[USERNAME]'` - for privacy masking, Linux usernames are masked before being sent to AbuseIPDB, this is the replacement word value.
* `ACCOUNT_REPLACEMENT = '[REDACTED]'` - for privacy masking, Linux account usernames are masked before being sent to AbuseIPDB, this is the replacement word value.

Example of `USERNAME_REPLACEMENT = '[USERNAME]'` privacy masking the Comments details

```
Comment: (sshd) Failed SSH login from 5.189.165.229 (DE/Germany/vmi927439.contaboserver.net): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 31 00:41:53 sshd[13465]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=5.189.165.229  user=[USERNAME]
Mar 31 00:41:55 sshd[13465]: Failed password for [USERNAME] from 5.189.165.229 port 51296 ssh2
Mar 31 00:45:27 sshd[15102]: Invalid user [USERNAME] from 5.189.165.229 port 35276
Mar 31 00:45:29 sshd[15102]: Failed password for invalid user [USERNAME] from 5.189.165.229 port 35276 ssh2
Mar 31 00:46:35 sshd[15383]: Invalid user [USERNAME] from 5.189.165.229 port 59862
```

## abuseipdb-reporter.ini

The script now supports `abuseipdb-reporter.ini` file you can create within same directory as `abuseipdb-reporter.py` script to override the following settings without editing the `abuseipdb-reporter.py` script itself:

```
[settings]
DEBUG = True
LOG_API_REQUEST = True
LOG_MODE = full
JSON_LOG_FORMAT = False
JSON_APILOG_FORMAT = False
API_KEY = YOUR_API_KEY
DEFAULT_LOG_FILE = /var/log/abuseipdb-reporter-debug.log
DEFAULT_JSONLOG_FILE = /var/log/abuseipdb-reporter-debug-json.log
DEFAULT_APILOG_FILE = /var/log/abuseipdb-reporter-api.log
DEFAULT_JSONAPILOG_FILE = '/var/log/abuseipdb-reporter-api-json.log'
mask_hostname = MASKED_HOSTNAME
mask_ip = 0.0.0.x
USERNAME_REPLACEMENT = '[USERNAME]'
ACCOUNT_REPLACEMENT = '[REDACTED]'
```

### Log Inspection

When you set `DEBUG = True`, look at logs:

when `JSON_LOG_FORMAT = False` set
```
DEFAULT_LOG_FILE = '/var/log/abuseipdb-reporter-debug.log'
```
when `JSON_LOG_FORMAT = True` set
```
DEFAULT_JSONLOG_FILE = '/var/log/abuseipdb-reporter-debug-json.log'
```

When you set `DEBUG = False` look at logs:

when `JSON_LOG_FORMAT = False` set
```
DEFAULT_APILOG_FILE = '/var/log/abuseipdb-reporter-api.log'
```
when `JSON_LOG_FORMAT = True` set
```
DEFAULT_JSONAPILOG_FILE = '/var/log/abuseipdb-reporter-api-json.log'
```

## Example

CSF Firewall when it's `lfd` process detects and logs a block action from bad IPs usually just blocks the request and adds an entry into `/var/log/lfd.log` log. However, you can configure CSF Firewall to also pass that `lfd` block action data i.e. IP address etc and send it to a defined custom script (`abuseipdb-reporter.py`) setup assigned to variable `BLOCK_REPORT` in your CSF config file `/etc/csf/csf.conf`.

CSF Firewall passes data to `BLOCK_REPORT` defined script for the following arguments:

```
ARG 1 = IP Address  # The IP address or CIDR being blocked
ARG 2 = ports   # Port, comma separated list or * for all ports
ARG 3 = permanent # 0=temporary block, 1=permanent block
ARG 4 = inout   # Direction of block: in, out or inout
ARG 5 = timeout   # If a temporary block, TTL in seconds, otherwise 0
ARG 6 = message   # Message containing reason for block
ARG 7 = logs    # The logs lines that triggered the block (will contain
                        # line feeds between each log line)
ARG 8 = trigger   # The configuration settings triggered
```

Example of `DEBUG = True` debug mode with `JSON_LOG_FORMAT = False` saved log file entries at `/var/log/abuseipdb-reporter-debug.log` 

Data logging of processed data that AbuseIPDB will receive (`DEBUG MODE: data intended to be sent to AbuseIPDB`) + also a raw copy of data passed from CSF (`DEBUG MODE: CSF passed data not sent to AbuseIPDB`) so can compare the two:

```
cat /var/log/abuseipdb-reporter-debug.log

############################################################################
Version: 0.2.0
DEBUG MODE: data intended to be sent to AbuseIPDB
URL: https://api.abuseipdb.com/api/v2/report
Headers: {"Accept":"application/json","Key":"YOUR_API_KEY"}
IP: 147.182.171.152
IPencoded: 147.182.171.152
Categories: 22
Comment: (sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 31 22:48:39 sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
Mar 31 22:48:41 sshd[655144]: Failed password for [USERNAME] from 147.182.171.152 port 34306 ssh2
Mar 31 22:51:24 sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
Mar 31 22:51:26 sshd[655193]: Failed password for [USERNAME] from 147.182.171.152 port 45160 ssh2
Mar 31 22:52:30 sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
---------------------------------------------------------------------------
DEBUG MODE: CSF passed data not sent to AbuseIPDB
Ports: *
In/Out: inout
Message: (sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs
Logs: Mar 31 22:48:39 hostname sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root
Mar 31 22:48:41 hostname sshd[655144]: Failed password for root from 147.182.171.152 port 34306 ssh2
Mar 31 22:51:24 hostname sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root
Mar 31 22:51:26 hostname sshd[655193]: Failed password for root from 147.182.171.152 port 45160 ssh2
Mar 31 22:52:30 hostname sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root

Trigger: LF_SSHD
############################################################################
--------
```

So CSF passed raw data for `hostname` and `147.182.171.152` but script will remove the `lfd.log` 4th field for `hostname` when sending to AbuseIPDB.

# JSON log format

Example of `DEBUG = True` debug mode with `JSON_LOG_FORMAT = True` saved log file entries at `/var/log/abuseipdb-reporter-debug-json.log` 

```json
[
  {
    "sentVersion": "0.2.0",
    "sentURL": "https://api.abuseipdb.com/api/v2/report",
    "sentHeaders": {
      "Accept": "application/json",
      "Key": "YOUR_API_KEY"
    },
    "sentIP": "147.182.171.152",
    "sentIPencoded": "147.182.171.152",
    "sentCategories": "22",
  "sentComment": "(sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 31 22:48:39 sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]\nMar 31 22:48:41 sshd[655144]: Failed password for [USERNAME] from 147.182.171.152 port 34306 ssh2\nMar 31 22:51:24 sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]\nMar 31 22:51:26 sshd[655193]: Failed password for [USERNAME] from 147.182.171.152 port 45160 ssh2\nMar 31 22:52:30 sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser=   rhost=147.182.171.152  user=[USERNAME]",
    "notsentPorts": "*",
    "notsentInOut": "inout",
    "notsentMessage": "(sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs",
  "notsentLogs": "Mar 31 22:48:39 hostname sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\nMar 31 22:48:41 hostname sshd[655144]: Failed password for root from 147.182.171.152 port 34306 ssh2\nMar 31 22:51:24 hostname sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\nMar 31 22:51:26 hostname sshd[655193]: Failed password for root from 147.182.171.152 port 45160 ssh2\nMar 31 22:52:30 hostname sshd[655208]: pam_unix( sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\n",
    "notsentTrigger": "LF_SSHD"
  }
]
```

For JSON format, the key names prefixed with `sent` are data that is sent to AbuseIPDB. While key names prefixed with `notsent` is data CSF passed onto the script. So CSF passed raw data for `hostname` and `147.182.171.152` but script will remove the `lfd.log` 4th field for `hostname` when sending to AbuseIPDB.

## Parsing JSON formatted logs

You can also use `jq` to parse and filter the JSON formatted logs.

Get `sentIP` for each entry

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq -r '.[] | .sentIP'
147.182.171.152
```

Only get `sentIP` and `sentCategories` for each entry

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '[.[] | {sentIP, sentCategories}]'
[
  {
    "sentIP": "147.182.171.152",
    "sentCategories": "22"
  }
]
```

Only get entries where `notsentTrigger` = `LF_SSHD`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.notsentTrigger == "LF_SSHD")'
```

Only get entries where `notsentTrigger` != `LF_SSHD`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.notsentTrigger != "LF_SSHD")'
```

Only get entries where `notsentTrigger` != `LF_CLUSTER`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.notsentTrigger != "LF_CLUSTER")'
```

Only get entries where `notsentTrigger` = `LF_SSHD` and `sentIP` = `147.182.171.152`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.notsentTrigger == "LF_SSHD" and .sentIP == "147.182.171.152")'
```

Only get entries where `sentCategories` = `22`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.sentCategories == "22")'
```

### Convert JSON Format Back To Non-JSON Format

You can even use `jq` to convert the JSON formatted entries back to the non-JSON format. If the JSON formatted entry for last entry in log is:

```
cat /var/log/abuseipdb-reporter-debug-json.log | jq -c '.[]'| tail -1 | jq -r
```
```json
{
  "sentVersion": "0.2.0",
  "sentURL": "https://api.abuseipdb.com/api/v2/report",
  "sentHeaders": {
    "Accept": "application/json",
    "Key": "YOUR_API_KEY"
  },
  "sentIP": "147.182.171.152",
  "sentIPencoded": "147.182.171.152",
  "sentCategories": "22",
  "sentComment": "(sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 31 22:48:39 sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]\nMar 31 22:48:41 sshd[655144]: Failed password for [USERNAME] from 147.182.171.152 port 34306 ssh2\nMar 31 22:51:24 sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]\nMar 31 22:51:26 sshd[655193]: Failed password for [USERNAME] from 147.182.171.152 port 45160 ssh2\nMar 31 22:52:30 sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]",
  "notsentPorts": "*",
  "notsentInOut": "inout",
  "notsentMessage": "(sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs",
  "notsentLogs": "Mar 31 22:48:39 hostname sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\nMar 31 22:48:41 hostname sshd[655144]: Failed password for root from 147.182.171.152 port 34306 ssh2\nMar 31 22:51:24 hostname sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\nMar 31 22:51:26 hostname sshd[655193]: Failed password for root from 147.182.171.152 port 45160 ssh2\nMar 31 22:52:30 hostname sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root\n",
  "notsentTrigger": "LF_SSHD"
}
```

You can use command against last entry in log:

```
cat /var/log/abuseipdb-reporter-debug-json.log | jq -c '.[]'| tail -1 | jq -r '"############################################################################\nVersion: " + .sentVersion + "\nDEBUG MODE: data intended to be sent to AbuseIPDB\nURL: " + .sentURL + "\nHeaders: " + (.sentHeaders | tostring) + "\nIP: " + .sentIP + "\nIPencoded: " + .sentIPencoded + "\nCategories: " + (.sentCategories | tostring) + "\nComment: " + .sentComment + "\n---------------------------------------------------------------------------\nDEBUG MODE: CSF passed data not sent to AbuseIPDB\nPorts: " + .notsentPorts + "\nIn/Out: " + .notsentInOut + "\nMessage: " + .notsentMessage + "\nLogs: " + .notsentLogs + "\nTrigger: " + .notsentTrigger + "\n############################################################################\n--------"'
```

Returns converted output:

```
############################################################################
Version: 0.2.0
DEBUG MODE: data intended to be sent to AbuseIPDB
URL: https://api.abuseipdb.com/api/v2/report
Headers: {"Accept":"application/json","Key":"YOUR_API_KEY"}
IP: 147.182.171.152
IPencoded: 147.182.171.152
Categories: 22
Comment: (sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 31 22:48:39 sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
Mar 31 22:48:41 sshd[655144]: Failed password for [USERNAME] from 147.182.171.152 port 34306 ssh2
Mar 31 22:51:24 sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
Mar 31 22:51:26 sshd[655193]: Failed password for [USERNAME] from 147.182.171.152 port 45160 ssh2
Mar 31 22:52:30 sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=[USERNAME]
---------------------------------------------------------------------------
DEBUG MODE: CSF passed data not sent to AbuseIPDB
Ports: *
In/Out: inout
Message: (sshd) Failed SSH login from 147.182.171.152 (US/United States/-): 5 in the last 3600 secs
Logs: Mar 31 22:48:39 hostname sshd[655144]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root
Mar 31 22:48:41 hostname sshd[655144]: Failed password for root from 147.182.171.152 port 34306 ssh2
Mar 31 22:51:24 hostname sshd[655193]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root
Mar 31 22:51:26 hostname sshd[655193]: Failed password for root from 147.182.171.152 port 45160 ssh2
Mar 31 22:52:30 hostname sshd[655208]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=147.182.171.152  user=root

Trigger: LF_SSHD
############################################################################
--------
```

For converting all JSON log entries to Non-JSON format, remove the `tail -1` filter for the command:

```
cat /var/log/abuseipdb-reporter-debug-json.log | jq -c '.[]' | jq -r '"############################################################################\nVersion: " + .sentVersion + "\nDEBUG MODE: data intended to be sent to AbuseIPDB\nURL: " + .sentURL + "\nHeaders: " + (.sentHeaders | tostring) + "\nIP: " + .sentIP + "\nIPencoded: " + .sentIPencoded + "\nCategories: " + (.sentCategories | tostring) + "\nComment: " + .sentComment + "\n---------------------------------------------------------------------------\nDEBUG MODE: CSF passed data not sent to AbuseIPDB\nPorts: " + .notsentPorts + "\nIn/Out: " + .notsentInOut + "\nMessage: " + .notsentMessage + "\nLogs: " + .notsentLogs + "\nTrigger: " + .notsentTrigger + "\n############################################################################\n--------"'
```

## CSF Cluster Mode

For folks using CSF Cluster Mode, the `abuseipdb-reporter.py` script will also privacy mask your Cluster members IP addresses. Example in `DEBUG = True` mode logging:

```
cat /var/log/abuseipdb-reporter-debug.log

############################################################################
Version: 0.1.0
DEBUG MODE: data intended to be sent to AbuseIPDB
URL: https://api.abuseipdb.com/api/v2/report
Headers: {'Accept': 'application/json', 'Key': 'YOUR_API_KEY'}
IP: 49.212.187.208
Categories: 14
Comment:  DENY 49.212.187.208, Reason:[(sshd) Failed SSH login from 49.212.187.208 (JP/Japan/os3-301-40454.vs.sakura.ne.jp): 5 in the last 3600 secs]; Ports: *; Direction: inout; Trigger: LF_CLUSTER; Logs: 
---------------------------------------------------------------------------
DEBUG MODE: CSF passed data not sent to AbuseIPDB
Ports: *
In/Out: inout
Message: Cluster member 45.xxx.xxx.xxx (US/United States/-) said, DENY 49.212.187.208, Reason:[(sshd) Failed SSH login from 49.212.187.208 (JP/Japan/os3-301-40454.vs.sakura.ne.jp): 5 in the last 3600 secs]
Logs:  
Trigger: LF_CLUSTER
############################################################################
--------
```

The CSF passed data also reveals your Cluster member's real IP address `45.xxx.xxx.xxx`. The `abuseipdb-reporter.py` script will remove that and the full line `Cluster member 45.xxx.xxx.xxx (US/United States/-) said,` from the data intended to be sent to AbuseIPDB so it doesn't reveal your CSF Cluster member IP addresses.

# JSON log format CSF Cluster

Example of `DEBUG = True` debug mode with `JSON_LOG_FORMAT = True` saved log file entries at `/var/log/abuseipdb-reporter-debug-json.log` 

```json
[
  {
    "sentVersion": "0.1.3",
    "sentURL": "https://api.abuseipdb.com/api/v2/report",
    "sentHeaders": {
      "Accept": "application/json",
      "Key": "YOUR_API_KEY"
    },
    "sentIP": "162.241.124.124",
    "sentCategories": "14",
    "sentComment": " DENY 162.241.124.124, Reason:[(sshd) Failed SSH login from 162.241.124.124 (US/United States/162-241-124-124.webhostbox.net): 5 in the last 3600 secs]; Ports: *; Direction: inout; Trigger: LF_CLUSTER; Logs: ",
    "notsentPorts": "*",
    "notsentInOut": "inout",
    "notsentMessage": "Cluster member 45.xxx.xxx.xxx (US/United States/-) said, DENY 162.241.124.124, Reason:[(sshd) Failed SSH login from 162.241.124.124 (US/United States/162-241-124-124.webhostbox.net): 5 in the last 3600 secs]",
    "notsentLogs": " ",
    "notsentTrigger": "LF_CLUSTER"
  }
]
```

For JSON format, the key names prefixed with `sent` are data that is sent to AbuseIPDB. While key names prefixed with `notsent` is data CSF passed onto the script. The CSF passed data also reveals your Cluster member's real IP address `45.xxx.xxx.xxx`. The `abuseipdb-reporter.py` script will remove that and the full line `Cluster member 45.xxx.xxx.xxx (US/United States/-) said,` from the data intended to be sent to AbuseIPDB so it doesn't reveal your CSF Cluster member IP addresses.

4. Set the `BLOCK_REPORT` variable in `/etc/csf.conf` to the executable script file.

```
BLOCK_REPORT = "/root/tools/abuseipdb-reporter.py"
```

or

```
BLOCK_REPORT = "/home/centminmod-abuseipdb-reporter/abuseipdb-reporter.py"
```

restart CSF and lfd using:

```
csf -ra
```
# Additional Tools

`lfd-rate.py` can parse the CSF Firewall `/var/log/lfd.log` log and calculate the rate of LFD actions in terms of log entries for per second, minute, hour and daily metrics.

```
./lfd-rate.py

LFD actions per second:
  2023-03-28 00:07:52: 22 lfd actions
  2023-03-28 00:07:53: 1 lfd actions
  2023-03-28 00:09:04: 4 lfd actions
  2023-03-28 00:09:05: 18 lfd actions
  ...
  2023-03-31 19:28:52: 1 lfd actions
  2023-03-31 19:28:53: 2 lfd actions
  2023-03-31 19:59:34: 3 lfd actions
  2023-03-31 20:43:34: 3 lfd actions
  2023-03-31 22:52:37: 3 lfd actions
  2023-03-31 23:16:37: 1 lfd actions
  2023-03-31 23:16:38: 2 lfd actions
  2023-03-31 23:56:27: 1 lfd actions

LFD actions per minute:
  2023-03-31 16:48: 6 lfd actions
  2023-03-31 16:53: 6 lfd actions
  2023-03-31 19:28: 3 lfd actions
  2023-03-31 19:59: 3 lfd actions
  2023-03-31 20:43: 3 lfd actions
  2023-03-31 22:52: 3 lfd actions
  2023-03-31 23:16: 3 lfd actions
  2023-03-31 23:56: 1 lfd actions

LFD actions per hour:
  2023-03-31 00: 30 lfd actions
  2023-03-31 01: 13 lfd actions
  2023-03-31 02: 3 lfd actions
  2023-03-31 03: 3 lfd actions
  2023-03-31 04: 6 lfd actions
  2023-03-31 05: 2 lfd actions
  2023-03-31 06: 1 lfd actions
  2023-03-31 07: 83 lfd actions
  2023-03-31 08: 54 lfd actions
  2023-03-31 09: 12 lfd actions
  2023-03-31 10: 13 lfd actions
  2023-03-31 11: 1 lfd actions
  2023-03-31 12: 1 lfd actions
  2023-03-31 13: 2 lfd actions
  2023-03-31 14: 5 lfd actions
  2023-03-31 15: 9 lfd actions
  2023-03-31 16: 17 lfd actions
  2023-03-31 19: 6 lfd actions
  2023-03-31 20: 3 lfd actions
  2023-03-31 22: 3 lfd actions
  2023-03-31 23: 4 lfd actions

LFD actions per day:
  2023-03-28: 348 lfd actions
  2023-03-29: 350 lfd actions
  2023-03-30: 344 lfd actions
  2023-03-31: 271 lfd actions
```