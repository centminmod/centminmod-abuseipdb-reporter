# CSF Firewall + AbuseIPDB Integration

Based on CSF Firewall and AbuseIPDB integration guide at https://www.abuseipdb.com/csf. Tailored for Centmin Mod LEMP stack based servers.

This guide will show you how to set up CSF Firewall so that attempted intrusions against your system are automatically blocked by CSF's Login Failure Daemon (lfd) logged actions. It is also possible to use CSF Firewall to pre-emptively block bad IP addresses using [CSF Firewall's blocklist feature and AbuseIPDB's collated blocklist database](#setup).

* [Dependencies](#dependencies)
* [Setup](#setup)
* [Configuration](#configuration)
  * [abuseipdb-reporter.ini](#abuseipdb-reporterini)
  * [Example](#example)
  * [JSON log format](#json-log-format)
    * [Parsing JSON formatted logs](#parsing-json-formatted-logs)
* [CSF Cluster Mode](#csf-cluster-mode)
  * [JSON log format CSF Cluster](#json-log-format-csf-cluster)

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
API_KEY = YOUR_API_KEY
DEFAULT_LOG_FILE = /var/log/abuseipdb-reporter-debug.log
DEFAULT_JSONLOG_FILE = /var/log/abuseipdb-reporter-debug-json.log
DEFAULT_APILOG_FILE = /var/log/abuseipdb-reporter-api.log
mask_hostname = MASKED_HOSTNAME
mask_ip = 0.0.0.x
USERNAME_REPLACEMENT = '[USERNAME]'
ACCOUNT_REPLACEMENT = '[REDACTED]'
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
Version: 0.1.0
DEBUG MODE: data intended to be sent to AbuseIPDB
URL: https://api.abuseipdb.com/api/v2/report
Headers: {'Accept': 'application/json', 'Key': 'YOUR_API_KEY'}
IP: 1.34.234.1
Categories: 22
Comment: (sshd) Failed SSH login from 1.34.234.1 (TW/Taiwan/1-34-234-1.hinet-ip.hinet.net): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 28 23:52:08 sshd[548999]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.34.234.1  user=[USERNAME]
Mar 28 23:52:11 sshd[548999]: Failed password for [USERNAME] from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:14 sshd[548999]: Failed password for [USERNAME] from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:19 sshd[548999]: Failed password for [USERNAME] from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:23 sshd[548999]: Failed password for [USERNAME] from 1.34.234.1 port 43749 ssh2
---------------------------------------------------------------------------
DEBUG MODE: CSF passed data not sent to AbuseIPDB
Ports: *
In/Out: inout
Message: (sshd) Failed SSH login from 1.34.234.1 (TW/Taiwan/1-34-234-1.hinet-ip.hinet.net): 5 in the last 3600 secs
Logs: Mar 28 23:52:08 hostname sshd[548999]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.34.234.1  user=[USERNAME]
Mar 28 23:52:11 hostname sshd[548999]: Failed password for root from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:14 hostname sshd[548999]: Failed password for root from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:19 hostname sshd[548999]: Failed password for root from 1.34.234.1 port 43749 ssh2
Mar 28 23:52:23 hostname sshd[548999]: Failed password for root from 1.34.234.1 port 43749 ssh2

Trigger: LF_SSHD
############################################################################
--------
```

So CSF passed raw data for `hostname` and `1.34.234.1` but script will remove the `lfd.log` 4th field for `hostname` when sending to AbuseIPDB.

# JSON log format

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
    "sentIP": "165.154.247.162",
    "sentCategories": "22",
    "sentComment": "(sshd) Failed SSH login from 165.154.247.162 (TH/Thailand/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 30 06:07:54 sshd[617133]: Invalid user [USERNAME] from 165.154.247.162 port 41276\nMar 30 06:07:56 sshd[617133]: Failed password for invalid user [USERNAME] from 165.154.247.162 port 41276 ssh2\nMar 30 06:09:36 sshd[617167]: Invalid user [USERNAME] from 165.154.247.162 port 38986\nMar 30 06:09:39 sshd[617167]: Failed password for invalid user [USERNAME] from 165.154.247.162 port 38986 ssh2\nMar 30 06:10:55 sshd[617254]: Invalid user administrator from 165.154.247.162 port 34516",
    "notsentPorts": "*",
    "notsentInOut": "inout",
    "notsentMessage": "(sshd) Failed SSH login from 165.154.247.162 (TH/Thailand/-): 5 in the last 3600 secs",
    "notsentLogs": "Mar 30 06:07:54 hostname sshd[617133]: Invalid user vr from 165.154.247.162 port 41276\nMar 30 06:07:56 hostname sshd[617133]: Failed password for invalid user vr from 165.154.247.162 port 41276 ssh2\nMar 30 06:09:36 hostname sshd[617167]: Invalid user user from 165.154.247.162 port 38986\nMar 30 06:09:39 hostname sshd[617167]: Failed password for invalid user user from 165.154.247.162 port 38986 ssh2\nMar 30 06:10:55 hostname sshd[617254]: Invalid user administrator from 165.154.247.162 port 34516\n",
    "notsentTrigger": "LF_SSHD"
  }
]
```

For JSON format, the key names prefixed with `sent` are data that is sent to AbuseIPDB. While key names prefixed with `notsent` is data CSF passed onto the script. So CSF passed raw data for `hostname` and `165.154.247.162` but script will remove the `lfd.log` 4th field for `hostname` when sending to AbuseIPDB.

## Parsing JSON formatted logs

You can also use `jq` to parse and filter the JSON formatted logs.

Get `sentIP` for each entry

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq -r '.[] | .sentIP'
165.154.247.162
```

Only get `sentIP` and `sentCategories` for each entry

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '[.[] | {sentIP, sentCategories}]'
[
  {
    "sentIP": "165.154.247.162",
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

Only get entries where `notsentTrigger` = `LF_SSHD` and `sentIP` = `165.154.247.162`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.notsentTrigger == "LF_SSHD" and .sentIP == "165.154.247.162")'
```

Only get entries where `sentCategories` = `22`

```bash
cat /var/log/abuseipdb-reporter-debug-json.log | jq '.[] | select(.sentCategories == "22")'
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
