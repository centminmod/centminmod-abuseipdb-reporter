# CSF Firewall + AbuseIPDB Integration

Based on CSF Firewall and AbuseIPDB integration guide at https://www.abuseipdb.com/csf. Tailored for Centmin Mod LEMP stack based servers.

## Dependencies

Python 3.x required as well as `requests` module:


Centmin Mod users can install Python 3.x via `addons/python36_install.sh`

```
/usr/local/src/centminmod/addons/python36_install.sh
```
```
pip3 install requests
```

## Setup

1. Create an AbuseIPDB API key

Register an account with AbuseIPDB, and [create an API key](https://www.abuseipdb.com/account/api). The API is free to use, but you do have to [create an account](https://www.abuseipdb.com/register).

2. Integrating our Blacklist

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

Edit the `/root/tools/abuseipdb-reporter.py` script's variables:

* `DEBUG = True` - When set to `True`, debug mode is enabled and no actual CSF Firewall block actions will be sent to AbuseIPDB via API endpoint url. Instead block actions will be saved to a local log file `/var/log/abuseipdb-reporter-debug.log`. You can use this mode for troubleshooting or testing before you eventually set `DEBUG = False` to enable actual CSF Firewall block actions to be sent to AbuseIPDB via API endpoint url.
* `API_KEY = 'YOUR_API_KEY'` - Set `YOUR_API_KEY` to your AbuseIPDB API key

Example of `DEBUG = True` debug mode saved log file entries at `/var/log/abuseipdb-reporter-debug.log` 

Data logging of processed data that AbuseIPDB will receive + also a raw copy of data passed from CSF so can compare the two:

```
cat /var/log/abuseipdb-reporter-debug.log
DEBUG MODE: No actual report sent.
URL: https://api.abuseipdb.com/api/v2/report
Headers: {'Accept': 'application/json', 'Key': 'YOUR_API_KEY'}
IP: 104.xxx.xxx.xxx
Categories: 22
Comment: (sshd) Failed SSH login from 104.xxx.xxx.xxx (CA/Canada/hostname.domain.com): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 27 20:02:04 sshd[583368]: Failed password for root from 104.xxx.xxx.xxx port 20136 ssh2
Mar 27 20:09:38 sshd[583565]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=104.xxx.xxx.xxx  user=root
Mar 27 20:09:40 sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2
Mar 27 20:09:45 sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2
Mar 27 20:09:54 sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2
----
DEBUG MODE: CSF passed data
Ports: *
In/Out: inout
Message: (sshd) Failed SSH login from 104.xxx.xxx.xxx (CA/Canada/hostname.domain.com): 5 in the last 3600 secs
Logs: Mar 27 20:02:04 hostname sshd[583368]: Failed password for root from 104.xxx.xxx.xxx port 20136 ssh2
Mar 27 20:09:38 hostname sshd[583565]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=104.xxx.xxx.xxx  user=root
Mar 27 20:09:40 hostname sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2
Mar 27 20:09:45 hostname sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2
Mar 27 20:09:54 hostname sshd[583565]: Failed password for root from 104.xxx.xxx.xxx port 20240 ssh2

Trigger: LF_SSHD
----
```

So CSF passed raw data for `hostname` and `104.xxx.xxx.xxx` but script will remove the `lfd.log` 4th field for hostname when sending to AbuseIPDB.

4. Set the `BLOCK_REPORT` variable in `/etc/csf.conf` to the executable script file.

```
BLOCK_REPORT = "/root/tools/abuseipdb-reporter.py"
```

restart CSF and lfd using:

```
csf -ra
```

