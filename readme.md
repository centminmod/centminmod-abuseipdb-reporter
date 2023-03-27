# CSF Firewall + AbuseIPDB Integration

Based on CSF Firewall and AbuseIPDB integration guide at https://www.abuseipdb.com/csf. Tailored for Centmin Mod LEMP stack based servers.

## Dependencies

Python 3.x required as well as:

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

```
cat /var/log/abuseipdb-reporter-debug.log

DEBUG MODE: No actual report sent.
URL: https://api.abuseipdb.com/api/v2/report
Headers: {'Accept': 'application/json', 'Key': 'YOUR_API_KEY'}
IP: 47.149.92.160
Categories: 14
Comment: (sshd) Failed SSH login from 47.149.92.160 (US/United States/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 27 09:03:28 MASKED_HOSTNAME sshd[572974]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=47.149.92.160  user=root
Mar 27 09:03:30 MASKED_HOSTNAME sshd[572974]: Failed password for root from 47.149.92.160 port 55878 ssh2
Mar 27 09:05:38 MASKED_HOSTNAME sshd[572998]: Invalid user emilio from 47.149.92.160 port 34094
Mar 27 09:05:39 MASKED_HOSTNAME sshd[572998]: Failed password for invalid user emilio from 47.149.92.160 port 34094 ssh2
Mar 27 09:07:21 MASKED_HOSTNAME sshd[573017]: Invalid user exploit from 47.149.92.160 port 34666

----
DEBUG MODE: No actual report sent.
URL: https://api.abuseipdb.com/api/v2/report
Headers: {'Accept': 'application/json', 'Key': 'YOUR_API_KEY'}
IP: 210.187.80.132
Categories: 14
Comment: (sshd) Failed SSH login from 210.187.80.132 (MY/Malaysia/-): 5 in the last 3600 secs; Ports: *; Direction: inout; Trigger: LF_SSHD; Logs: Mar 27 09:04:37 MASKED_HOSTNAME sshd[572984]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=210.187.80.132  user=root
Mar 27 09:04:39 MASKED_HOSTNAME sshd[572984]: Failed password for root from 210.187.80.132 port 46148 ssh2
Mar 27 09:07:02 MASKED_HOSTNAME sshd[573011]: Invalid user api from 210.187.80.132 port 50060
Mar 27 09:07:04 MASKED_HOSTNAME sshd[573011]: Failed password for invalid user api from 210.187.80.132 port 50060 ssh2
Mar 27 09:08:52 MASKED_HOSTNAME sshd[573069]: Invalid user osa from 210.187.80.132 port 50630
```

4. Set the `BLOCK_REPORT` variable in `/etc/csf.conf` to the executable script file.

```
BLOCK_REPORT = "/root/tools/abuseipdb-reporter.py"
```

restart CSF and lfd using:

```
csf -ra
```

