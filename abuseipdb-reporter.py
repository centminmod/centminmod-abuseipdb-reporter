#!/usr/bin/env python
import requests
import json
import sys

# Set your API key here
API_KEY = '$YOUR_API_KEY'

# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/report'
ports = sys.argv[1]
inOut = sys.argv[3]
message = sys.argv[5]
logs = sys.argv[6]
trigger = sys.argv[7]
comment = message + "; Ports: " + ports + "; Direction: " + inOut + "; Trigger: " + trigger + "; Logs: " + logs
headers = {
     'Accept': 'application/json',
     'Key': API_KEY
}
# String holding parameters to pass in json format
querystring = {
    'ip': sys.argv[1],
    'categories': '14',
    'comment': comment
}

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