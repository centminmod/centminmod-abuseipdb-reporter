#!/usr/bin/env python3
####################################################################
# created for CentOS, AlmaLinux, RockyLinux RPM OSes
# specifically for Centmin Mod LEMP stacks centminmod.com
# by George Liu (eva2000)
# https://github.com/centminmod/centminmod-abuseipdb-reporter
####################################################################
import sys
import os
import argparse
import requests
import configparser

VERSION = "0.0.2"

def read_api_key():
    if "ABUSEIPDB_API_KEY" in os.environ:
        return os.environ["ABUSEIPDB_API_KEY"]

    config = configparser.ConfigParser()
    config.read("abuseipdb-reporter.ini")

    if "settings" in config.sections() and "API_KEY" in config["settings"]:
        return config["settings"]["API_KEY"]

    return None

def query_abuseipdb(ip_address, max_days, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    data = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_days,
        "verbose": ""
    }

    response = requests.get(url, headers=headers, params=data)
    return response.json()

def extract_info(json_data, include_reports):
    data = json_data['data']
    reports = data['reports']
    info = []

    if include_reports:
        for report in reports:
            extracted = {
                "reporterId": report['reporterId'],
                "categories": report['categories'],
                "reporterCountryCode": report['reporterCountryCode'],
                "reportedAt": report['reportedAt']
            }
            info.append(extracted)

    return {
        "ipAddress": data['ipAddress'],
        "isPublic": data['isPublic'],
        "ipVersion": data['ipVersion'],
        "isWhitelisted": data['isWhitelisted'],
        "abuseConfidenceScore": data['abuseConfidenceScore'],
        "countryCode": data['countryCode'],
        "usageType": data['usageType'],
        "isp": data['isp'],
        "totalReports": data['totalReports'],
        "numDistinctUsers": data['numDistinctUsers'],
        "reportsInfo": info if include_reports else None
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip", required=True, help="IP address to query")
    parser.add_argument("-maxdays", type=int, default=7, help="Max age in days (default is 7)")
    parser.add_argument("-apikey", help="Your API key for AbuseIPDB (optional)")
    parser.add_argument("-reports", choices=['yes', 'no'], default='no', help="Include reports data (default is 'no')")
    args = parser.parse_args()

    api_key = args.apikey or read_api_key()

    if not api_key:
        print("API key not provided or found in the environment variable or ini file")
        sys.exit(1)

    json_data = query_abuseipdb(args.ip, args.maxdays, api_key)
    extracted_data = extract_info(json_data, args.reports == 'yes')

    import json
    print(json.dumps(extracted_data))

if __name__ == "__main__":
    main()
