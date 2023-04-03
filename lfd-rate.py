#!/usr/bin/env python3
import os
import re
import datetime

debug = False
log_file_path = '/var/log/lfd.log'

def parse_timestamp(line):
    pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    match = re.search(pattern, line)
    if match:
        timestamp = datetime.datetime.strptime(match.group(1), '%b %d %H:%M:%S')
        current_year = datetime.datetime.now().year
        timestamp = timestamp.replace(year=current_year)
        return timestamp
    return None

def calculate_lfd_rate(log_file_path, debug=False):
    if not os.path.exists(log_file_path):
        print("Log file not found.")
        return

    with open(log_file_path, 'r') as log_file:
        lines = log_file.readlines()

    lfd_counts = {
        'second': {},
        'minute': {},
        'hour': {},
        'day': {}
    }

    line_count = 0
    matched_line_count = 0

    for line in lines:
        line_count += 1
        if re.search(r'\bSSH login\b', line) or re.search(r'\bBlocked in csf\b', line):
            matched_line_count += 1
            if debug:
                print(f"Matched line {matched_line_count}: {line.strip()}")
            timestamp = parse_timestamp(line)
            if timestamp:
                for unit in lfd_counts:
                    if unit == 'second':
                        key_format = '%Y-%m-%d %H:%M:%S'
                    elif unit == 'minute':
                        key_format = '%Y-%m-%d %H:%M'
                    elif unit == 'hour':
                        key_format = '%Y-%m-%d %H'
                    else: # day
                        key_format = '%Y-%m-%d'

                    unit_key = timestamp.strftime(key_format)

                    if unit_key not in lfd_counts[unit]:
                        lfd_counts[unit][unit_key] = 1
                    else:
                        lfd_counts[unit][unit_key] += 1

    print(f"Total lines processed: {line_count}")
    print(f"Total matched lines: {matched_line_count}")

    for unit, counts in lfd_counts.items():
        print(f"LFD actions per {unit}:")
        if counts:
            for unit_key, count in sorted(counts.items()):
                print(f"  {unit_key}: {count} lfd actions")
        else:
            print(f"  No actions found for {unit}")
        print()

if __name__ == '__main__':
    calculate_lfd_rate(log_file_path, debug=debug)
