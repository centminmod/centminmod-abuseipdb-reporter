#!/usr/bin/env python3

import json
from collections import defaultdict
from datetime import datetime
import plotly.graph_objects as go
import plotly.io as pio
from plotly.io import to_json
from datetime import datetime, timedelta

# Load the JSON data from the log file
with open('/var/log/abuseipdb-reporter-api-json.log', 'r') as f:
    logs = json.load(f)

# Prepare data structures for the charts
ip_submissions = defaultdict(int)
ip_scores = defaultdict(float)
hourly_counts = defaultdict(lambda: 0)

# Process the logs
for log in logs:
    ip = log['sentIP']
    trigger = log.get('notsentTrigger', 'Unknown')
    timestamp = log.get('notsentTimestamp', None)
    api_response = log.get('apiResponse', None)

    if api_response:
        try:
            confidence_score = api_response['data'].get('abuseConfidenceScore', 0)
            ip_scores[ip] += confidence_score
            ip_submissions[ip] += 1
        except KeyError:
            pass

    # update hourly_counts
    if timestamp:
        timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        hour = timestamp.replace(minute=0, second=0, microsecond=0)
        hourly_counts[hour] += 1

# Generate chart 1
top_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
ip_addresses = [ip[0] for ip in top_ips]
submission_counts = [ip_submissions[ip[0]] for ip in top_ips]
confidence_scores = [ip[1] for ip in top_ips]

fig1 = go.Figure(go.Bar(x=ip_addresses, y=submission_counts, name='IP Addresses'))
fig1.update_layout(
    title='Top 10 IP Addresses Submitted with Abuse Confidence Scores',
    xaxis_title='IP Address',
    yaxis_title='Total API Submissions'
)

# Generate chart 2
# Get the current time
now = datetime.now()

# Calculate the time 24 hours ago
last_24_hours = now - timedelta(hours=24)

# Filter out the logs older than 24 hours and ensure both 'abuseConfidenceScore' and 'notsentTimestamp' are present
print(f"Total logs: {len(logs)}")
recent_logs = [
    log for log in logs
    if log.get('apiResponse', {}).get('data', {}).get('abuseConfidenceScore', None) is not None
    and 'notsentTimestamp' in log
    and datetime.strptime(log['notsentTimestamp'], '%Y-%m-%d %H:%M:%S') >= last_24_hours
]

# Aggregate hourly submissions
hourly_counts = defaultdict(int)
print(f"Logs within the last 24 hours: {len(recent_logs)}")

for log in recent_logs:
    ip = log['sentIP']
    timestamp = datetime.strptime(log['notsentTimestamp'], '%Y-%m-%d %H:%M:%S')
    current_hour = timestamp.replace(minute=0, second=0, microsecond=0)

    trigger = log.get('notsentTrigger', 'Unknown')
    confidence_score = log.get('apiResponse', {}).get('data', {}).get('abuseConfidenceScore', 0)

    if confidence_score > 0:
        hourly_counts[current_hour] += 1

print(f"Hourly counts: {hourly_counts}")

hourly_timestamps = []
hourly_submission_counts = []

for i in range(24):
    hour = last_24_hours + timedelta(hours=i)
    hourly_timestamps.append(hour)
    hourly_submission_counts.append(hourly_counts.get(hour, 0))

fig2 = go.Figure(go.Bar(x=hourly_timestamps, y=hourly_submission_counts))
fig2.update_layout(
    title='Hourly Total IP Submissions with Abuse Confidence Scores in the Last 24 Hours',
    xaxis_title='Hour',
    yaxis_title='Submission Count'
)

# Save chart 1 JSON data to a file
with open('chart1_data.json', 'w') as chart1_file:
    chart1_file.write(to_json(fig1))

# Save chart 2 data to a file
def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

with open('chart2_data.json', 'w') as chart2_file:
    json.dump(fig2.to_dict(), chart2_file, indent=2, default=serialize_datetime)

# Load chart 2 data from file
with open('chart2_data.json', 'r') as f:
    chart2_data = json.load(f)

# Create the HTML file with two chart containers and the Plotly.js library from a CDN
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Charts</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div id="chart1"></div>
    <div id="chart2"></div>
    <script>
        Plotly.react('chart1', {0});
        Plotly.react('chart2', {1});
        Plotly.update('chart2', {{
            'xaxis': {{
                'tickvals': [{2}],
                'ticktext': [{3}],
                'tickangle': 45
            }}
        }});
    </script>
</body>
</html>
'''

# Update the last line of the script as follows
with open('charts.html', 'w') as f:
    f.write(html_template.format(to_json(fig1), to_json(fig2), str(hourly_timestamps), str(hourly_submission_counts)))
