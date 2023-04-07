#!/usr/bin/env python3
import json
from collections import defaultdict
from datetime import datetime
import plotly.graph_objects as go
import plotly.io as pio
from plotly.io import to_json
from datetime import datetime, timedelta

VERSION = "0.0.3"

# Load the JSON data from the log file
with open('/var/log/abuseipdb-reporter-api-json.log', 'r') as f:
    logs = json.load(f)

# Prepare data structures for the charts
ip_submissions = defaultdict(int)
ip_scores = defaultdict(float)
hourly_counts = defaultdict(lambda: defaultdict(int))

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
        hourly_counts[hour][trigger] += 1

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
    if log.get('apiResponse', {}).get('data', {}).get('abuseConfidenceScore') is not None
    and log.get('notsentTimestamp') is not None
    and datetime.strptime(log['notsentTimestamp'], '%Y-%m-%d %H:%M:%S') > last_24_hours
]
print(f"Logs within last 24 hours: {len(recent_logs)}")

# Aggregate hourly submissions and triggers
hourly_submission_counts = defaultdict(int)
hourly_triggers = defaultdict(lambda: defaultdict(int))

for log in recent_logs:
    ip = log['sentIP']
    timestamp = datetime.strptime(log['notsentTimestamp'], '%Y-%m-%d %H:%M:%S')
    current_hour = timestamp.replace(minute=0, second=0, microsecond=0)

    trigger = log.get('notsentTrigger', 'Unknown')
    confidence_score = log.get('apiResponse', {}).get('data', {}).get('abuseConfidenceScore', 0)

    if confidence_score > 0:
        hourly_submission_counts[current_hour] += 1
        hourly_triggers[current_hour][trigger] += 1

print("Hourly counts with breakdown of trigger counts (last 24 hours):")
for hour in hourly_counts:
    if hour > last_24_hours:
        triggers = hourly_triggers[hour]
        trigger_breakdown = ', '.join([f"{trigger}: {count}" for trigger, count in triggers.items()])
        total_count = sum(triggers.values())
        print(f"{hour}: {total_count} ({trigger_breakdown})")

# Create a list of unique triggers
unique_triggers = sorted({trigger for hour, triggers in hourly_triggers.items() for trigger in triggers})

# Prepare the data for the stacked bar chart
start_hour = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=24)
hourly_timestamps = [start_hour + timedelta(hours=i) for i in range(25)]
hourly_trigger_counts = {trigger: [hourly_triggers[hour].get(trigger, 0) for hour in hourly_timestamps] for trigger in unique_triggers}

# Generate the stacked bar chart
fig2 = go.Figure()

for trigger in unique_triggers:
    hover_text = []
    for i, hour in enumerate(hourly_timestamps):
        count = hourly_trigger_counts[trigger][i]
        total_count = hourly_submission_counts[hour]
        hover_text.append(f"{hour}: {count}<br>Total: {total_count}")
    fig2.add_trace(go.Bar(x=hourly_timestamps, y=hourly_trigger_counts[trigger], name=trigger, hovertext=hover_text))

fig2.update_layout(
    title='Hourly Total IP Submissions with Abuse Confidence Scores in the Last 24 Hours',
    xaxis_title='Hour',
    yaxis_title='Submission Count',
    barmode='stack'
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
html_template = r'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Charts</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        .chart-container {{
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            align-items: center;
            margin: 10px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            width: 100%;
            max-width: 1400px;
        }}
        .chart-container > div {{
            width: 100%;
            margin: 10px;
        }}
        @media only screen and (max-width: 768px) {{
            .chart-container {{
                max-width: 640px;
            }}
            .chart-container > div {{
                width: 50%;
            }}
        }}
    </style>
</head>
<body>
    <div class="chart-container">
        <div id="chart1"></div>
        <div id="chart2"></div>
    </div>
    <script>
        Plotly.react('chart1', {0});
        Plotly.react('chart2', {1});
        Plotly.update('chart2', {{
            'xaxis': {{
                'tickvals': {2},
                'ticktext': {3},
                'tickangle': 45
            }}
        }});
    </script>
</body>
</html>
'''

# Create charts.html
hourly_timestamps_str = [hour.isoformat() for hour in hourly_timestamps]
with open('charts.html', 'w') as f:
    f.write(html_template.format(to_json(fig1), to_json(fig2), hourly_timestamps, hourly_timestamps_str))
