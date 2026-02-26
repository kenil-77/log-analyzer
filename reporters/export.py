import csv
import os
from datetime import datetime

def export_csv(ip_targets, failed_logins, successful_logins, output_dir="reports"):
    """
    Exports brute force results to a CSV file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"ssh_report_{timestamp}.csv")

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)

        # Brute Force Section
        writer.writerow(["BRUTE FORCE DETECTION RESULTS"])
        writer.writerow(["IP Address", "Total Attempts", "Users Targeted", "First Seen", "Last Seen", "Status"])

        for ip, data in ip_targets.items():
            writer.writerow([
                ip,
                data['count'],
                ', '.join(data['targeted_users']),
                data['first_seen'],
                data['last_seen'],
                "FLAGGED"
            ])

        writer.writerow([])

        # Successful Logins Section
        writer.writerow(["SUCCESSFUL LOGINS"])
        writer.writerow(["Timestamp", "Username", "IP Address"])

        for login in successful_logins:
            writer.writerow([
                login['timestamp'],
                login['user'],
                login['ip']
            ])

    print(f"  CSV saved to: {filepath}")
    return filepath


def export_html(ip_targets, failed_logins, successful_logins, output_dir="reports"):
    """
    Exports brute force results to a clean HTML file.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"ssh_report_{timestamp}.html")

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SSH Log Analysis Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #1e1e1e;
            color: #f0f0f0;
            padding: 30px;
        }
        h1 { color: #00bcd4; border-bottom: 2px solid #00bcd4; padding-bottom: 10px; }
        h2 { color: #00bcd4; margin-top: 40px; }
        .summary {
            background-color: #2a2a2a;
            border: 1px solid #00bcd4;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            display: inline-block;
        }
        .summary p { margin: 5px 0; font-size: 16px; }
        .failed  { color: #f44336; font-weight: bold; }
        .success { color: #4caf50; font-weight: bold; }
        .warning { color: #ff9800; font-weight: bold; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background-color: #00bcd4;
            color: #1e1e1e;
            padding: 12px 15px;
            text-align: left;
        }
        td { padding: 10px 15px; border-bottom: 1px solid #333; }
        tr:nth-child(even) { background-color: #2a2a2a; }
        tr:nth-child(odd)  { background-color: #252525; }
        .flagged { color: #f44336; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔍 SSH Log Analysis Report</h1>
"""

    html += f"""
    <div class="summary">
        <p>Total Failed Logins:     <span class="failed">{len(failed_logins)}</span></p>
        <p>Total Successful Logins: <span class="success">{len(successful_logins)}</span></p>
        <p>Suspicious IPs Detected: <span class="warning">{len(ip_targets)}</span></p>
    </div>

    <h2>⚠ Brute Force Detection Results</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Attempts</th>
            <th>Users Targeted</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Status</th>
        </tr>
"""

    for ip, data in ip_targets.items():
        html += f"""
        <tr>
            <td>{ip}</td>
            <td>{data['count']}</td>
            <td>{', '.join(data['targeted_users'])}</td>
            <td>{data['first_seen']}</td>
            <td>{data['last_seen']}</td>
            <td class="flagged">⚠ FLAGGED</td>
        </tr>
"""

    html += """
    </table>

    <h2>✅ Successful Logins</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Username</th>
            <th>IP Address</th>
        </tr>
"""

    for login in successful_logins:
        html += f"""
        <tr>
            <td>{login['timestamp']}</td>
            <td>{login['user']}</td>
            <td>{login['ip']}</td>
        </tr>
"""

    html += """
    </table>
</body>
</html>
"""

    with open(filepath, 'w') as f:
        f.write(html)

    print(f"  HTML saved to: {filepath}")
    return filepath
