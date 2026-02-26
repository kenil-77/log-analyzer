from collections import Counter
import pandas as pd

def detect_brute_force(failed_logins, threshold=5):
    if not failed_logins:
        return {}, {}

    df = pd.DataFrame(failed_logins)
    ip_counts = df['ip'].value_counts()
    brute_force_ips = ip_counts[ip_counts >= threshold]

    ip_targets = {}
    for ip in brute_force_ips.index:
        ip_rows = df[df['ip'] == ip]
        targeted_users = ip_rows['user'].unique().tolist()
        attempt_count = len(ip_rows)
        ip_targets[ip] = {
            'count': attempt_count,
            'targeted_users': targeted_users,
            'first_seen': ip_rows['timestamp'].iloc[0],
            'last_seen': ip_rows['timestamp'].iloc[-1]
        }

    return brute_force_ips.to_dict(), ip_targets


def detect_username_attacks(failed_logins):
    if not failed_logins:
        return {}

    df = pd.DataFrame(failed_logins)
    return df['user'].value_counts().to_dict()
