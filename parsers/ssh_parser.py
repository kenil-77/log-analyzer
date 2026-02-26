import re                        # Python's built-in regex library
from datetime import datetime    # For working with timestamps
from collections import defaultdict  # Special dictionary with default values

def parse_ssh_log(filepath):
    """
    Reads an auth.log file line by line.
    For each line that contains a failed login attempt,
    extracts the timestamp, username, and IP address.
    Returns a list of dictionaries, one per failed attempt.
    """

    failed_logins = []   # We'll store all failed attempts here
    successful_logins = []  # We'll also track successful ones

    # This is our regex pattern. Let's break it down piece by piece:
    # (\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})  → captures timestamp like "Jun 10 14:23:01"
    # .*                                        → any characters in between
    # Failed password for                       → literal text we're looking for
    # (?:invalid user )?                        → optionally matches "invalid user "
    # (\w+)                                     → captures the username
    # from                                      → literal text
    # ([\d.]+)                                  → captures the IP address
    # port                                      → literal text
    # (\d+)                                     → captures the port number

    failed_pattern = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\w+) from ([\d.]+) port (\d+)'
    )

    success_pattern = re.compile(
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted password for (\w+) from ([\d.]+)'
    )

    # Open the file and read line by line
    # We read line by line because log files can be HUGE
    # Reading all at once could crash with a memory error
    with open(filepath, 'r', errors='ignore') as f:
        for line_number, line in enumerate(f, 1):

            # Try to match the failed login pattern against this line
            failed_match = failed_pattern.search(line)
            if failed_match:
                failed_logins.append({
                    'line_number': line_number,
                    'timestamp': failed_match.group(1),
                    'user': failed_match.group(2),
                    'ip': failed_match.group(3),
                    'port': failed_match.group(4),
                    'raw': line.strip()
                })
                continue  # No need to check success pattern if already matched

            success_match = success_pattern.search(line)
            if success_match:
                successful_logins.append({
                    'line_number': line_number,
                    'timestamp': success_match.group(1),
                    'user': success_match.group(2),
                    'ip': success_match.group(3),
                    'raw': line.strip()
                })

    return failed_logins, successful_logins
