import random
from datetime import datetime, timedelta

def generate_fake_auth_log(output_path="sample_logs/auth.log", num_lines=500):
    """
    Generates a realistic fake auth.log for testing.
    Includes both legitimate logins and simulated brute force attacks.
    """

    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
    legitimate_users = ['john', 'sarah', 'deploy', 'ubuntu']

    # Attacker IPs — these will generate many failures
    attacker_ips = ['192.168.1.100', '10.0.0.55', '172.16.0.200']

    # Normal users — occasional failures
    normal_ips = ['192.168.1.2', '192.168.1.5', '10.0.0.10']

    lines = []
    base_time = datetime(2024, 6, 10, 8, 0, 0)

    for i in range(num_lines):
        current_time = base_time + timedelta(seconds=i * 2)
        timestamp = current_time.strftime('%b %d %H:%M:%S')
        pid = random.randint(1000, 9999)

        # 60% chance of attacker activity
        if random.random() < 0.6:
            ip = random.choice(attacker_ips)
            user = random.choice(['root', 'admin', 'administrator', 'test'])
            port = random.randint(40000, 60000)
            line = f"{timestamp} myserver sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

        # 30% legitimate failures
        elif random.random() < 0.3:
            ip = random.choice(normal_ips)
            user = random.choice(legitimate_users)
            port = random.randint(40000, 60000)
            line = f"{timestamp} myserver sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

        # 10% successful logins
        else:
            ip = random.choice(normal_ips)
            user = random.choice(legitimate_users)
            line = f"{timestamp} myserver sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"

        lines.append(line)

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))

    print(f"Generated {num_lines} log lines at {output_path}")

if __name__ == '__main__':
    generate_fake_auth_log()
