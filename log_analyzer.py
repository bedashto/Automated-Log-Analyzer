import re
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

def parse_log(file_path):
    """Parse log file and extract relevant fields."""
    log_entries = []
    pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.+?)\] '
        r'"(?P<request>.*?)" (?P<status>\d+) (?P<size>\d+)'
    )
    try:
        with open(file_path, "r") as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    log_entries.append(match.groupdict())
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return pd.DataFrame(log_entries)

def detect_failed_logins(log_df):
    """Detect IPs with high numbers of failed login attempts."""
    failed_ips = log_df[
        (log_df['status'] == '401')  # HTTP 401: Unauthorized
    ]['ip']
    return Counter(failed_ips)

def detect_high_request_ips(log_df, threshold=100):
    """Detect IPs with requests exceeding the threshold."""
    request_counts = log_df['ip'].value_counts()
    return request_counts[request_counts > threshold]

def detect_brute_force(log_df, failed_attempt_threshold=5):
    """Detect brute force attacks by counting failed logins per IP."""
    log_df['date'] = pd.to_datetime(log_df['date'], format='%d/%b/%Y:%H:%M:%S %z')
    failed_logins = log_df[log_df['status'] == '401']
    brute_force_ips = failed_logins.groupby('ip').size()
    return brute_force_ips[brute_force_ips > failed_attempt_threshold]

def visualize_data(failed_ips, high_request_ips, brute_force_ips):
    """Generate visualizations for the analysis."""
    # Plot failed login attempts
    if failed_ips:
        plt.figure(figsize=(10, 6))
        plt.bar(failed_ips.keys(), failed_ips.values(), color='red')
        plt.title('Failed Login Attempts by IP')
        plt.xlabel('IP Address')
        plt.ylabel('Failed Attempts')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("failed_logins.png")
        plt.show()

    # Plot high request IPs
    if not high_request_ips.empty:
        high_request_ips.plot(kind='bar', color='blue', title='High Request IPs')
        plt.ylabel('Request Count')
        plt.tight_layout()
        plt.savefig("high_request_ips.png")
        plt.show()

    # Plot brute force attempts
    if not brute_force_ips.empty:
        brute_force_ips.plot(kind='bar', color='orange', title='Brute Force IPs')
        plt.ylabel('Failed Login Count')
        plt.tight_layout()
        plt.savefig("brute_force_ips.png")
        plt.show()

def main():
    log_file = input("Enter the log file path: ")
    logs_df = parse_log(log_file)

    if logs_df.empty:
        print("No valid log entries found. Exiting.")
        return

    # Detect anomalies
    print("\nAnalyzing logs...")
    failed_logins = detect_failed_logins(logs_df)
    high_request_ips = detect_high_request_ips(logs_df, threshold=100)
    brute_force_ips = detect_brute_force(logs_df, failed_attempt_threshold=5)

    # Display results
    print("\nFailed Login Attempts:")
    for ip, count in failed_logins.items():
        print(f"{ip}: {count} times")

    print("\nHigh Request IPs:")
    print(high_request_ips)

    print("\nBrute Force IPs:")
    print(brute_force_ips)

    # Visualize results
    visualize_data(failed_logins, high_request_ips, brute_force_ips)

if __name__ == "__main__":
    main()
