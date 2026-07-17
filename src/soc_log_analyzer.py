from datetime import datetime

def analyze_logs(filepath: str) -> dict:

    """
    Reads an authentication log file and counts failed login attempts for each IP address. 
    
    Args: filepath: Path to the authentication log file. 
    
    Returns: A dictionary containing failed login information for each IP address.
    """

    try:
        with open(filepath, "r") as file:
            content = file.readlines()

    except FileNotFoundError:
        print(f"Error: Log file '{filepath}' was not found!")
        return {}
    
    failed_ips = {}

    for line in content:
        line = line.strip()

        if "Failed password" in line:
            parts = line.split()
            
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{current_year} {' '.join(parts[:3])}", "%Y %b %d %H:%M:%S")

            for_index = parts.index("for")
            username = parts[for_index + 1]

            from_index = parts.index("from")
            ip = parts[from_index + 1]

            if ip not in failed_ips:
                failed_ips[ip] = {"attempts": 1, "usernames": [username], "timestamps": [timestamp]}
            else:
                failed_ips[ip]["attempts"] += 1
                failed_ips[ip]["timestamps"].append(timestamp)
                failed_ips[ip]["usernames"].append(username)

    return failed_ips

def is_brute_force(timestamps: list[datetime], threshold: int, time_window: int) -> bool:
    """
    Detect whether a series of failed login attempts resembles a brute-force attack.

    Args:
        timestamps: List of failed login attempt times.
        threshold: Number of attempts required to trigger detection.
        time_window: Time window in seconds.

    Returns:
        True if a brute-force pattern is detected, otherwise False.
    """

    timestamps = sorted(timestamps)

    for i in range(len(timestamps) - threshold + 1):
        start = timestamps[i]
        end = timestamps[i + threshold - 1]

        difference = (end - start).total_seconds()

        if difference <= time_window:
            return True
        
    return False

def print_report(failed_ips: dict) -> None:
    """
    Prints a summary report of failed login attempts.

    Args:
        failed_ips: Dictionary containing failed login information for each IP.

    Returns:
        None.
    """

    print("\n=== FAILED LOGINS REPORT ===\n")

    for ip in failed_ips:
        attempts = failed_ips[ip]["attempts"]
        usernames = failed_ips[ip]["usernames"]
        timestamps = failed_ips[ip]["timestamps"]
        unique_usernames = ", ".join(set(usernames))

        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {attempts}")
        print(f"Targeted User(s): {unique_usernames}")
        print(f"First Attempt: {timestamps[0]}")
        print(f"Last Attempt: {timestamps[-1]}")
        print()

    print(f"Total Unique Attacking IPs: {len(failed_ips)}")

def print_alerts(failed_ips: dict, threshold: int) -> None:
    """
    Prints an alert for every IP address whose failed login attempts
    meet or exceed the threshold value.

    Args:
        failed_ips: Dictionary containing failed login information.
        threshold: Minimum number of failed attempts required to trigger an alert.

    Returns:
        None.
    """

    print("\n=== ALERTS ===")
    for ip in failed_ips:
        attempts = failed_ips[ip]["attempts"]

        if attempts >= threshold:
            print(f"⚠ Alert: {ip} exceeded the threshold with {attempts} failed attempts.")

def most_suspicious_ip(failed_ips: dict) -> tuple[str, int]:
    """
    Finds the IP address with the highest number of failed login attempts.

    Args:
        failed_ips: Dictionary containing failed login information.

    Returns:
        A tuple containing the most suspicious IP address and
        its fail count.
    """

    if not failed_ips:
        return "", 0

    most_suspicious_ip = max(failed_ips, key= lambda ip: failed_ips[ip]["attempts"])
    attempts = failed_ips[most_suspicious_ip]["attempts"]

    return most_suspicious_ip, attempts

def main() -> None: 
    log_file = "logs/sample_auth.log"
    threshold = 3

    failed_ips = analyze_logs(log_file)

    print_report(failed_ips)
    print_alerts(failed_ips, threshold)

    ip, attempts = most_suspicious_ip(failed_ips)

    print("\n=== MOST SUSPICIOUS IP ===\n")
    print(f"IP Address: {ip}")
    print(f"Failed Attempts: {attempts}")

main()