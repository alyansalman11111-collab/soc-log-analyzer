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
            try:
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

            except ValueError:
                continue

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

def is_password_spray(usernames: list[str], timestamps: list[datetime], threshold: int, time_window: int) -> bool:
    """
    Detect whether a series of failed login attempts resembles a password spraying attack.

    Args:
        usernames: List of usernames targeted by an IP address.
        timestamps: List of failed login attempt times.
        threshold: Minimum number of unique usernames required.
        time_window: Time window in seconds.

    Returns:
        True if a password spraying pattern is detected, otherwise False. 
    """

    combined = sorted(zip(timestamps, usernames))

    for i in range(len(combined) - threshold + 1):
        start_time = combined[i][0]
        end_time = combined[i + threshold - 1][0]

        difference = (end_time - start_time).total_seconds()

        if difference <= time_window:
            window_usernames = {
                username
                for _, username in combined [i: i + threshold]
            }

            if len(window_usernames) >= threshold:
                return True

    return False

def calculate_attempt_rate(attempts: int, timestamps: list[datetime]) -> float:
    """
    Calculates the average number of failed login attempts per minute.

    Args:
        attempts: Total number of failed login attempts.
        timestamps: List of datetime objects for the IP's attempts.

    Returns:
        Average failed login attempts per minute. 
    """

    duration = (timestamps[-1] - timestamps[0]).total_seconds()

    if duration == 0:
        return float(attempts)
    
    minutes = duration / 60
    rate = attempts / minutes

    return round(rate, 2)

def calculate_risk_score(attempts: int, brute_force: bool, password_spray: bool, attempt_rate: float) -> int:
    """
    Calculates a risk score based on multiple attack indicators.

    Args:
        attempts: Total failed login attempts.
        brute_force: Whether brute-force behavior was detected.
        password_spray: Whether password spraying was detected.
        attempt_rate: Average failed login attempts per minute.

    Returns:
        An integer risk score.
    """

    score = 0

    if brute_force:
        score += 2

    if password_spray:
        score += 2

    if attempts >= 10:
        score += 1

    if attempt_rate >= 20:
        score += 1

    return score

def get_severity(risk_score: int) -> str:
    """
    Converts a risk score into a security level.

    Args:
        risk_score: Calculated risk score.

    Returns:
        Security level as a string.
    """

    if risk_score >= 6:
        return "Critical"

    if risk_score >= 4:
        return "High"

    if risk_score >= 2:
        return "Medium"

    else:
        return "Low"

def calculate_attack_duration(timestamps: list[datetime]) -> str:
    """
    Calculates the duration of an attack.

    Args:
        timestamps: List of failed login attempt timstamps.

    Returns:
        Attack duration as a human-readable string.
    """

    duration = (timestamps[-1] - timestamps[0]).total_seconds()

    hours = int(duration // 3600)
    minutes = int((duration % 3600) // 60)
    seconds = int(duration % 60)

    if hours > 0: 
        return f"{hours} hour(s), {minutes} minute(s), {seconds} second(s)"

    elif minutes > 0:
        return f"{minutes} minute(s), {seconds} second(s)"

    else:
        return f"{seconds} second(s)" 

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
        brute_force = is_brute_force(timestamps, threshold = 3, time_window = 60)   
        attempt_rate = calculate_attempt_rate(attempts, timestamps)
        attack_duration = calculate_attack_duration(timestamps)
        password_spray = is_password_spray(usernames, timestamps, threshold = 3, time_window = 60)
        risk_score = calculate_risk_score(attempts, brute_force, password_spray, attempt_rate)
        severity = get_severity(risk_score)
        unique_usernames = ", ".join(set(usernames))

        print(f"IP Address: {ip}")
        print(f"Failed Attempts: {attempts}")
        print(f"Attempts per Minute: {attempt_rate}")
        print(f"Attack Duration: {attack_duration}")
        print(f"Severity: {severity}")
        print(f"Password Spray Detected: {password_spray}")
        print(f"Targeted User(s): {unique_usernames}")
        print(f"Brute-Force Detected: {brute_force} ")
        print(f"Risk Score: {risk_score}")
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

if __name__ == "__main__":
    main()