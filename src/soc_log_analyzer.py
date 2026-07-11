def analyze_logs(filepath: str) -> dict[str, int]: 
    """
    Reads an authentication log file and counts failed login attempts for each IP address.

    Args:
    filepath: Path to the authentication log file.

    Returns:
    A dictionary where the keys are the IP addresses and the values are the number of failed login attempts for each IP.
    """
    try:
        with open(filepath ,"r") as file:
            content = file.readlines()

    except FileNotFoundError:
        print(f"Error: Log file '{filepath}' was not found!.")
        return {}

    failed_ips = {}

    for line in content:
        line = line.strip()

        if "Failed password" in line:
            parts = line.split()
            from_index = parts.index("from")
            ip = parts[from_index + 1]

            if ip not in failed_ips:
                failed_ips[ip] = 1
            else:
                failed_ips[ip] += 1

    return failed_ips

def print_report(failed_ips: dict[str, int]) -> None:
    """
    Prints a summary report of failed login attempts by IP address and shows how many unique attacking IPs were there.

    Args:
    failed_ips: Dictionary containing IP addreses and their corresponding failed login attempts count.

    Returns:
    None.

    """
    print("=== FAILED LOGINS REPORT === ")
    
    for ip in failed_ips:
        print(f"{ip} : {failed_ips[ip]} attempts")
        
    print(f"Total unique attacking IPs: {len(failed_ips)}")

def print_alerts(failed_ips: dict[str, int], threshold: int) -> None: 
    """
    Prints an alert for every IP address whose failed login attempts meet or exceed the threshold value.

    Args:
    failed_ips: Dictionary containing IP addreses and their corresponding failed login attempts count.
    threshold: Minimum number of failed attempts required to trigger an alert.

    Returns:
    None.
    """
    print("=== ALERTS ===")
    
    for ip in failed_ips:
        if failed_ips[ip] >= threshold:
            print(f"⚠ {ip} exceeded the threshold ({failed_ips[ip]} attempts)")

def find_most_suspicious_ip(failed_ips: dict[str, int]) -> tuple[str, int]:
    """
    Finds the IP address with the highest number of failed login attempts.

    Args:
    failed_ips: Dictionary containing IP addreses and their corresponding failed login attempts count.

    Returns:
    A tuple containing the most suspicious IP address and its failed login attempt count.
    """
    max_attempts = 0
    most_suspicious_ip = ""
    for ip in failed_ips:
        if failed_ips[ip] > max_attempts:
            max_attempts = failed_ips[ip]
            most_suspicious_ip = ip

    return most_suspicious_ip, max_attempts

def main() -> None:
    log_file = "logs/sample_auth.log"
    threshold = 3
    
    failed_ips = analyze_logs(log_file)
    
    print_report(failed_ips)
    print()
    print_alerts(failed_ips, threshold)

    ip, attempts = find_most_suspicious_ip(failed_ips)

    print(f"Most Suspicious IP: {ip}")
    print(f"Attempts: {attempts}")

main()