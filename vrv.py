import re
import csv
from collections import defaultdict
import logging

# Set up logging
logging.basicConfig(filename='log_analysis.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def parse_log_line(line):
    try:
        ip_match = re.match(r'(\d{1,3}\.){3}\d{1,3}', line)
        endpoint_match = re.search(r'\"[A-Z]+\s(/[\w\-/\.\?=&]*)\s', line)
        status_match = re.search(r'\s(\d{3})(?:\s|$)', line)

        ip = ip_match.group(0) if ip_match else None
        endpoint = endpoint_match.group(1) if endpoint_match else None
        status = int(status_match.group(1)) if status_match else None

        return ip, endpoint, status
    except Exception as e:
        logging.error(f"Error parsing line: {line.strip()}. Error: {e}")
        return None, None, None

# Function to count requests by IP
def count_requests_by_ip(log_lines):
    ip_counts = defaultdict(int)
    for line in log_lines:
        ip, _, _ = parse_log_line(line)
        if ip:
            ip_counts[ip] += 1
    return ip_counts

# Function to determine the most frequent endpoint
def most_frequent_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        _, endpoint, _ = parse_log_line(line)
        if endpoint:
            endpoint_counts[endpoint] += 1
    if endpoint_counts:
        return max(endpoint_counts.items(), key=lambda x: x[1])
    return None


# Function to detect suspicious activity
def detect_suspicious_activity(log_lines, threshold=10, failure_patterns=None):
    if failure_patterns is None:
        failure_patterns = ['401', 'Invalid credentials']
    failed_logins = defaultdict(int)

    for line in log_lines:
        try:
            ip, _, status = parse_log_line(line)
            if ip and str(status) in failure_patterns:
                failed_logins[ip] += 1
        except Exception as e:
            logging.error(f"Error processing line for suspicious activity: {line.strip()}. Error: {e}")

    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= threshold}
    return suspicious_ips


# Function to save results to a CSV file
def save_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips):
    try:
        with open("log_analysis_results.csv", mode="w", newline="") as csvfile:
            writer = csv.writer(csvfile)

            
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow([ip, count])

            writer.writerow([])

            writer.writerow(["Most Accessed Endpoint"])
            if most_accessed_endpoint:
                writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
            else:
                writer.writerow(["None", "0"])

            writer.writerow([])

            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
    except Exception as e:
        logging.error(f"Error saving to CSV: {e}")

def analyze_logs(file_path, threshold=10):
    try:
        with open(file_path, 'r') as file:
            log_lines = file.readlines()

        
        ip_counts = count_requests_by_ip(log_lines)

        most_accessed_endpoint = most_frequent_endpoint(log_lines)

        # Detect suspicious activity
        suspicious_ips = detect_suspicious_activity(log_lines, threshold)

        
        print("Requests per IP:")
        print(f"{'IP Address':<20} {'Request Count':<15}")
        print("=" * 35)
        for ip, count in ip_counts.items():
            print(f"{ip:<20} {count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        if most_accessed_endpoint:
            print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
        else:
            print("No endpoints found.")

        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Count':<20}")
        print("=" * 45)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")

        # Save results to CSV
        save_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips)
        print("\nResults saved to 'log_analysis_results.csv'.")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except PermissionError:
        print(f"Error: Permission denied when trying to read '{file_path}'.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    log_file_path = "./sample.log"  #sample log file
    analyze_logs(log_file_path, threshold=3)
