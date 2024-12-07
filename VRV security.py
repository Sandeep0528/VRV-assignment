import csv
import re

def analyze_log(log_file, failed_attempt_threshold= 10):
    # Initializing dictionaries to store counts
    ip_counts = {}
    endpoint_counts = {}
    failed_logins = {}

   
    with open(log_file, 'r') as f:
        for line in f:
            
            ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            if not ip_match:
                continue  
            ip_address = ip_match.group()

            
            endpoint_match = re.search(r'\"(?:GET|POST) (.*?) HTTP', line)
            if not endpoint_match:
                continue  
            endpoint = endpoint_match.group(1)

            
            status_code_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
            if not status_code_match:
                continue  
            status_code = int(status_code_match.group(1))

            
            ip_counts[ip_address] = ip_counts.get(ip_address, 0) + 1

           
            endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

            
            if status_code == 401:
                failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

   
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get)
    sorted_failed_logins = sorted(
        [(ip, count) for ip, count in failed_logins.items() if count > failed_attempt_threshold],
        key=lambda x: x[1], reverse=True)

   
    print("IP Address".ljust(20) + "Request Count")
    for ip, count in sorted_ip_counts:
        print(f"{ip.ljust(20)}{str(count).rjust(10)}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {endpoint_counts[most_accessed_endpoint]} times)")

   
    print("\nSuspicious Activity Detected:")
    print("IP Address".ljust(20) + "Failed Login Attempts")
    for ip, count in sorted_failed_logins:
        if count > failed_attempt_threshold:
            print(f"{ip.ljust(20)}{str(count).rjust(10)}")

    # Writing results to CSV file
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        
        csv_writer.writerow(['IP Address', 'Request Count'])
        csv_writer.writerows(sorted_ip_counts)

        csv_writer.writerow([])  # Add an empty row for separation

       
        csv_writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        csv_writer.writerow([most_accessed_endpoint, endpoint_counts[most_accessed_endpoint]])

        csv_writer.writerow([])

        
        csv_writer.writerow(['IP Address', 'Failed Login Attempts'])
        csv_writer.writerows(sorted_failed_logins)


analyze_log(r"C:\VRV assignment\sample.log")
