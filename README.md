### **Objective**

The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in **file handling**, **string manipulation**, and **data analysis**, which are essential skills for cybersecurity-related programming tasks.
### **Core Requirements**

Your Python script should implement the following functionalities:

1. **Count Requests per IP Address**:
    - Parse the provided log file to extract all IP addresses.
    - Calculate the number of requests made by each IP address.
    - Sort and display the results in descending order of request counts.
    - Example output:
    - IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
10.0.0.2             92
      Identify the Most Frequently Accessed Endpoint:
Extract the endpoints (e.g., URLs or resource paths) from the log file.
Identify the endpoint accessed the highest number of times.
Provide the endpoint name and its access count.
Example output:
Most Frequently Accessed Endpoint:
/home (Accessed 403 times)
Detect Suspicious Activity:
Identify potential brute force login attempts by:
Searching for log entries with failed login attempts (e.g., HTTP status code 401 or a specific failure message like "Invalid credentials").
Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
Display the flagged IP addresses and their failed login counts.
Example output:
Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        56
203.0.113.34         12
      4. **Output Results**:
    - Display the results in a clear, organized format in the terminal.
    - Save the results to a CSV file named `log_analysis_results.csv` with the following structure:
        - **Requests per IP**: Columns: `IP Address`, `Request Count`
        - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
        - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`
