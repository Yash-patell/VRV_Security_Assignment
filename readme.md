

# VRV Security’s Python Intern Assignment


This repository contains the solution for the Log Analysis Assignment for VRV Security's Python Intern role. The goal is to demonstrate proficiency in Python programming, focusing on file handling, data parsing, and log analysis, key skills for tackling cybersecurity challenges.


## Assignment Description
The Python script analyzes a sample web server log file (sample.log) to extract and process information. The script implements the following functionalities:

1.Count Requests per IP Address
- Extracts all IP addresses from the log file.
- Counts and sorts the number of requests made by each IP address.
- Displays the results in descending order of request count.


2.Identify the Most Frequently Accessed Endpoint
- Extracts and counts access frequencies of all endpoints (e.g., URLs).
- Identifies and displays the most frequently accessed endpoint along with its count.
- Detect Suspicious Activity


3.Flags potential brute force login attempts by analyzing failed login entries (HTTP 401 status or failure -messages like "Invalid credentials").
- Lists IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
- Save Results to CSV


4.Outputs the analysis to a CSV file (log_analysis_results.csv) with the following sections:
- Requests per IP
- Most accessed endpoint
- Suspicious activity


## Thankyou for reviewing this assignment!
