# SIEM-Implementation-and-Log-analysis
## Executive Summary
Our organization recently experience few suspicious incidence and our team was tasked with analyzing an OpenSSH Log file to help identify potential security threat to the organization, main objectives include the identification and monitoring of suspicious activities such as unusual IP addresses, multiple failed login attempts, and other indicators of potentialsecurity issues. 

Splunk Cloud was deployed and Log file uploaded with a suspicious pattern identified, through the analyses we found several Authentication failures, Invalid user access attempts, repeated login failures (e.g., from 183.62.140.253), Disconnect messages (e.g., Bye Bye [preauth]) with multiple IP addresses with high event counts from different geolocations. The behavior of this log file confirms a brute-force attempts via automated scanning botnet or unauthorized probes. 

A dashboard and an ALERT system was created with certain conditions to visualize, detects and trigger any potential brute-force or unauthorized access attempts. In addition, user roles were created and reviewed in line with the principle of least privilege.

# Objective
- Create user account for the team
- Analyze the provided OpenSSH logsforsuspicious behavior
- Detect any unusual IP addresses
- Detect multiple failed login attempts
- Create a dashboard for real-time monitoring
- Set up automated alertsfor critical events.
- As well as extracting a field.

### Methodology
## User Creation and Role Management
Users account were created within the Splunk Cloud environment showing the roles and access
capabilities of members, 2 users have Admin privilege, 7 users with power role and 1 with user’s
role.
The aim is to ensure proper access control, validate role assignments, and support internal audits
or compliance efforts.
## During accountsetup:
The Time Zone for each user was configured to West Africa Time (WAT) to maintain consistency
in event timestamps.
The default application was set to Launcher (Home) for a uniform user interface experience upon
login.
Password Policy was enforced to mandate password changes upon first login, enhancing account
security.

<img width="1901" height="825" alt="Screenshot 2025-08-20 145656" src="https://github.com/user-attachments/assets/58e3bb0d-c424-4bb9-bb17-fadc9a65b058" />

## Analysis of OpenSSH Log File
The OpenSSH file was manually uploaded to Splunk Cloud which is crucial for managing and
searching data effectively with the following parameters
Source= OpenSSH.csv (the origin or where splunk gets it data from either a file or directory)
Sourcetype = csv (the format, structure or how splunk data is parse or understood in this case,
comma separated value was used)
Index = main (where Splunk stores the data like a database or folder)

<img width="1868" height="800" alt="Screenshot 2025-08-20 150849" src="https://github.com/user-attachments/assets/ba1f85ef-0746-441c-bc19-4f87c347ad8c" />

The analysis contains 2,000 event with key observation features like Failed Logins Attempts, Disconnection event, external IP, Timestamp and IP Locations.

<img width="1901" height="843" alt="Screenshot 2025-08-20 151107" src="https://github.com/user-attachments/assets/1b06c8d8-e40b-4608-a72b-bc45dbcfe87f" />

<img width="1902" height="803" alt="Screenshot 2025-08-20 152011" src="https://github.com/user-attachments/assets/cfccf445-2d28-494d-831f-2dc75d88767b" />

## Analysis by Multiple Failed Attempts
To identify the IP addresses (rhost) responsible for the highest number of failed SSH login attempts and assess potential brute-force or reconnaissance behavior.
The following command was ran and the interpretation given below;
index="main" source="OpenSSH SIEM.csv" "authentication failure"
| rex "rhost=(?<rhost>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by rhost
| where count > 5
| sort –count
183.62.140.253 is the most active attacker, accounting for 57.8% of the total 496 failed attempts. All the IPs from the 183.62.140.x subnet collectively contributed 431 attempts which suggest a coordinated scanning or attack from a botnet or single actor using multiple IPs, Repeated IPs andconsistent failure rates point to brute-force activity.

<img width="1899" height="791" alt="Screenshot 2025-08-20 152559" src="https://github.com/user-attachments/assets/5478f81c-c943-4d8f-8dbc-9afc10234284" />

## Unusual IP Address Detection
To identify suspicious or unusual IP addresses attempting to access our
infrastructure, we used the following Splunk SPL query:
index="main" source="OpenSSH.csv" "authentication failure"
| rex "rhost=(?<rhost>\d{1,3}(?:\.\d{1,3}){3})"
| stats count by rhost
| where count <= 5
| sort -count

<img width="1887" height="790" alt="Screenshot 2025-08-20 152949" src="https://github.com/user-attachments/assets/e310ad29-e1d7-44f1-9331-b2c60e33c4d5" />

This query allowed us to aggregate and rank the number of connection attempts by remote hosts (rhost). Based on the results, we identified approximately 15 unusual IP addresses exhibiting abnormal behavior or access patterns, indicating potential unauthorized access attempts or brute-force activities. These findings were further analyzed to support alert configurations and dashboard visualizations for proactive monitoring.

## Analysis by Timestamp
Further analysis done breaks the event by timestamps into 5-minute and group the events that occurred within the same 5-minute window, counts how many events like failed login attempts each remote host (rhost) generated per 5-minute window and filters only those IPs that attempted access more than 5 times in any 5-minute window then sorts the output in descending order by time (latest attempts first).

<img width="1883" height="801" alt="Screenshot 2025-08-20 154018" src="https://github.com/user-attachments/assets/a9481fb6-face-4e4c-901c-3ff1b3555e66" />

<img width="1889" height="771" alt="Screenshot 2025-08-20 153942" src="https://github.com/user-attachments/assets/25f6bcc5-68dd-40ab-a1d5-f233e78789ce" />

Clearer insights into the activities of the above image shows IP 183.62.140.253 is highly aggressive showing 129-141 login attempts within just 5-minute intervals. IPs like 103.99.0.122, 187.141.143.180, and 112.195.230.3 are also showing repeated attempts which is possibly a brute-force or scanning activity.
These are not normal user behaviors and suggest potential malicious actors attempting SSH login brute-force attacks.

## Analysis by Geolocation
A total of 496 failed SSH authentication attempts were identified from non-Nigerian IP addresses with source IPs mapped to countries known for botnet or brute-force activity. These attempts represent a potential external brute-force attack pattern targeting our infrastructure. China is the top source country with over 300 combined attempts from multiple cities (Beijing, Shenzhen, Weifang, Langfang). Mexico and Vietnam also show a substantial volume of attempts. The data was filtered to exclude
internal/Nigerian IPs suggesting these are likely unauthorized foreign entities.  

<img width="1891" height="801" alt="Screenshot 2025-08-20 160640" src="https://github.com/user-attachments/assets/9ebfd664-7573-45b0-805d-483f30694827" />

<img width="1884" height="782" alt="Screenshot 2025-08-20 160821" src="https://github.com/user-attachments/assets/9a35c70b-aad4-4811-b862-4bae826fd0b4" />

## Analysisi by Users
Analyses was done for failed SSH login attempts in the OpenSSH logs to identify the most frequently targeted usernames. The report states root was the primary target accounting for 74.3%nof all failed attempts. Other usernames like uucp, ftp, mysql, and git are common service accounts. The heavy targeting of root suggests an active brute-force attack aiming for administrative access. Attempts on service accounts indicate automated scans or credential stuffing using known
usernames. These patterns are typical of external threat actors probing for vulnerable systems.

<img width="1881" height="762" alt="Screenshot 2025-08-20 161539" src="https://github.com/user-attachments/assets/7f3c3086-584c-41e3-9532-c061734e1eda" />

## Dashboard Configuration
A Dashboard was created to monitor and give early warning sign to a high frequency logs of disconnects initiated from the malicious IP addresses. The repetitive pattern and timing suggest that a system likely external is attempting to establish SSH connections and being disconnectedrepeatedly before authentication ([preauth]). The disconnection messages are consistent, indicating potential scanning or brute-force attack behavior.

<img width="1823" height="702" alt="Screenshot 2025-08-20 163812" src="https://github.com/user-attachments/assets/64978452-d025-489b-90f9-27256a9636fc" />

## Alert Configuration
To complement the dashboard, an automated alert system was configured with the following settings:
- Schedule: Runs daily at 8:00 AM (WAT).
- Alert Expiration: Set to expire after 24 hours.
-  Trigger Condition: Fires when the number of matching results is greater than 2.
-  Notification Type: Sent via plain text email.
-  Recipients: All Group 4 members were added as recipients to ensure
collective visibility.
-  Domain Restriction: Splunk was configured to only allow emails to be sent
to a specific domain (e.g., gmail.com) to enhance security and limit alert
delivery to approved users.

This alert is designed to monitor and automatically detect suspicious SSH disconnect events which could indicate Brute-force attack attempts (automated login failures), Network scanning or reconnaissance activity Abuse from malicious IP addresses (bots or unauthorized users), Unexpected session terminations on critical servers.

<img width="1916" height="462" alt="Screenshot 2025-08-20 172748" src="https://github.com/user-attachments/assets/54c095ea-5b3c-48d7-9c12-4e54e6b5d4d4" />

<img width="1887" height="548" alt="Screenshot 2025-08-20 182959" src="https://github.com/user-attachments/assets/e5c7eeef-b350-4e1f-8978-6e04229296fb" />

## Field Extraction Configuration
A custom field (src_ip) was created and extracted to store the IP 183.62.140.253. The src_ip fielis crucial for tracking source hosts in SSH disconnect events and ensure the IP is constantly tagged for correlation, reporting and alerting, it provides actionable intelligence about suspicious SSH activity and inform automated defenses, blacklists, and SIEM correlation rules. Splunk identified 867 events generated by this IP, covering 99.95% of all events in the dataset.

<img width="1883" height="798" alt="Screenshot 2025-08-20 184044" src="https://github.com/user-attachments/assets/20031fbf-340d-41fa-8c06-fd759570ccac" />

<img width="1914" height="833" alt="Screenshot 2025-08-20 184913" src="https://github.com/user-attachments/assets/a8f28426-ae77-4ebc-86e1-5e3fd6dd58b4" />

## Conclusion
The analysis of the OpenSSH.csv logs through Splunk has revealed a high number of failed SSH authentication attempts primarily from a concentrated group of external IP addresses like 183.62.140.253 from Beijing China as the top offender with 285 login failures, several other IPs from the same subnet were also active suggesting automated or coordinated attack attempts likely brute-force in nature. Attempts were mainly directed at privileged accounts like root accounting for 74% of the total failed logins 369 out of 496, The source of attacks includes countries such as China, Mexico, Vietnam, Russia, and the United States, indicating global threat
vectors targeting the system. These patterns are typical of credential stuffing, dictionary attacks, or brute force login attempts, and if not mitigated could lead to unauthorized system access and compromise of critical infrastructure.

## Recommendation
To enhance the security of your SSH service and prevent unauthorized access, this should be implemented:
1. Immediate Mitigation: Block/Blacklist Malicious IPs using firewall rules to block high-risk IPs like 183.62.140.253 Disable Root Login In
2. Access Hardening: Enable Rate Limiting: Deploy fail2ban or sshguard to automatically block IPs with multiple failed attempts.
Restrict Access via Geo-IP: Implement IP filtering to block SSH access from high-rise countries unless necessary for operations. Use SSH Keys Instead of Passwords: Enforce public key authentication for all users to eliminate password-based attacks.
3. Account Security: Enforce Strong Password Policies: Require complex passwords and change them
periodically Limit SSH Access to Specific Users: Use AllowUsers or AllowGroups in SSH configuration.
