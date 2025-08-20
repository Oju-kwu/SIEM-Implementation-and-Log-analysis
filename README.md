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

This query allowed us to aggregate and rank the number of connection attempts by remote hosts (rhost). Based on the results, we identified approximately 15 unusual IP addresses exhibiting abnormal behavior or access patterns, indicating potential unauthorized access attempts or brute-force activities. These findings were further analyzed to support alert configurations and dashboard visualizations for proactive monitoring.

<img width="1887" height="790" alt="Screenshot 2025-08-20 152949" src="https://github.com/user-attachments/assets/e310ad29-e1d7-44f1-9331-b2c60e33c4d5" />

## Analysis by Timestamp
Further analysis done breaks the event by timestamps into 5-minute and group the events that occurred within the same 5-minute window, counts how many events like failed login attempts each remote host (rhost) generated per 5-minute window and filters only those IPs that attempted access more than 5 times in any 5-minute window then sorts the output in descending order by time (latest attempts first).

<img width="1883" height="801" alt="Screenshot 2025-08-20 154018" src="https://github.com/user-attachments/assets/a9481fb6-face-4e4c-901c-3ff1b3555e66" />

<img width="1889" height="771" alt="Screenshot 2025-08-20 153942" src="https://github.com/user-attachments/assets/25f6bcc5-68dd-40ab-a1d5-f233e78789ce" />

Clearer insights into the activities of the above image shows IP 183.62.140.253 is highly aggressive showing 129-141 login attempts within just 5-minute intervals. IPs like 103.99.0.122, 187.141.143.180, and 112.195.230.3 are also showing repeated attempts which is possibly a brute-force or scanning activity.
These are not normal user behaviors and suggest potential malicious actors attempting SSH login brute-force attacks.
  
# Recommended Improvements:
● Block the sender domain (access-accsecurity[.]com) at the email gateway: This domain is not affiliated with Microsoft and was used to spoof the brand. Blocking this domain at the perimeter (Exchange Online Protection, Proofpoint, Mimecast, etc.) will prevent further emails from this sender from reaching user inboxes.

● Blacklist the originating IP address (89[.]144[.]44[.]41): This IP address belongs to a hosting provider (HostSailor) with a known history of abuse-related activity. Blacklisting this IP prevents future attempts from the same infrastructure and may help reduce similar attack vectors.
.
● Monitor for related campaigns or IOC matches (domains, IPs, headers): Use threat intel feeds or your SIEM to watch for similar Reply-To patterns, sender domains, or tracking pixel URLs (thebandalisty.com). Monitor for any other messages from the same ASN or IP block used in this campaign.

● Quarantine or auto-delete unauthenticated Microsoft-branded messages: Set conditional mail flow rules (Transport Rules / Mail Flow Rules) that quarantine or flag any message claiming to be from Microsoft.com or Outlook.com domains if they fail SPF, DKIM, or DMARC. This adds a defensive layer without outright blocking potentially legitimate external senders.

● Add detection rules for tracking pixels and beaconing links: Use a secure email gateway or a DLP/content filter to identify invisible <img> tags linked to remote third-party URLs. These are often used for tracking engagement or setting up further social engineering.

● Consider integrating a sandbox/detonation environment: If not already deployed, use a sandbox to detonate suspicious attachments or follow suspicious links. While this email was HTML-based and had no attachments, future variants may include weaponized files or redirect chains.

● Notify internal users and conduct phishing awareness reinforcement: Since the email mimics Microsoft account alerts, users may be susceptible to social engineering tactics. Circulating a short internal advisory with red flags from this case (e.g., Gmail reply address, unverified sender, Russia login bait) helps strengthen user awareness and reduce click risk.


# Conclusion
This email is a clear phishing attempt designed to impersonate Microsoft's account security alerts. Key indicators include the non-Microsoft sender domain (access-accsecurity.com), a Gmail Reply-To address, failed or missing email authentication (SPF, DKIM, DMARC), an anonymous authentication status within Exchange, a suspicious originating IP address from Germany, and a hidden tracking pixel from an unrelated domain. These findings confirm the email's malicious intent to socially engineer recipients and compromise their credentials. Immediate actions, such as blocking the sender domain and IP and enhancing email authentication checks, are recommended to mitigate risks and prevent future phishing attacks.


 

