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


 

