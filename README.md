# Email-Phishing-Analysis

## Introduction

Email phishing remains one of the most prevalent methods attackers use to gain unauthorized access to systems and sensitive information. This project demonstrates how a controlled cybersecurity lab environment can be used to analyze and respond to a phishing attack scenario. Using tools such as Notepad++, CyberChef, and HxD, I focused on decoding email headers, identifying malicious attachments, and understanding the tactics employed by attackers.

## Scenario

In this project, I analyzed an email phishing scenario provided in a CTF lab environment called "The Planet's Prestige," hosted on Blue Team Cyber Range. The challenge simulated a phishing email received by an Army Major stationed on Earth. The malicious email included encoded Base64 content, disguised attachments, and suspicious metadata, demanding a ransom for the safe return of abducted individuals. 

### Skills Learned

- Email Header Analysis
  - Decoding email headers to understand sender authenticity and delivery paths.
  - Identifying mismatched "From" and "Reply-To" fields, failed SPF, and DKIM records as red flags for phishing.

- Base64 Decoding
  - Using tools like CyberChef to decode Base64-encoded email content and attachments.
  - Analyzing the extracted files for additional clues and hidden messages.

- File Signature Verification
  - Cross-verifying file extensions with their hexadecimal signatures to identify disguised files (e.g., ZIP files labeled as PDFs).

- Malware Analysis in Isolated Environments
  - Extracting and examining suspicious files within a secure virtual machine to avoid impacting the host system.

### Tools Used

- Notepad++
- CyberChef
- HxD (Hex Editor)
- VirtualBox
- Metadata Analysis Tools (e.g., ExifTool)

## Steps

#### Step 1: Email Analysis

1. Examination of Email Headers:
  - Inspected headers to identify the sender's authenticity, email server path, and authentication statuses such as SPF, DKIM, and DMARC.
![Ref 1  spf does not permit](https://github.com/user-attachments/assets/f196a4eb-aee9-4d93-aad8-80a6e6ecd668)
Ref 1. SPF does not recognize the IP and domain as a permitted sender.

![Ref 2  from and reply to](https://github.com/user-attachments/assets/ca5dd3e4-0130-4908-be14-df2c005b9954)

Ref 2. The from and reply to emails are different

![Ref 9  recieved from fake email](https://github.com/user-attachments/assets/94da17a5-cb89-4206-a6b0-bb1b76ca7ade)
![Ref 10  recieved from fake email](https://github.com/user-attachments/assets/52ecbfcb-ccb3-455c-a268-59d23e3f9ec7)

Ref 3. recognized emkei as a fake email host

2. Decoded Base64 Content:
  - Used CyberChef to decode the email body and attachments. The email body contained a ransom demand along with a clue encoded as Base64.
![Ref 4  decoded email](https://github.com/user-attachments/assets/e687e929-286e-4a2e-ba7b-dfaced4e91e9)
Ref 4. Decoded email using CyberChef

#### Step 2: Attachment Analysis

1. File Signature Verification:
  - Verified the attachments' true file types using hexadecimal signatures, revealing a ZIP file disguised as a PDF.
![Ref 6  Decoded pdf puzzle](https://github.com/user-attachments/assets/78690662-63af-4682-a11c-36aecbba8fb4)
Ref 5. Decoded attachment in email and their hexadecimal signature

![Ref 7  file is zip not pdf](https://github.com/user-attachments/assets/b44bcda4-400c-468e-8ca5-10ffb45b3e6d)
Ref 6. This shows that the attachment is a Zip file not a Pdf as said in the email


#### Step 3: Detecting Port Scanning Activity
1. Examined conversation details under the IPv4 and TCP tabs.
2. Noted that source IP 10.251.96.4 consistently targeted multiple ports on 10.251.96.5, with the same source port (41675) being used repeatedly.
    - This consistent behavior strongly indicated port scanning activity.

![Detecting Port Scanning Activity](https://github.com/user-attachments/assets/88084fba-6521-437b-8f31-3e0563a2795d)
Ref 3. Detecting Port Scanning Activity.


#### Step 4: HTTP Stream Analysis
1. Investigated an HTTP POST request from packet 38.
2. Reconstructed the HTTP stream and discovered a login attempt with credentials:
    - Username: admin
    - Password: Admin@1234
3. Decoded special characters (e.g., %40 → @) to interpret the full password.
4. Observed that the login occurred over HTTP instead of HTTPS, indicating insecure communication.

![Ref 4  Explore post request](https://github.com/user-attachments/assets/04fdd3a4-8485-4557-8e49-6ee4c9d6c294)
Ref 4. Investigated an HTTP POST request.


#### Step 5: Identifying Attack Tools
1. Recognized the use of Gobuster v3.0.1, a directory brute-forcing tool, from the user agent string.
2. Detected SQLmap v1.4.7, an automated SQL injection tool, used for unauthorized database access attempts.
![Ref 6  Exploring a GET request on a packet we notice the user agent as gobuster](https://github.com/user-attachments/assets/ce8aff31-5470-4e2e-8ebc-b3de869f1b03)
Ref 5. Recognized the use of Gobuster v3.0.1

![Ref 8  Noticed another user agent sqlmap](https://github.com/user-attachments/assets/4ded5263-eedb-4171-963f-d4777fd83110)
Ref 6. Detected SQLmap v1.4.7

![Ref 9  An SQL attack following](https://github.com/user-attachments/assets/83ad6804-cbce-4537-8911-24cadead71aa)
Ref 7. An SQL Attack detected

#### Step 6: Web Shell Analysis
1. Analyzed a callback from 10.251.96.5 to 10.251.96.4 on port 4422, which occurred during the attack.
2. Reconstructed the TCP stream to identify the upload of a malicious web shell (db_functions.php).
3. Observed attacker commands executed on the compromised server:
    - whoami, cd, ls: Discovery commands.
    - python: Used to establish a reverse shell.
    - rm db: Attempted file removal.

![Ref 10  successful webshell](https://github.com/user-attachments/assets/c931497d-2e18-46df-8af1-fd02e14ceed2)
Ref 8. Web Shell Analysis

## Practical Applications and Organizational Benefits

#### 1. Threat Detection and Incident Response
SOC teams can use similar techniques to identify malicious activities like port scanning, unauthorized logins, and web shell uploads in their environments.

#### 2. Malicious Tool Recognition
Understanding tools like Gobuster and SQLmap enhances the ability to detect and mitigate automated attacks.

#### 3. Post-Attack Forensics
Reconstructing attacker activity enables organizations to identify vulnerabilities and strengthen defenses.

#### 4. Skill Development
Hands-on analysis of PCAP files provides real-world experience with network monitoring tools and techniques.


## Conclusion 
Through this project, I analyzed malicious network activity, identified attack patterns, and gained valuable experience with incident response. This exercise reinforced the importance of traffic analysis and the ability to detect, investigate, and respond to cybersecurity threats effectively.
