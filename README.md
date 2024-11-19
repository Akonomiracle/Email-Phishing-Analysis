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

2. Extracting Contents:
  - Analyzed extracted files (a JPEG image, a PDF file with instructions, and an Excel file with hidden Base64 content).

3. Decoding Hidden Content:
  - Decoded the Base64 string in the Excel file, revealing the attacker’s location as "The Martian Colony."
![Ref 8  decoded message from ransome puzzle](https://github.com/user-attachments/assets/73ed5016-004f-41b7-aa09-90a5153fcae3)
Ref 7. Attackers location

#### Step 3: Connecting Metadata to the Attacker
1. Metadata Analysis:
  - Used ExifTool to examine the files’ metadata, identifying the author's name and possible links to the phishing campaign.

#### Step 4: Reporting Findings
1. Compiled findings to trace the attacker's methods and potential command-and-control (C2) domain.


## Practical Applications and Organizational Benefits

#### 1. Phishing Attack Identification
Enhanced understanding of how to detect phishing attempts using email headers, authentication results, and suspicious file behaviors.

#### 2.Malware Containment in Secure Labs
Safe analysis of potentially malicious attachments prevents organizational network compromise.

#### 3. Cyber Threat Awareness
Improved ability to identify and respond to phishing attempts, a critical skill for SOC analysts.

#### 4. Efficient Incident Reporting
Documented findings and recommendations in a clear, actionable format for organizational benefit.


## Conclusion 
By completing this project, I developed a robust foundation in phishing email analysis, Base64 decoding, and file signature verification. This practical experience is essential for identifying and mitigating phishing attacks in real-world scenarios, protecting organizations from significant security threats.


## Report of Findings and Recommendations
### Findings

#### 1. Email Header Analysis:
  - The sender's email address was spoofed using a fake email service.
  - The SPF check failed, and the "From" and "Reply-To" fields did not match, indicating malicious intent.

#### 2. Encoded Attachments:
  - Attachments were disguised with misleading extensions and contained hidden Base64 data.
  - Metadata linked the attachments to the attacker, confirming their role in the phishing campaign.

#### 3. Command-and-Control Domain:
  - The domain "pasto.com" was identified as the probable C2 domain for the attacker’s bots.


### Recommendations

#### 1. Strengthen Email Security Measures:
  - Implement DMARC, SPF, and DKIM protocols across the organization to prevent domain spoofing.
  - Configure email gateways to flag emails with mismatched headers or failed SPF checks.

#### 2. Educate Employees on Phishing Awareness:
  - Conduct regular training sessions on identifying phishing attempts, focusing on red flags in email headers and suspicious attachments.

#### 3. Establish a Secure Analysis Environment:
  - Use isolated virtual machines for malware analysis and suspicious file handling to protect the organization’s network.

#### 4. Deploy Endpoint Detection and Response (EDR):
  - Install EDR solutions to monitor and block communication with known malicious C2 domains.

#### 5. Regularly Audit Email Infrastructure:
  - Review and update email filtering policies to adapt to evolving phishing tactics.

By implementing these measures, the organization can enhance its resilience against phishing attacks and protect its critical assets.
