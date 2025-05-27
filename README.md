# Phishing Email Analysis Report

## Task Objective

The goal of this task is to analyze a sample phishing email and identify key characteristics that indicate it's a phishing attempt. This helps in building awareness of email-based cyber threats and improving threat detection skills.

## Phishing Indicators

1. Spoofed Sender Address: The email is from `support@paypa1.com` instead of the legitimate `paypal.com`.
2. Urgent Language: The message pressures the user to "verify immediately" or face "account suspension."
3. Suspicious Link: The hyperlink points to `http://fake-paypal-verify.com`, not a secure or official domain.
4. Generic Greeting:Uses "Dear Customer" instead of the user's actual name.
5. Grammatical Errors: Minor issues in sentence structure and punctuation.
6. Lack of Personalization: No reference to any user account details.

 ## Email Header Analysis

Used MxToolbox to analyze headers. Found:
- Return-Path and Reply-To addresses differ from sender address.
- SPF and DKIM validation failed.
## Tools Used

- MxToolbox Email Header Analyzer (https://mxtoolbox.com/EmailHeaders.aspx)
- VirusTotal (https://www.virustotal.com/) (for scanning suspicious links or attachments)
-  PhishTank (https://www.phishtank.com/) (for phishing sample)
   
## Conclusion

The analyzed email demonstrates several common phishing techniques including spoofed sender addresses, urgency, and fake login links. Awareness of these traits is crucial in identifying and avoiding phishing attempts. Regular training and careful inspection of email elements can greatly enhance security posture.
