# What is URLShield?
URLShield is a python tool which is designed to catch malicious activities and vulnerabilities in the URL. I designed this project back in 2024 while being in my class 12th. <br>
I was interested in making a project related to Computer Networks and the DNS System. <br>
Therefore, I decided to work on this tool as I was already good in Python and some of its libraries. <br>

# How it works?
The goal of this project is to demonstrate how phishing URLs can be identified through simple but effective cybersecurity principles. <br>
The detector examines several characteristics of a URL such as: <br>
-Raw IP address usage <br>
-Suspicious domain structures <br>
-Brand impersonation attempts <br>
-URL shorteners <br>
-Non-standard ports <br>
-Missing HTTPS <br>
-Excessive subdomains <br>
-Suspicious Top-Level Domains (TLDs) <br>

Each detected indicator contributes risk points to an overall score, allowing the tool to classify URLs as: <br>
Low Risk ✅ <br>
Suspicious ⚠️ <br>
High Risk 🚨 <br>
<br>
The detector evaluates a URL against multiple cybersecurity rules and each triggered rule adds a predefined number of risk points. <br>
The total score is capped at 100 points. <br>
<br>
| Score    | Verdict    |
| -------- | ---------- |
| 0 - 19   | LOW RISK   |
| 20 - 49  | SUSPICIOUS |
| 50 - 100 | HIGH RISK  |

Risk Scoring System: <br>
| Vulnerability Detected           | Points |
| -------------------------------- | ------ |
| Raw IP Address instead of domain | +30    |
| '@' Symbol in URL                | +25    |
| Brand Impersonation              | +25    |
| Excessive Subdomains             | +15    |
| Suspicious TLD (.tk, .xyz, etc.) | +15    |
| Known URL Shortener              | +15    |
| Non-Standard Port                | +12    |
| Multiple Hyphens in Domain       | +10    |
| Missing HTTPS                    | +10    |
| Unusually Long URL               | +8     |

# How to use this tool?
It's so simple to use this tool. All you have to do is to download and run the attached .py file in your desired terminal.
```bash
python3 urlchecker.py
```
As soon as the file runs. You see the following section appear which asks you to enter your URL.
```bash
Phishing / suspicious URL checker. Type 'quit' to exit.
Enter a URL to scan:
```
## Sample Run
Let's try by providing a simple URL i.e. "amazon-account-verify-secure.xyz".

```bash
Enter a URL to scan: amazon-account-verify-secure.xyz

==================================================
URL checked : amazon-account-verify-secure.xyz
Host        : amazon-account-verify-secure.xyz
Risk score  : 60/100
Verdict     : HIGH RISK
==================================================

Flags raised:

  [+25] A known brand name appears in the domain, but the domain isn't actually that brand's.
  [+15] Uses a top-level domain that's disproportionately common in phishing campaigns.
  [+10] Multiple hyphens in the domain — often used to mimic a real brand name.
  [+10] No HTTPS — not definitive alone, but most legitimate sites use it today.
```  

# Thank You For Reading.
## Author- Lalit Sharma
