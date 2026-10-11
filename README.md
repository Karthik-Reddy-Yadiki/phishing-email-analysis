# Phishing Email Analysis

SOC-style analysis of four real-world emails from the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot) dataset. Three malicious emails were linked to a single spam campaign, and one flagged email was identified as a false positive.

## Key Findings
- **One campaign, three lures:** a prize scam, a fake health product (Dutch) and a casino bonus, all sent within about 80 minutes on 8 July 2026 from throwaway Microsoft 365 tenants via the Gmail API, sharing hidden filter-evasion text and the same tracking-link structure.
- **Forged headers:** one email contained headers copied from a legitimate marketing platform (Klaviyo) to look like normal newsletter traffic.
- **Authentication needs interpreting:** a DKIM "pass" proved nothing when it was for an unaligned domain, while a DKIM/DMARC "fail" on a mailing-list email turned out to be harmless.
- **Safe attachment analysis:** attachments were decoded and hashed in CyberChef without being saved or opened, and their real file type was confirmed from magic bytes.

## Reports
| # | Email | Verdict |
|---|---|---|
| [01](report-01.md) | "Your Big Win Is Ready" prize scam | Malicious |
| [02](report-02.md) | "Akusoli" fake health product (Dutch) | Malicious |
| [03](report-03.md) | "Aquaspins" fake casino bonus | Malicious |
| [04](report-04.md) | Mailing list email with PCAP attachments | Benign (false positive) |

## Method
1. Open the raw `.eml` in a text editor only – never an email client
2. Check sender fields (From, Reply-To, Return-Path) and decode encoded headers
3. Trace the `Received` chain bottom-up to find the real origin
4. Review SPF, DKIM and DMARC results, including domain alignment
5. Extract and defang links and other IOCs
6. Hash attachments in CyberChef (From Base64 → SHA-256) and verify file type
7. Check domains, URLs and hashes on VirusTotal and urlscan.io
8. Compare emails for shared infrastructure and patterns
9. Write a verdict and recommended actions

## Tools Used
Text editor, CyberChef, VirusTotal, urlscan.io

## Skills Demonstrated
Email header analysis · SPF/DKIM/DMARC and alignment · IOC extraction and defanging · Threat intelligence lookups · Safe attachment hashing · Campaign correlation · False-positive triage · Incident reporting

## Safety
Original `.eml` files are not included in this repository because they contain live malicious links. All IOCs in the reports are defanged (e.g. `hxxps://example[.]com`).
