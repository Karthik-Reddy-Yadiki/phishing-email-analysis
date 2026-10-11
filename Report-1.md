# Phishing Analysis Report 01 – "Your Big Win Is Ready" Prize Scam

## Summary
A mass-mailed prize/lottery lure ("FREE Lucky CARDS!") sent from a throwaway Microsoft 365 tenant through Google's Gmail API. The email uses filter-evasion techniques (hidden random text, spaced-out display name) and per-recipient tracking links to drive victims to a scam domain flagged as phishing/malicious by threat intelligence vendors.

## Email Details
| Field | Value |
|---|---|
| From (display name) | `C O N G R A T U L A T I O N S ! ! !` |
| From (address) | `sage.jones@gbnfrostbornwarriors02[.]onmicrosoft[.]com` |
| Return-Path | `sage.jones@gbnfrostbornwarriors02[.]onmicrosoft[.]com` |
| Reply-To | Not present |
| Subject | `Your Big Win Is Ready—Claim Now!` (UTF-8 encoded in header) |
| Date sent | Wed, 08 Jul 2026 14:55:24 -0700 |
| Sending IP | `74.125.224.50` (`mail-yx1-f50.google.com` – Google infrastructure) |
| Origin | Created via Gmail API (`gmailapi.google.com with HTTPREST`) |
| Attachments | None |

## Authentication Results
| Check | Result | Notes |
|---|---|---|
| SPF | **Fail** | `onmicrosoft.com` domain does not authorise Google's IP `74.125.224.50` |
| DKIM | Pass (not aligned) | Signed by `...gappssmtp.com` (Google Workspace default), not the From domain, so it gives no assurance about the sender |
| DMARC | None | No DMARC policy enforced |

Microsoft's filtering also flagged the message: Spam Confidence Level **8/9** (`X-MS-Exchange-Organization-SCL: 8`), Sender ID **FAIL**, delivered to the **Junk** folder.

## Indicators of Compromise (IOCs)
| Type | Indicator | Notes |
|---|---|---|
| Domain | `woondsplay[.]com` | Primary malicious domain |
| URL | `hxxps://woondsplay[.]com/index[.]php?search=4&...` | Main "claim" link (×3) |
| URL | `hxxp://woondsplay[.]com/rd/index[.]php?...` | Redirect link over plain HTTP |
| URL | `hxxps://woondsplay[.]com/track/index[.]php?...` | 1×1 tracking pixel – confirms email was opened |
| Sender | `sage.jones@gbnfrostbornwarriors02[.]onmicrosoft[.]com` | Throwaway M365 tenant |
| Image | `hxxps://i[.]imgur[.]com/rd1JS6V[.]png` | Lure image (legitimate host) |
| Image | `hxxps://i[.]imgur[.]com/l5706eG[.]png` | Lure image (legitimate host) |
| IP | `74.125.224.50` | Google mail server – **legitimate shared infrastructure, do not block** |

## Analysis

**Header analysis.** The From address claims a Microsoft 365 domain, but the `Received` chain shows the message was generated through the Gmail API and sent from a Google mail server. This mismatch explains the SPF failure. DKIM passed only because Google signed it with its own default Workspace domain, which does not align with the From domain. The tenant name (`gbnfrostbornwarriors02`) appears randomly generated, consistent with a disposable account created for bulk sending.

**Content analysis.** The visible content is minimal: a "FREE Lucky CARDS!" headline and two clickable images, a classic reward lure. Thousands of lines of random characters are included in the plain-text part and hidden in the HTML part with `display:none`. This is a hash-busting / filter-poisoning technique that makes each copy unique and dilutes spam-filter scoring. The spaced-out display name likely serves a similar evasion purpose.

**Link analysis.** All links point to `woondsplay[.]com` and carry long unique parameters (e.g. `lm=164627VZLE1595116`), which appear to be per-recipient tracking IDs. A hidden 1×1 tracking image reports back to the attacker when the email is opened, confirming an active mailbox.

**Threat intelligence.**
- **VirusTotal:** 7/92 vendors flagged `woondsplay[.]com`, including alphaMountain.ai (Phishing), Rising (Malicious), ESET (Suspicious) and Forcepoint ThreatSeeker (Spam). The mix of phishing and spam classifications is consistent with a mass-mailed scam designed to harvest user information.
- **urlscan.io:** Scan failed with a DNS resolution error. The domain no longer resolves, indicating it was taken down or abandoned after the campaign (email sent 08 Jul 2026; analysis performed 11 Oct 2026).

## Verdict
**Malicious – Prize/lottery scam with phishing intent**, delivered via abused legitimate email infrastructure.

## Recommended Actions
- Block `woondsplay[.]com` at the email gateway and web proxy.
- Block the sender address and the `gbnfrostbornwarriors02[.]onmicrosoft[.]com` tenant domain.
- Search mailboxes for messages with the same subject or links to `woondsplay[.]com` and remove them.
- Check proxy logs for any user visits to the domain; follow up with affected users (password reset if credentials were entered).
- Do **not** block `74.125.224.50` – it is shared Google mail infrastructure.
- Remind users to treat unexpected "you've won" emails as suspicious and report them.

## Tools Used
Text editor (raw `.eml` review), VirusTotal, urlscan.io

*Source: public phishing_pot dataset. All IOCs are defanged.*
