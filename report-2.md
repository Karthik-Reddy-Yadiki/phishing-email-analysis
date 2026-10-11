# Phishing Analysis Report 02 – "Akusoli" Fake Health Product Scam (Dutch)

## Summary
A Dutch-language spam email advertising fake "Japanese acupressure insoles" with a "70% off, today only" urgency lure. It was sent from a throwaway Microsoft 365 tenant through Google's Gmail API and contains **forged headers copied from a legitimate email marketing platform (Klaviyo)** to make it look like ordinary newsletter traffic. Links lead to `cricktoon[.]org`, which 7 of 10 flagging vendors classify as phishing. The email shares its infrastructure and techniques with Report 01, so both appear to come from the same campaign.

## Email Details
| Field | Value |
|---|---|
| From (display name) | `"Akusoli" (acupressuur + zool)` (Base64-encoded in header; means "acupressure + insole") |
| From (address) | `harper.flores@organisation82[.]onmicrosoft[.]com` |
| Return-Path | `harper.flores@organisation82[.]onmicrosoft[.]com` |
| Reply-To | Not present |
| Subject | `Als je Akusoli hebt geprobeerd, zullen je schoenen nooit meer hetzelfde aanvoelen.` ("Once you've tried Akusoli, your shoes will never feel the same.") |
| Date sent | Wed, 08 Jul 2026 14:19:32 -0700 |
| Sending IP | `209.85.210.179` (`mail-pf1-f179.google.com` – Google infrastructure) |
| Origin | Created via Gmail API (`gmailapi.google.com with HTTPREST`) |
| Attachments | None |

## Authentication Results
| Check | Result | Notes |
|---|---|---|
| SPF | **Fail** | `organisation82.onmicrosoft.com` does not authorise Google's IP `209.85.210.179` |
| DKIM | **Fail** | Signature claims `send.workwithshadow[.]com` (unrelated domain) and does not verify |
| DMARC | None | No DMARC policy enforced |
| Composite auth | **Fail** | `compauth=fail reason=001` |

Microsoft's filtering flagged the message: Spam Confidence Level **8/9**, Sender ID **FAIL**, delivered to the **Junk** folder (`dest:J`).

## Indicators of Compromise (IOCs)
| Type | Indicator | Notes |
|---|---|---|
| Domain | `cricktoon[.]org` | Primary malicious domain |
| URL | `hxxp://cricktoon[.]org/4CURNH23342ICyz1698kievbmmckn107PIOIJSNKENRBCTS76086NYYR632864D1` | Product link (plain HTTP) |
| URL | `hxxp://cricktoon[.]org/4OddHM23342Jisp1698lhqhpabztf107DTPYQWPGXXPZCBF76086AIKG632864x1` | "70% off" link (plain HTTP) |
| URL | `hxxps://cricktoon[.]org/track/3SrWkW23342MWEM1698dskeraswnt107QUPVELXYVMNMYEJ76086FETV632864u1` | Tracking pixel – confirms email was opened |
| Image | `hxxps://articles[.]orbio[.]world/assets/79ec489d-.../6[.]jpg` | Product image host |
| Sender | `harper.flores@organisation82[.]onmicrosoft[.]com` | Throwaway M365 tenant |
| Forged | `send.workwithshadow[.]com`, `klaviyomail[.]com` headers | Copied to appear legitimate – **do not block Klaviyo**, it is a legitimate service |
| IP | `209.85.210.179` | Google mail server – **legitimate shared infrastructure, do not block** |

## Analysis

**Header analysis.** The From address claims a Microsoft 365 domain, but the message was generated through the Gmail API and sent from a Google mail server, causing the SPF failure. The tenant name `organisation82` is generic and numbered, consistent with disposable accounts created in bulk.

**Forged headers.** Below the Gmail API `Received` lines are headers that appear to come from Klaviyo, a legitimate email marketing platform (`Received: ... kmta-send@vmta.klaviyomail.com`, `X-Kmail-*`, `CFBL-Address`, `Feedback-ID`) plus a DKIM signature for `send.workwithshadow.com`. Because these sit *below* the first hop the attacker controlled, they were written by the sender, not added in transit. They were most likely copied from a genuine marketing email so the message looks like normal newsletter traffic. The copied DKIM signature fails because the content no longer matches what was originally signed. Only `Received` headers added by trusted servers (here, Microsoft's) should be relied on.

**Content analysis.** The visible content promotes "Akusoli" insoles that supposedly relieve foot, joint and lower-back pain using "magnetic therapy", with a "70% KORTING, alleen vandaag!" ("70% OFF, today only!") urgency lure. Over 200,000 characters of random text are included in the plain-text part and hidden in the HTML part (`display:none`) to defeat spam filtering (hash-busting). The recipient's address is embedded inside the random text, making every copy unique.

**Link analysis.** All links point to `cricktoon[.]org`. Each contains shared values (`23342`, `1698`, `76086`) that are likely campaign identifiers, plus unique per-recipient strings for tracking clicks. Two links use plain HTTP. A hidden tracking image reports back when the email is opened.

**Threat intelligence.**
- **VirusTotal:** 10/93 vendors flagged `cricktoon[.]org`. Seven classify it as **Phishing** (alphaMountain.ai, CyRadar, ESET, Fortinet, G-Data, Lionic, Sophos), VIPRE as **Malware**, Webroot as **Malicious** and Forcepoint ThreatSeeker as **Spam**. This strong phishing consensus suggests the site was used to harvest personal or payment details, and the VIPRE label indicates possible malicious downloads.
- **urlscan.io:** Scan failed with a DNS resolution error. The domain no longer resolves, indicating it was taken down or abandoned after the campaign (email sent 08 Jul 2026; analysis performed 11 Oct 2026). The landing domain from Report 01 shows the same result, consistent with the operator using short-lived, disposable domains.

## Campaign Link to Report 01
| Indicator | Report 01 | Report 02 |
|---|---|---|
| Sender type | Throwaway `*.onmicrosoft.com` tenant | Throwaway `*.onmicrosoft.com` tenant |
| Sending method | Gmail API → Google mail server | Gmail API → Google mail server |
| Date | 08 Jul 2026, 14:55 -0700 | 08 Jul 2026, 14:19 -0700 |
| Filter evasion | Hidden random text (recipient address embedded) | Hidden random text (recipient address embedded) |
| Link structure | Per-recipient IDs + `/track/` pixel | Per-recipient IDs + `/track/` pixel |
| Lure | English "prize win" | Dutch fake health product |
| Landing domain | `woondsplay[.]com` | `cricktoon[.]org` |

The shared infrastructure, timing and techniques indicate both emails were sent by the same operator using rotating domains, languages and lures. Blocking individual domains alone is therefore insufficient; detection should also target the pattern (onmicrosoft.com sender + SPF fail + Gmail API origin + large hidden text).

## Verdict
**Malicious – Spam/phishing campaign promoting a fake health product**, likely aimed at stealing payment details or selling counterfeit goods. Uses forged headers to impersonate legitimate marketing traffic.

## Recommended Actions
- Block `cricktoon[.]org` at the email gateway and web proxy.
- Block the sender address and the `organisation82[.]onmicrosoft[.]com` tenant domain.
- Search mailboxes for messages linking to `cricktoon[.]org` or `woondsplay[.]com`, or with the same sender pattern, and remove them.
- Check proxy logs for visits to the domain; follow up with any users who clicked (card/password reset if details were entered).
- Consider a mail-flow rule flagging `*.onmicrosoft.com` senders that fail SPF.
- Do **not** block `209.85.210.179` (Google) or Klaviyo domains – they are legitimate services abused or impersonated by the attacker.

## Tools Used
Text editor (raw `.eml` review), CyberChef (Base64 decoding), VirusTotal, urlscan.io

*Source: public phishing_pot dataset. All IOCs are defanged.*
