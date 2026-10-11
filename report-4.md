# Phishing Analysis Report 04 – False Positive: Mailing List Email with PCAP Attachments

## Summary
An email delivered to the Junk folder with **DKIM and DMARC failures** and two attachments. Investigation shows it is a **legitimate post to the public `john-users` mailing list** (the discussion list for the John the Ripper password-auditing tool), in which a list member shares two network capture (`.pcap`) files for testing. The authentication failures are caused by the mailing list modifying the message, a well-known and harmless side effect of list forwarding. **Verdict: Benign – false positive.**

## Email Details
| Field | Value |
|---|---|
| From | `Albert Veli <albert.veli@gmail[.]com>` |
| Reply-To | `john-users@lists.openwall[.]com` (the list address – normal for mailing lists) |
| Return-Path | `john-users-return-10955-<victim>@lists.openwall[.]com` (list bounce address) |
| To | `john-users@lists.openwall[.]com` |
| Subject | `[john-users] Re: SNMPv3 format` |
| Date sent | Tue, 03 Jun 2025 10:53:20 +0200 |
| Sending IP | `193.110.157.125` (`second.openwall.net` – Openwall list server) |
| Client | Mozilla Thunderbird |
| Attachments | 2 × `.pcap` (network capture files) |

## Authentication Results
| Check | Result | Notes |
|---|---|---|
| SPF | **Pass** | `lists.openwall.com` authorises its own server `193.110.157.125` |
| DKIM | **Fail** | Original `gmail.com` signature no longer verifies |
| DMARC | **Fail** | From domain (`gmail.com`) does not align with the sending domain (`lists.openwall.com`) |
| Composite auth | **Fail** | `compauth=fail reason=001` |

Microsoft scored the message **SCL 5** and delivered it to **Junk**.

### Why authentication failed
1. The author sent the message from Gmail, which signed it with DKIM. The signature covers the **Subject** header (`h=...subject...`).
2. The mailing list software (ezmlm, `Mailing-List: ... run by ezmlm`) **added the tag `[john-users]` to the subject** and redistributed the message from its own server.
3. Changing the subject invalidated Gmail's DKIM signature → **DKIM fail**.
4. The message now comes from `lists.openwall.com` while the From header still says `gmail.com`, so neither SPF nor DKIM aligns with the From domain → **DMARC fail**.

This is a well-documented limitation of mailing lists, not evidence of spoofing.

## Attachment Analysis
| File | Size | Detected type | SHA-256 |
|---|---|---|---|
| `snmpv3_user_albert_auth_md5_aes128.pcap` | 1,128 bytes | PCAP (network capture) | `8320de2cea3e41dafa417eb5836a5f62ea9f9af3e39170c037c4a08b607c46cf` |
| `snmpv3_unencrypted_user_albert_auth_md5.pcap` | 1,092 bytes | PCAP (network capture) | `0971a7e49f7e457788b51e5685367e0171a382b5c76700e4f8938f685864e55f` |

**Method.** Each Base64 attachment block was decoded and hashed in CyberChef (From Base64 → SHA2-256) without saving or opening the files. **Detect File Type** confirmed both are genuine PCAP files (file signature `D4 C3 B2 A1`), matching the declared `Content-Type: application/vnd.tcpdump.pcap` and `.pcap` extension. There is no type mismatch.

**Assessment.** PCAP files are passive data (recorded network traffic) opened in tools like Wireshark; they are not executable. Their small size (about 1 KB each) is consistent with a few captured SNMP packets, as the email body describes. The captures contain deliberately weak example passphrases used only to test John the Ripper's SNMPv3 cracking support.

- **VirusTotal (hash lookup):** No matches found for either hash. Neither file has been previously submitted to VirusTotal. A missing result is neutral rather than proof of safety, but it is consistent with small, unique test captures created by the author for this discussion, and is supported by the confirmed PCAP file type, the plain technical context and the legitimate mailing-list source.

## Content Analysis
- The message is a **reply in an existing thread** (`In-Reply-To` and `References` headers point to the author's earlier post).
- The body is purely technical: it documents the exact `snmpwalk` commands used to create each capture and links to the John the Ripper source code on GitHub (`github.com/openwall/john`) and an OID reference site.
- There is **no call to action**, no urgency, no request for credentials or payment, no hidden text and no tracking pixels.
- All mailing-list headers (`List-ID`, `List-Post`, `List-Unsubscribe`, `Precedence: bulk`) are consistent with genuine list traffic.

## Indicators of Compromise (IOCs)
None. All observed indicators (`lists.openwall.com`, `193.110.157.125`, `github.com/openwall/john`) belong to legitimate, well-known open-source project infrastructure.

## Comparison with Malicious Samples (Reports 01–03)
| Indicator | Reports 01–03 (malicious) | Report 04 (benign) |
|---|---|---|
| Why authentication failed | Sender not authorised to use the From domain | Mailing list modified the message after signing |
| Sender | Throwaway, randomly named accounts | Real, consistent identity replying in a thread |
| Content | Lures, urgency, hidden junk text | Plain technical discussion |
| Links | Malicious domains with tracking IDs | Legitimate project source code |
| Attachments | None | Genuine data files; type matches extension |

## Verdict
**Benign – False Positive.** Legitimate mailing-list traffic misclassified as spam because list processing broke DKIM and DMARC alignment.

## Recommended Actions
- Release the message from Junk if the recipient subscribes to the list.
- No blocking actions required.
- If list mail is regularly misclassified, consider allow-listing the list (`List-ID: john-users.lists.openwall.com`) or relying on ARC, which lets trusted forwarders preserve original authentication results.
- Close the ticket as a false positive and document the reason.

## Lessons Learned
Authentication failures alone do not prove an email is malicious. An analyst must determine **why** a check failed: here, a mailing list legitimately altered the message. Treating every DKIM/DMARC failure as phishing would generate false positives and block legitimate communication.

## Tools Used
Text editor (raw `.eml` review), CyberChef (Base64 decoding, SHA-256 hashing, file type detection), VirusTotal

*Source: public phishing_pot dataset.*
