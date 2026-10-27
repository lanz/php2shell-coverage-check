# Verdicts and reasons

Each host gets exactly one verdict, checked in this order. The first that applies wins.

## vulnerable

An open (or reopened) finding from **any** plugin for CVE-2026-109618 or CVE-2026-109619:
the version check (369483), distro advisory plugins, "unpatched" plugins, or product
plugins such as the Tenable Security Center advisory (371459).

- **Action:** update PHP, or apply the vendor's patched package. Until then, apply the
  interim mitigations and consider isolating internet-facing hosts.
- Notes are left out: a plugin has already decided.

## likely-vulnerable

No PHP2Shell plugin reports the host, but an inventory plugin (48243, 58987, 216936 or
200476) shows a PHP version that's affected and isn't distro-managed:

| Reason | Why it happens |
|---|---|
| `PHP x is below <fixed>` | Usually the last scan predates the plugins (see the notes), or the CVE plugin didn't run |
| `PHP x has no official PHP2Shell fix` | PHP 8.1 and older. In testing, hosts that plugin 58987 (unsupported version) flagged had no CVE finding, so CVE-based views showed nothing |

- **Action:** upgrade to 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or isolate the host. Rescan
  with credentials afterwards to confirm.

## unverified

No finding yet, because the last scan wasn't set up to detect PHP2Shell:

| Reason | Fix |
|---|---|
| No "Nessus Scan Information" (19506) result | Rescan. Without 19506 the tool can't see how the host was scanned |
| The last scan doesn't report its plugin feed | Rescan |
| Plugin feed older than 2026-10-21 | Rescan. The scanner or agent must have updated its plugins first; agents update on their own schedule, so check the feed in the new scan |
| Not credentialed, and only remote PHP detection | Rescan with credentials, or with an agent. Remote checks only see PHP when the web server reveals its version |
| PHP bundled in another product, with "Assess component installs" off | Rescan with that setting on |

- **Never describe these hosts as safe.** "No finding" here means "not checked".

## patched

- The PHP2Shell finding was reported **fixed**, or
- a capable scan (credentialed, current feed) saw a PHP version that includes the fix.

## no-finding

A credentialed scan with a current feed ran the checks and reported nothing. For
distro-managed PHP, the distro plugins decide; see the notes below.

## Notes

Notes don't change the verdict, but always pass them on:

| Note | Meaning |
|---|---|
| Distro-managed or backported PHP | The version number can't show a backported fix (RHEL's 8.0.30, for example). These hosts aren't graded by version; distro plugins decide |
| Feed from the first days of coverage | Feeds from 2026-10-21 to 2026-10-23 may lack later distro and unpatched checks |
| "Scan for Unpatched Vulnerabilities" was off | Distro packages without a vendor fix yet aren't flagged |
| The last scan predates the plugins (on likely-vulnerable) | Explains why no plugin reported it |
| The last scan wasn't credentialed (on likely-vulnerable) | Remote evidence only |

## What the check can't see

- Hosts where Tenable never detected PHP. Inventory plugins can miss some installs, so if
  another tool shows PHP on a host the check doesn't list, rescan it with credentials.
- PHP inside containers or images that these plugins don't scan. Use Tenable Cloud
  Security's PHP2Shell view for those.
