# PHP2Shell Coverage Check

Checks that your Tenable scanning is set up to detect PHP2Shell (CVE-2026-109618,
CVE-2026-109619) on every host where Tenable has seen PHP, and tells you which hosts need
a rescan or a settings change.

Tenable detects PHP2Shell once a host is scanned with the PHP2Shell plugins and the right
settings. Hosts that haven't had that scan yet show no finding, the same as patched hosts.
This tool tells them apart. For every PHP host, it joins:

- the PHP installs Tenable detected (plugins 48243, 58987, 216936 and 200476), with versions
- every finding for the two CVEs, from any plugin, including distro and "unpatched" checks
- the host's latest **Nessus Scan Information** (plugin 19506), which records the plugin
  feed the scan used, whether it was credentialed, and settings such as "Assess component
  installs"

Each host gets a verdict and a reason: **vulnerable**, **likely-vulnerable** (an affected
version that no PHP2Shell plugin reports), **unverified** (no finding yet, because the last
scan wasn't set up to detect it), **patched**, or **no-finding**. It also prints the list
of hosts to rescan.

It works with Tenable Vulnerability Management, Tenable Security Center, and `.nessus`
files from any Nessus edition. It needs no Tenable One or Hexa AI subscription. It runs as
a Claude Code skill or as a standalone script.

> **PHP2Shell coverage is evolving quickly.** Tenable keeps publishing plugins and updating
> its guidance, and this tool will be updated to match. See
> [Keeping up with PHP2Shell coverage](#keeping-up-with-php2shell-coverage).

## Why it's useful

PHP2Shell was disclosed, and its plugins published, on 2026-10-21. Any scan before then
couldn't report it, and the plugins keep growing as distro advisories and product checks
are added. In the first days and weeks of an emergency like this, how many findings you
have depends as much on when and how each host was last scanned as on how many hosts are
vulnerable.

- **Turns "no finding" into something you can act on.** Instead of a count of affected
  hosts, you get every PHP host sorted into vulnerable, needs a rescan, or done, each with
  the reason and the fix.
- **Finds the scan settings that matter.** It reads the plugin feed, credentials, "Assess
  component installs" and "Scan for Unpatched Vulnerabilities" from each host's last scan,
  so you see which hosts need a fresh, credentialed scan, and which scan policies to change.
- **Flags end-of-life PHP.** PHP 8.1 and older have no fixed release. The tool grades the
  detected version, so these hosts appear even when no CVE finding exists for them yet.
- **Avoids false alarms on distro PHP.** Distro packages, such as RHEL's PHP 8.0.30, carry
  backported fixes under old version numbers. The tool leaves those to the distro
  plugins rather than grading the version.
- **Gives you the rescan list** (`targets`), one address per line, ready to paste into a
  scan.
- **Works where you already are.** Vulnerability Management, Security Center or plain
  `.nessus` exports, with read-only API access.
- **Helps you answer leadership with confidence.** "N hosts vulnerable, M patched, K
  rescans scheduled" is a better status than a finding count alone.

## How it fits with the other PHP2Shell skills

The CyberAgents Exchange already has two PHP2Shell listings. They answer *where are we
exposed, what do we fix first, and were we hit?* This tool answers the question before
those: *are our scans set up to find it everywhere?*

| | Answers | Data source |
|---|---|---|
| **PHP2Shell Coverage Check** (this) | Which PHP hosts have been scanned in a way that can detect PHP2Shell, and which need a rescan or settings change | Vulnerability Management or Security Center API, or `.nessus` files |
| [PHP2Shell Tenable Skill](https://github.com/securibee/php2shell-tenable-skill) | Which assets are exposed, graded against the fixed releases, as an HTML, PDF and CSV report | Tenable One, through Hexa AI MCP |
| [PHP2Shell Response Playbook](https://github.com/jtbuchanan-tenb/php2shell-playbook) | Find, fix and hunt: exposure, a fix order, and a threat hunt in your SIEM and EDR | Tenable One through Hexa AI MCP, plus SIEM and EDR |

They work well together:

1. **Run this check first**, and rescan the hosts it lists with a current feed and
   credentials.
2. **Then run the exposure report or the playbook**, so it works from complete scan data.
3. **Run this check again** if the report shows hosts as unknown, or as having no
   PHP2Shell finding, to see whether the scan or the host is the reason.

If you don't have Tenable One or Hexa AI, this tool works on its own, and its report
includes the fixed versions and interim mitigations.

## Prerequisites

- Python 3.11 or later, and [uv](https://docs.astral.sh/uv/) (recommended) or pip.
- One of:
  - **Tenable Vulnerability Management:** an API key pair whose user has the Basic role (or
    the vulnerability export privilege) and Can View on the assets you want covered. Set
    `TIO_ACCESS_KEY` and `TIO_SECRET_KEY`, and `TIO_URL` if you don't use
    `cloud.tenable.com`.
  - **Tenable Security Center:** an API key pair for an organization user (administrators
    can't see vulnerability data), and the URL. Set `TSC_ACCESS_KEY`, `TSC_SECRET_KEY` and
    `TSC_URL`.
  - **Nessus:** one or more `.nessus` exports. Any edition can export them from its UI, so
    no API access is needed. Security Center scan results download as a `.zip` holding the
    `.nessus` file; pass the zip as it is.

## Installation

### As a Claude Code skill

```bash
git clone https://github.com/lanz/php2shell-coverage-check ~/.claude/skills/php2shell-coverage-check
```

Then ask, for example, "Are our scans set up to detect PHP2Shell everywhere?" or "Which
hosts do we need to rescan for PHP2Shell?", or run `/php2shell-coverage-check`.

### Standalone

```bash
git clone https://github.com/lanz/php2shell-coverage-check
cd php2shell-coverage-check
uv run scripts/coverage_check.py --help     # uv installs pyTenable from the script's metadata
```

## Usage

```bash
uv run scripts/coverage_check.py collect                          # Vulnerability Management
uv run scripts/coverage_check.py collect --platform sc            # Security Center
uv run scripts/coverage_check.py collect --nessus a.nessus b.nessus
uv run scripts/coverage_check.py report                           # markdown summary and hosts to act on
uv run scripts/coverage_check.py report --format csv > php2shell.csv
uv run scripts/coverage_check.py report --verdict unverified likely-vulnerable
uv run scripts/coverage_check.py targets > rescan.txt             # one address per line
```

Use `--env-prefix PROD` to read `PROD_ACCESS_KEY`, `PROD_SECRET_KEY` and `PROD_URL`
instead, and `--snapshot` to choose where the snapshot goes.

## Output

The markdown report starts with the verdict counts and the reasons hosts are unverified:

```
| Verdict | Hosts | Meaning |
|---|---|---|
| **vulnerable** | 1 | A PHP2Shell plugin reports it |
| **likely-vulnerable** | 1 | Detected PHP version is affected, but no PHP2Shell plugin reports it |
| **unverified** | 2 | No finding yet: the last scan wasn't set up to detect it |
| patched | 0 | Fixed finding, or a fixed version seen by a capable scan |
| no-finding | 1 | A capable scan reported no finding |

- 2 × last scanned with plugin feed 202609110358, before the PHP2Shell plugins existed
```

It then lists each host to act on with its reason, action, PHP versions, last scan, plugin
feed and whether it was credentialed. CSV and JSON include every host and a `notes` column.
[references/verdicts.md](references/verdicts.md) explains every verdict and reason.

## How it works

- **Vulnerability Management:** two vulnerability exports.
  1. The inventory plugins plus plugin 19506, open findings from the last 400 days
     (`--since-days` changes the window).
  2. Every finding for the two CVEs (open, reopened and fixed), filtered by CVE ID, so new
     distro plugins are included automatically.
- **Security Center:** the same data through cumulative and patched analysis queries.
- **`.nessus` files**, or zips of them: the latest scan of each host wins, so pass older
  and newer exports together.

Verdicts are computed when you run `report`, so the snapshot doesn't need to be collected
again if the verdict rules change. The PHP2Shell specifics (CVEs, plugin IDs, fixed
versions and the date the plugins were published) live in `profiles/php2shell.json`.

## Data handling and network access

- **Read-only.** Every request reads data. On Vulnerability Management, collection starts
  two export jobs, which change nothing, and cancels them if it stops early. If an
  identical export is already running, the tool reads that one instead and leaves it to its
  owner. It contacts only the Tenable URL you configure, and sends no telemetry.
- **TLS.** Security Center certificates are verified. Pass `--ca-bundle` for a private CA;
  `--insecure` turns verification off and isn't recommended.
- **Credentials** come from environment variables only and are never written anywhere.
- **The snapshot** (under `~/.cache/php2shell-coverage-check/`, or `PHP2SHELL_CHECK_HOME`)
  lists host names, addresses, PHP versions and scan settings. It's written with owner-only
  permissions. Treat it as internal and don't commit it.
- **With the skill**, the assistant reads the report, so host names in it go to the model
  provider like anything else you share.

## Known limitations

- **Only hosts where Tenable detected PHP appear.** Unauthenticated scans see PHP only when
  a web server reveals its version, and inventory plugins can miss some installs. If another
  tool shows PHP on a host this check doesn't list, rescan that host with credentials.
- **Version grading is a guide.** Distro packages often carry backported fixes under an
  old version number. Those hosts aren't graded by version; distro plugins decide, and the
  report says so.
- **The scan information is per host, not per install.** If a host has several PHP
  installs, the verdict uses the most urgent one.
- **Security Center** results cover only the repositories the API user can see.
- **Coverage keeps changing.** See the next section.

## Keeping up with PHP2Shell coverage

PHP2Shell coverage is evolving quickly. Tenable Research is still publishing plugins
(distro advisories, unpatched-package checks and product-specific checks) and updating its
guidance, including recommended scan settings.

- **New plugins for the two CVEs are picked up automatically.** Findings are collected by
  CVE ID, not plugin ID.
- **Everything else is in `profiles/php2shell.json`:** the inventory plugins, the date the
  plugins were published, the earliest plugin feed that can detect it, the fixed versions
  and the interim mitigations. They reflect coverage when this version was released.
- **This tool will be updated as coverage evolves.** Run `git pull` in the skill folder
  before each use while PHP2Shell is active, and check the releases page for changes.
- **Tenable's guidance comes first.** If it differs from this tool, follow the
  [Tenable Research PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote),
  and please open an issue so the profile can be updated.

## Development

```bash
pip install pytenable pytest responses ruff
pytest
ruff check scripts tests
```

The tests use synthetic data in the formats of real plugin output, and mocked HTTP. They
don't contact Tenable.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 [Lance Duvall](https://github.com/lanz).

## Disclaimer

This is an independent open source community project. It is not an official Tenable
product and is not affiliated with, sponsored by, endorsed by, or supported by
Tenable, Inc.

Tenable, Nessus and other Tenable product names are trademarks or registered trademarks
of Tenable, Inc. Other names may be trademarks of their respective owners.
