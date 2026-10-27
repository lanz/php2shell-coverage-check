# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Lance Duvall
# Project: <https://github.com/lanz/php2shell-coverage-check>
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytenable>=26.10.1"]
# ///
"""
PHP2Shell Coverage Check: for every host where Tenable has seen PHP, check that its scans
are set up to detect PHP2Shell.

A host can show no PHP2Shell finding because it's patched, or because it was last scanned
before the detection plugins existed, without credentials, or with checks turned off.
This tool joins three things per host: the PHP installs Tenable has detected, any finding
for the PHP2Shell CVEs (from any plugin, including distro checks), and the host's latest
"Nessus Scan Information" (plugin 19506), which records the plugin feed and whether the
scan was credentialed. It then gives each host a verdict and the reason.

    coverage_check.py collect                       # Tenable Vulnerability Management
    coverage_check.py collect --platform sc         # Tenable Security Center
    coverage_check.py collect --nessus scan1.nessus scan2.nessus
    coverage_check.py report
    coverage_check.py report --format csv --verdict unverified
    coverage_check.py targets                       # hosts to rescan, one per line

Credentials come from environment variables only: TIO_ACCESS_KEY / TIO_SECRET_KEY
(optional TIO_URL) for VM, or TSC_ACCESS_KEY / TSC_SECRET_KEY / TSC_URL for Security
Center. Every API call reads data; VM collection starts two vulnerability export jobs,
which change nothing, and cancels them if collection stops early.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Iterable

VERSION = '1.0.0'
TOOL = 'php2shell-coverage-check'
HERE = Path(__file__).resolve().parent
DEFAULT_PROFILE = HERE.parent / 'profiles' / 'php2shell.json'

# Verdicts, most urgent first.
VULNERABLE = 'vulnerable'
LIKELY = 'likely-vulnerable'
UNVERIFIED = 'unverified'
PATCHED = 'patched'
NO_FINDING = 'no-finding'
VERDICTS = [VULNERABLE, LIKELY, UNVERIFIED, PATCHED, NO_FINDING]
OPEN_STATES = {'OPEN', 'REOPENED'}


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------------------
# Profile
# --------------------------------------------------------------------------------------


def load_profile(path: str | None) -> dict:
    p = Path(path) if path else DEFAULT_PROFILE
    try:
        profile = json.loads(p.read_text(encoding='utf-8'))
    except (OSError, ValueError) as err:
        sys.exit(f'error: can\'t read the profile {p}: {err}')
    for key in ('id', 'cves', 'detection', 'inventory_plugins', 'versions'):
        if key not in profile:
            sys.exit(f'error: the profile {p} has no "{key}"')
    return profile


def inventory_ids(profile: dict) -> set[int]:
    return {int(k) for k in profile['inventory_plugins']}


def local_inventory_ids(profile: dict) -> set[int]:
    return {int(k) for k, v in profile['inventory_plugins'].items() if v.get('kind') == 'local'}


# --------------------------------------------------------------------------------------
# Plugin output parsing
# --------------------------------------------------------------------------------------

LABEL_RE = re.compile(r'^\s*([A-Za-z][\w ()/.-]{0,48}?)\s*:\s*(.*?)\s*$')


def labelled(output: str | None) -> list[tuple[str, str]]:
    """The 'Label : value' lines of a plugin output, in order."""
    out = []
    for line in strip_tags(output or '').splitlines():
        m = LABEL_RE.match(line)
        if m:
            out.append((m.group(1).strip(), m.group(2).strip()))
    return out


def strip_tags(text: str) -> str:
    # Security Center wraps plugin output in <plugin_output> tags.
    return re.sub(r'</?plugin_output>', '', text or '')


def field(output: str | None, name: str) -> str | None:
    for k, v in labelled(output):
        if k.lower() == name.lower():
            return v
    return None


def yes_no(value: str | None) -> bool | None:
    """'yes', "yes, as 'svc' via ssh", 'no' -> True/False; anything else -> None."""
    if not value:
        return None
    word = value.strip().lower().split(',')[0].split()[0] if value.strip() else ''
    if word in ('yes', 'true', 'enabled', 'on'):
        return True
    if word in ('no', 'false', 'disabled', 'off', 'none'):
        return False
    return None


def parse_scan_info(output: str | None) -> dict:
    """The fields of a 'Nessus Scan Information' (19506) output this tool uses."""
    feed_raw = field(output, 'Plugin feed version') or ''
    digits = re.sub(r'\D', '', feed_raw)
    return {
        'feed': digits[:12] if len(digits) >= 8 else None,
        'credentialed': yes_no(field(output, 'Credentialed checks')),
        'scan_type': field(output, 'Scan type'),
        'policy': field(output, 'Scan policy used'),
        'unpatched_checks': yes_no(field(output, 'Scan for Unpatched Vulnerabilities')),
        'component_checks': yes_no(field(output, 'Assess component installs')),
        'thorough': yes_no(field(output, 'Thorough tests')),
        'scan_start': field(output, 'Scan Start Date'),
    }


BLOCK_KEYS = {'path', 'version', 'installed version', 'source'}


def parse_installs(output: str | None) -> list[dict]:
    """PHP installs from an inventory plugin's output. A block starts again when a key it
    already has repeats, which is how multiple installs are listed."""
    blocks: list[dict] = []
    current: dict = {}
    for k, v in labelled(output):
        key = k.lower()
        if key not in BLOCK_KEYS and key not in ('associated package', 'managed by os', 'is component',
                                                  'backported', 'ini file', 'end of support date',
                                                  'supported versions'):
            continue
        if key in current and key in BLOCK_KEYS:
            blocks.append(current)
            current = {}
        current[key] = v
    if current:
        blocks.append(current)
    installs = []
    for b in blocks:
        version = b.get('version') or b.get('installed version')
        if not version and not b.get('path'):
            continue
        installs.append({
            'path': b.get('path'),
            'version': version,
            'package': b.get('associated package'),
            'managed_by_os': yes_no(b.get('managed by os')),
            'component': yes_no(b.get('is component')),
            'backported': (b.get('backported') or '').strip() in ('1', 'yes', 'true'),
            'source': b.get('source'),
            'end_of_support': b.get('end of support date'),
        })
    return installs


# --------------------------------------------------------------------------------------
# Version grading
# --------------------------------------------------------------------------------------

VERSION_RE = re.compile(r'(\d+)\.(\d+)(?:\.(\d+))?')


def vtuple(version: str | None) -> tuple[int, int, int] | None:
    m = VERSION_RE.search(version or '')
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def grade(version: str | None, profile: dict) -> tuple[str, str | None]:
    """('fixed-available', '8.2.35') | ('no-fix', None) | ('fixed', None) |
    ('not-affected', None) | ('unknown', None)."""
    v = vtuple(version)
    if not v:
        return 'unknown', None
    pv = profile['versions']
    branch = f'{v[0]}.{v[1]}'
    fixed = pv['fixed'].get(branch)
    if fixed:
        return ('fixed', None) if v >= vtuple(fixed) else ('fixed-available', fixed)
    if v >= vtuple(pv['first_unaffected_branch']):
        return 'not-affected', None
    if v < vtuple(pv['earliest_affected']):
        return 'unknown', None  # older than the earliest affected code path; check manually
    lowest = min((vtuple(f) for f in pv['fixed'].values()), default=None)
    if lowest and (v[0], v[1]) < (lowest[0], lowest[1]):
        return 'no-fix', None
    return 'unknown', None


# --------------------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------------------


def verdict(host: dict, profile: dict) -> dict:
    """The verdict, its reason, an action and notes for one host from the snapshot."""
    det = profile['detection']
    min_feed, rec_feed = det['min_feed'], det.get('recommended_feed') or det['min_feed']
    scan = host.get('scan') or {}
    installs = host.get('installs') or []
    cves = host.get('cve_findings') or []
    notes: list[str] = []
    local_ids = local_inventory_ids(profile)
    has_local = any(i.get('plugin_id') in local_ids for i in installs)
    distro = [i for i in installs if i.get('managed_by_os') or i.get('backported')]
    if distro:
        notes.append('distro-managed or backported PHP: the version alone can\'t show whether the fix was backported; distro checks decide')
    feed = scan.get('feed')
    if feed and min_feed <= feed < rec_feed:
        notes.append(f'feed {feed} is from the first days of coverage; later distro checks may be missing')
    if scan and scan.get('unpatched_checks') is False and distro:
        notes.append('"Scan for Unpatched Vulnerabilities" was off: distro packages without a vendor fix yet aren\'t flagged')

    def result(v: str, reason: str, action: str) -> dict:
        return {'verdict': v, 'reason': reason, 'action': action, 'notes': notes}

    open_cve = [c for c in cves if c.get('state') in OPEN_STATES]
    if open_cve:
        names = sorted({str(c.get('plugin_id')) for c in open_cve})
        notes.clear()  # a plugin has decided; version and scan caveats don't apply
        return result(VULNERABLE, f'open finding for the {profile["name"]} CVEs (plugin {", ".join(names)})',
                      'patch PHP now, or apply the interim mitigations and isolate until you can')

    graded = [(i, *grade(i.get('version'), profile)) for i in installs]
    if any(g in ('fixed-available', 'no-fix') for i, g, _ in graded if i not in distro):
        # The version alone decides the verdict, but say when the scan couldn't have flagged it.
        if not scan or not feed or feed < min_feed:
            notes.append(f'the last scan predates the {profile["name"]} plugins, so no finding was possible')
        elif scan.get('credentialed') is not True and not has_local:
            notes.append("the last scan wasn't credentialed")
    for i, g, fix in graded:
        if i in distro:
            continue
        if g == 'fixed-available':
            return result(LIKELY, f'PHP {i.get("version")} is below {fix} and no PHP2Shell finding was reported',
                          f'update to {fix} or later; then rescan with credentials to confirm')
        if g == 'no-fix':
            return result(LIKELY, f'PHP {i.get("version")} has no official PHP2Shell fix, and no CVE plugin reports it',
                          'upgrade to a fixed branch (8.2.35, 8.3.36, 8.4.27 or 8.5.12) or isolate the host')

    if not scan:
        return result(UNVERIFIED, 'no "Nessus Scan Information" result for this host, so the last scan can\'t be checked',
                      'rescan with credentials and a current plugin feed')
    if not feed:
        return result(UNVERIFIED, 'the last scan doesn\'t report its plugin feed', 'rescan with credentials and a current plugin feed')
    if feed < min_feed:
        return result(UNVERIFIED, f'last scanned with plugin feed {feed}, before the {profile["name"]} plugins existed',
                      'rescan; a scan with an older feed can\'t detect it')
    if scan.get('credentialed') is not True and not has_local:
        return result(UNVERIFIED, 'last scan wasn\'t credentialed, and remote checks only see PHP when the host reveals its version',
                      'rescan with credentials, or with an agent')
    component = [i for i in installs if i.get('component')]
    if component and scan.get('component_checks') is False:
        return result(UNVERIFIED, 'PHP is bundled in another product, but "Assess component installs" was off in the last scan',
                      'rescan with "Assess component installs" enabled')

    fixed_cve = [c for c in cves if c.get('state') == 'FIXED']
    if fixed_cve:
        return result(PATCHED, 'the PHP2Shell finding was reported fixed', 'none')
    if any(g == 'fixed' for _, g, _ in graded) and not any(g in ('fixed-available', 'no-fix') for i, g, _ in graded if i not in distro):
        return result(PATCHED, 'detected PHP version includes the fix, and the last scan could have detected it', 'none')
    return result(NO_FINDING, 'credentialed scan with a current feed reported no PHP2Shell finding',
                  'none, unless other tools show PHP that Tenable didn\'t detect')


# --------------------------------------------------------------------------------------
# Host model
# --------------------------------------------------------------------------------------


def new_host(key: str, name: str | None, ip: str | None, **extra) -> dict:
    return {'key': key, 'name': name, 'ip': ip, 'installs': [], 'cve_findings': [], 'scan': None, **extra}


def add_install(host: dict, plugin_id: int, output: str | None, last_seen: str | None) -> None:
    for inst in parse_installs(output) or [{'path': None, 'version': None}]:
        inst['plugin_id'] = plugin_id
        inst['last_seen'] = last_seen
        if inst not in host['installs']:
            host['installs'].append(inst)


def add_cve(host: dict, plugin_id: int, name: str | None, state: str, last_seen: str | None, output: str | None) -> None:
    host['cve_findings'].append({
        'plugin_id': plugin_id, 'name': name, 'state': state, 'last_seen': last_seen,
        'installed_version': field(output, 'Installed version'), 'fixed_version': field(output, 'Fixed version'),
    })


def set_scan(host: dict, info: dict, seen: str | None) -> None:
    """Keep the most recent scan information for the host."""
    current = host.get('scan')
    if current and (current.get('seen') or '') >= (seen or ''):
        return
    host['scan'] = {**info, 'seen': seen}


# --------------------------------------------------------------------------------------
# Tenable Vulnerability Management
# --------------------------------------------------------------------------------------


def connect_vm(prefix: str, url: str | None):
    from tenable.io import TenableIO

    access, secret = os.environ.get(f'{prefix}_ACCESS_KEY'), os.environ.get(f'{prefix}_SECRET_KEY')
    if not access or not secret:
        sys.exit(f'error: set {prefix}_ACCESS_KEY and {prefix}_SECRET_KEY in the environment.')
    url = (url or os.environ.get(f'{prefix}_URL') or 'https://cloud.tenable.com').rstrip('/')
    return TenableIO(url=url, access_key=access, secret_key=secret, vendor='Community', product=TOOL, build=VERSION)


def vm_export(tio, filters: dict, label: str, deadline_s: int = 6 * 3600) -> Iterable[dict]:
    """Stream a vulnerability export. Built by hand rather than with pyTenable's
    exports.vulns, whose CVE pattern rejects six-digit CVE numbers such as CVE-2026-109618."""
    from tenable.errors import APIError

    body = {'num_assets': 500, 'include_unlicensed': False, 'filters': filters}
    adopted = False
    try:
        uuid = tio.post('vulns/export', json=body).json()['export_uuid']
    except APIError as err:
        # 409: an identical export is already running. Read it, but leave it to its owner.
        if err.code != 409:
            raise
        uuid = err.response.json()['active_job_id']
        adopted = True
    log(f'Export {label}: job {uuid}{" (reusing an identical running job)" if adopted else ""}')
    done: set[int] = set()
    state, started, delay = 'QUEUED', time.time(), 2
    try:
        while True:
            status = tio.get(f'vulns/export/{uuid}/status').json()
            state = status['status']
            new = [c for c in status.get('chunks_available', []) if c not in done]
            for chunk in new:
                yield from tio.get(f'vulns/export/{uuid}/chunks/{chunk}').json()
                done.add(chunk)
            if state in ('FINISHED', 'CANCELLED', 'ERROR') and not new:
                if state != 'FINISHED':
                    raise RuntimeError(f'export {label} ended {state}')
                return
            if time.time() - started > deadline_s:
                raise TimeoutError(f'export {label} took longer than {deadline_s // 3600} hours')
            if not new:
                time.sleep(delay)
                delay = min(delay + 1, 30)
            else:
                delay = 2
    finally:
        if state not in ('FINISHED', 'CANCELLED', 'ERROR') and not adopted:
            try:
                tio.post(f'vulns/export/{uuid}/cancel')
            except Exception:  # noqa: BLE001 - never hide the original error
                pass


def collect_vm(args: argparse.Namespace, profile: dict) -> dict:
    tio = connect_vm(args.env_prefix or 'TIO', args.url)
    since = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.since_days)).timestamp())
    inv_ids = inventory_ids(profile)
    info_id = int(profile.get('scan_info_plugin', 19506))
    hosts: dict[str, dict] = {}
    scan_info: dict[str, dict] = {}

    def host_for(f: dict) -> dict:
        a = f.get('asset') or {}
        key = a.get('uuid') or a.get('ipv4') or a.get('hostname')
        if key not in hosts:
            hosts[key] = new_host(key, a.get('fqdn') or a.get('hostname'), a.get('ipv4'), network=a.get('network_id'))
        return hosts[key]

    rows = 0
    for f in vm_export(tio, {'plugin_id': sorted(inv_ids | {info_id}), 'state': ['OPEN', 'REOPENED'], 'since': since},
                       'PHP inventory and scan information'):
        rows += 1
        pid = (f.get('plugin') or {}).get('id')
        if pid == info_id:
            a = f.get('asset') or {}
            key = a.get('uuid') or a.get('ipv4') or a.get('hostname')
            prev = scan_info.get(key)
            if not prev or (f.get('last_found') or '') > prev['seen']:
                # Parsed now, not kept raw: this plugin arrives for every scanned asset.
                scan_info[key] = {'info': parse_scan_info(f.get('output')), 'seen': f.get('last_found') or ''}
        elif pid in inv_ids:
            add_install(host_for(f), pid, f.get('output'), f.get('last_found'))
    for f in vm_export(tio, {'cve_id': profile['cves'], 'state': ['OPEN', 'REOPENED', 'FIXED'], 'since': since},
                       f'{profile["name"]} findings'):
        rows += 1
        p = f.get('plugin') or {}
        add_cve(host_for(f), p.get('id'), p.get('name'), f.get('state') or 'OPEN', f.get('last_found'), f.get('output'))
    for key, host in hosts.items():
        if key in scan_info:
            set_scan(host, scan_info[key]['info'], scan_info[key]['seen'])
    log(f'Read {rows} findings: {len(hosts)} hosts with PHP or a {profile["name"]} finding')
    host = re.sub(r'^https?://', '', str(tio._url)).split('/')[0]
    return {'platform': 'vm', 'source': host, 'hosts': list(hosts.values())}


# --------------------------------------------------------------------------------------
# Tenable Security Center
# --------------------------------------------------------------------------------------


def connect_sc(prefix: str, url: str | None, verify: bool | str):
    from tenable.sc import TenableSC

    access, secret = os.environ.get(f'{prefix}_ACCESS_KEY'), os.environ.get(f'{prefix}_SECRET_KEY')
    if not access or not secret:
        sys.exit(f'error: set {prefix}_ACCESS_KEY and {prefix}_SECRET_KEY in the environment (an organization user, not an administrator).')
    url = url or os.environ.get(f'{prefix}_URL')
    if not url:
        sys.exit(f'error: set {prefix}_URL or pass --url. Security Center has no default address.')
    return TenableSC(url=url.rstrip('/'), access_key=access, secret_key=secret, ssl_verify=verify,
                     vendor='Community', product=TOOL, build=VERSION)


def sc_rows(sc, source: str, *filters) -> Iterable[dict]:
    yield from sc.analysis.vulns(*filters, tool='vulndetails', source=source)


def collect_sc(args: argparse.Namespace, profile: dict) -> dict:
    verify: bool | str = args.ca_bundle or (not args.insecure)
    sc = connect_sc(args.env_prefix or 'TSC', args.url, verify)
    inv_ids = inventory_ids(profile)
    info_id = int(profile.get('scan_info_plugin', 19506))
    hosts: dict[str, dict] = {}
    scan_info: dict[str, dict] = {}

    def key_of(r: dict) -> str:
        repo = (r.get('repository') or {}).get('id', '')
        return r.get('uuid') or r.get('hostUUID') or f'{repo}:{r.get("ip")}'

    def host_for(r: dict) -> dict:
        k = key_of(r)
        if k not in hosts:
            hosts[k] = new_host(k, r.get('dnsName') or r.get('netbiosName'), r.get('ip'),
                                repository=(r.get('repository') or {}).get('name'))
        return hosts[k]

    def seen(r: dict) -> str:
        try:
            return dt.datetime.fromtimestamp(int(r.get('lastSeen') or 0), dt.timezone.utc).isoformat()
        except (TypeError, ValueError):
            return ''

    ids = ','.join(str(i) for i in sorted(inv_ids | {info_id}))
    rows = 0
    log('Reading PHP inventory and scan information…')
    for r in sc_rows(sc, 'cumulative', ('pluginID', '=', ids)):
        rows += 1
        pid = int(r.get('pluginID') or 0)
        if pid == info_id:
            k = key_of(r)
            if k not in scan_info or seen(r) > scan_info[k]['seen']:
                scan_info[k] = {'info': parse_scan_info(r.get('pluginText')), 'seen': seen(r)}
        elif pid in inv_ids:
            add_install(host_for(r), pid, r.get('pluginText'), seen(r))
    cve_filter = ('cveID', '=', ','.join(profile['cves']))
    log(f'Reading {profile["name"]} findings…')
    for source, state in (('cumulative', 'OPEN'), ('patched', 'FIXED')):
        for r in sc_rows(sc, source, cve_filter):
            rows += 1
            add_cve(host_for(r), int(r.get('pluginID') or 0), r.get('pluginName'), state, seen(r), r.get('pluginText'))
    for k, host in hosts.items():
        if k in scan_info:
            set_scan(host, scan_info[k]['info'], scan_info[k]['seen'])
    log(f'Read {rows} results: {len(hosts)} hosts with PHP or a {profile["name"]} finding')
    host = re.sub(r'^https?://', '', str(sc._url)).split('/')[0]
    return {'platform': 'sc', 'source': host, 'hosts': list(hosts.values())}


# --------------------------------------------------------------------------------------
# .nessus files (any Nessus edition, or exported from Security Center)
# --------------------------------------------------------------------------------------


def collect_nessus(paths: list[str], profile: dict) -> dict:
    inv_ids = inventory_ids(profile)
    info_id = int(profile.get('scan_info_plugin', 19506))
    cves = {c.upper() for c in profile['cves']}
    best: dict[str, tuple[str, dict]] = {}  # host key -> (scan end, host), latest scan wins
    reports = 0
    for path in paths:
        try:
            for name, fh in report_files(path):
                with fh:
                    try:
                        parsed = list(nessus_hosts(fh, inv_ids, info_id, cves))
                    except (ET.ParseError, ValueError) as err:
                        raise ValueError(f'{name}: {err}' if name != path else str(err)) from err
                reports += 1
                for end, host in parsed:
                    if host['key'] not in best or end > best[host['key']][0]:
                        best[host['key']] = (end, host)
        except (OSError, zipfile.BadZipFile, ValueError) as err:
            sys.exit(f'error: can\'t read {path}: {err}')
    hosts = [h for _, h in best.values()]
    log(f'Read {reports} report(s) from {len(paths)} file(s): {len(hosts)} hosts with PHP or a '
        f'{profile["name"]} finding')
    return {'platform': 'nessus', 'source': ', '.join(Path(p).name for p in paths), 'hosts': hosts}


def report_files(path: str):
    """Yield (name, binary file) for a .nessus file, or for each .nessus file in a zip.

    Security Center downloads scan results as a zip holding the .nessus file.
    """
    if not zipfile.is_zipfile(path):
        yield path, open(path, 'rb')
        return
    with zipfile.ZipFile(path) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir() and i.filename.lower().endswith('.nessus')]
        if not names:
            raise ValueError('the zip file contains no .nessus files')
        for name in names:
            yield name, zf.open(name)


def nessus_hosts(source, inv_ids: set[int], info_id: int, cves: set[str]):
    context = ET.iterparse(source, events=('start', 'end'))
    _, root = next(context)
    if root.tag != 'NessusClientData_v2':
        raise ValueError('not a Nessus v2 (.nessus) report')
    for event, el in context:
        if event != 'end' or el.tag != 'ReportHost':
            continue
        tags = {t.get('name'): (t.text or '').strip() for t in el.iterfind('HostProperties/tag')}
        name = el.get('name')
        end = tags.get('HOST_END_TIMESTAMP') or tags.get('HOST_END') or ''
        seen = ''
        if end.isdigit():
            seen = dt.datetime.fromtimestamp(int(end), dt.timezone.utc).isoformat()
        host = new_host(name, tags.get('host-fqdn') or tags.get('hostname') or name, tags.get('host-ip') or name)
        relevant = False
        for item in el.iterfind('ReportItem'):
            pid = int(item.get('pluginID') or 0)
            output = item.findtext('plugin_output')
            item_cves = {(c.text or '').strip().upper() for c in item.iterfind('cve')}
            if pid == info_id:
                set_scan(host, parse_scan_info(output), seen)
            elif pid in inv_ids:
                add_install(host, pid, output, seen)
                relevant = True
            elif item_cves & cves:
                add_cve(host, pid, item.get('pluginName'), 'OPEN', seen, output)
                relevant = True
        el.clear()
        if relevant:
            yield end, host
    root.clear()


# --------------------------------------------------------------------------------------
# Snapshot
# --------------------------------------------------------------------------------------


def home() -> Path:
    return Path(os.environ.get('PHP2SHELL_CHECK_HOME') or Path.home() / '.cache' / TOOL)


def write_snapshot(path: Path, data: dict, profile: dict) -> None:
    snap = {'tool': TOOL, 'version': VERSION, 'profile': profile['id'],
            'collected_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'), **data}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)  # also when the file already existed
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(snap, fh, indent=1)
    log(f'Wrote {len(data["hosts"])} hosts to {path} (it lists host names and addresses; keep it private)')


def snapshot_path(arg: str | None, source: str) -> Path:
    if arg:
        return Path(arg)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', source)[:80] or 'snapshot'
    return home() / f'{safe}.json'


def load_snapshot(arg: str | None) -> dict:
    if arg:
        path = Path(arg)
    else:
        candidates = sorted(home().glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True) if home().exists() else []
        if not candidates:
            sys.exit('error: no snapshot found. Run `coverage_check.py collect` first.')
        path = candidates[0]
    try:
        snap = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as err:
        sys.exit(f'error: can\'t read {path}: {err}')
    if not isinstance(snap, dict) or snap.get('tool') != TOOL:
        sys.exit(f'error: {path} isn\'t a {TOOL} snapshot.')
    snap['_path'] = str(path)
    return snap


# --------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------


def evaluate(snap: dict, profile: dict) -> list[dict]:
    rows = []
    for h in snap['hosts']:
        v = verdict(h, profile)
        versions = sorted({i['version'] for i in h['installs'] if i.get('version')} |
                          {c['installed_version'] for c in h['cve_findings'] if c.get('installed_version')})
        scan = h.get('scan') or {}
        rows.append({
            'host': h.get('name') or h['key'], 'ip': h.get('ip') or '', 'verdict': v['verdict'], 'reason': v['reason'],
            'action': v['action'], 'notes': '; '.join(v['notes']), 'php_versions': ', '.join(versions),
            'last_scan': scan.get('seen') or '', 'plugin_feed': scan.get('feed') or '',
            'credentialed': {True: 'yes', False: 'no'}.get(scan.get('credentialed'), ''),
            'scan_type': scan.get('scan_type') or '', 'network': h.get('repository') or h.get('network') or '',
        })
    order = {v: i for i, v in enumerate(VERDICTS)}
    rows.sort(key=lambda r: (order[r['verdict']], r['host']))
    return rows


COLUMNS = ['host', 'ip', 'verdict', 'reason', 'action', 'php_versions', 'last_scan', 'plugin_feed', 'credentialed', 'notes']


def render_md(snap: dict, profile: dict, rows: list[dict], limit: int) -> str:
    counts = {v: sum(r['verdict'] == v for r in rows) for v in VERDICTS}
    out = [f'# {profile["name"]} coverage check',
           '', f'_{len(rows)} hosts with PHP or a {profile["name"]} finding, from {snap["platform"]} `{snap["source"]}`, '
               f'collected {snap["collected_at"]}._', '',
           '| Verdict | Hosts | Meaning |', '|---|---|---|',
           f'| **{VULNERABLE}** | {counts[VULNERABLE]} | A {profile["name"]} plugin reports it |',
           f'| **{LIKELY}** | {counts[LIKELY]} | Detected PHP version is affected, but no {profile["name"]} plugin reports it |',
           f'| **{UNVERIFIED}** | {counts[UNVERIFIED]} | No finding yet: the last scan wasn\'t set up to detect it |',
           f'| {PATCHED} | {counts[PATCHED]} | Fixed finding, or a fixed version seen by a capable scan |',
           f'| {NO_FINDING} | {counts[NO_FINDING]} | A capable scan reported no finding |', '']
    reasons: dict[str, int] = {}
    for r in rows:
        if r['verdict'] == UNVERIFIED:
            reasons[r['reason']] = reasons.get(r['reason'], 0) + 1
    if reasons:
        out += ['**Why hosts are unverified:**', '']
        out += [f'- {n} × {reason}' for reason, n in sorted(reasons.items(), key=lambda x: -x[1])]
        out.append('')
    shown = [r for r in rows if r['verdict'] in (VULNERABLE, LIKELY, UNVERIFIED)][:limit]
    if shown:
        out += [f'## Hosts to act on (first {len(shown)})', '', '| ' + ' | '.join(COLUMNS[:9]) + ' |',
                '|' + '---|' * 9]
        for r in shown:
            out.append('| ' + ' | '.join(md_cell(r[c]) for c in COLUMNS[:9]) + ' |')
        out.append('')
    noted = sum(1 for r in rows if r['notes'])
    if noted:
        out += [f'{noted} host(s) have notes (distro backports, early feeds, checks turned off); see `--format csv`.', '']
    out += ['**Remediation**', ''] + [f'- {m}' for m in profile.get('mitigations', [])]
    out += ['', '**Sources:** ' + ', '.join(f'[{r["title"]}]({r["url"]})' for r in profile.get('references', []))]
    return '\n'.join(out) + '\n'


def md_cell(value: Any) -> str:
    return str(value).replace('|', '\\|').replace('\n', ' ')


def csv_safe(value: Any) -> str:
    s = str(value)
    return "'" + s if s[:1] in ('=', '+', '-', '@', '\t', '\r') else s


def render_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS + ['scan_type', 'network'], extrasaction='ignore')
    w.writeheader()
    for r in rows:
        w.writerow({k: csv_safe(v) for k, v in r.items()})
    return buf.getvalue()


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


def cmd_collect(args: argparse.Namespace) -> None:
    profile = load_profile(args.profile)
    if args.nessus:
        data = collect_nessus(args.nessus, profile)
    elif args.platform == 'sc':
        data = collect_sc(args, profile)
    else:
        data = collect_vm(args, profile)
    write_snapshot(snapshot_path(args.snapshot, data['source'] if not args.nessus else 'nessus-files'), data, profile)


def filtered(args: argparse.Namespace) -> tuple[dict, dict, list[dict]]:
    snap = load_snapshot(args.snapshot)
    profile = load_profile(args.profile)
    if snap.get('profile') != profile['id']:
        sys.exit(f'error: the snapshot was collected with the "{snap.get("profile")}" profile, not "{profile["id"]}".')
    rows = evaluate(snap, profile)
    if getattr(args, 'verdict', None):
        rows = [r for r in rows if r['verdict'] in args.verdict]
    return snap, profile, rows


def cmd_report(args: argparse.Namespace) -> None:
    snap, profile, rows = filtered(args)
    if args.format == 'json':
        print(json.dumps({'source': snap['source'], 'platform': snap['platform'], 'collected_at': snap['collected_at'],
                          'hosts': rows}, indent=1))
    elif args.format == 'csv':
        sys.stdout.write(render_csv(rows))
    else:
        sys.stdout.write(render_md(snap, profile, rows, args.limit))


def cmd_targets(args: argparse.Namespace) -> None:
    if not args.verdict:
        args.verdict = [UNVERIFIED, LIKELY]
    _, _, rows = filtered(args)
    seen = set()
    for r in rows:
        target = r['ip'] or r['host']
        if target and target not in seen:
            seen.add(target)
            print(target)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='coverage_check.py', description=__doc__.split('\n\n')[1].strip())
    parser.add_argument('--version', action='version', version=VERSION)
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('collect', help='Read PHP inventory, PHP2Shell findings and scan information into a local snapshot.')
    p.add_argument('--platform', choices=['vm', 'sc'], default='vm')
    p.add_argument('--nessus', nargs='+', metavar='FILE', help='Read .nessus files instead of an API.')
    p.add_argument('--url', help='Platform URL (VM default: $TIO_URL or https://cloud.tenable.com; SC: $TSC_URL).')
    p.add_argument('--env-prefix', help='Read <PREFIX>_ACCESS_KEY, <PREFIX>_SECRET_KEY and <PREFIX>_URL (default TIO or TSC).')
    p.add_argument('--since-days', type=int, default=400, help='VM: findings seen in the last N days (default 400).')
    p.add_argument('--ca-bundle', help='SC: CA bundle to verify the Security Center certificate.')
    p.add_argument('--insecure', action='store_true', help='SC: skip TLS verification (not recommended).')
    p.add_argument('--snapshot', help='Snapshot file (default: under $PHP2SHELL_CHECK_HOME or ~/.cache/php2shell-coverage-check).')
    p.add_argument('--profile', help='Vulnerability profile JSON (default: the bundled PHP2Shell profile).')
    p.set_defaults(func=cmd_collect)

    for name, helptext, func in (('report', 'Verdicts for every host, with reasons and actions.', cmd_report),
                                 ('targets', 'Hosts to rescan, one per line (default: unverified and likely-vulnerable).', cmd_targets)):
        p = sub.add_parser(name, help=helptext)
        p.add_argument('--snapshot')
        p.add_argument('--profile')
        p.add_argument('--verdict', nargs='+', choices=VERDICTS)
        if name == 'report':
            p.add_argument('--format', choices=['md', 'csv', 'json'], default='md')
            p.add_argument('--limit', type=int, default=50, help='Markdown: rows to show (default 50).')
        p.set_defaults(func=func)
    return parser


def main(argv: list[str] | None = None) -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
