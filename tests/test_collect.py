"""Collection from .nessus files, the VM API and the Security Center API, and the CLI."""

import argparse
import json
import os
import zipfile

import pytest
import responses

import coverage_check as cc
from conftest import (CVE_OUTPUT, PHP_REMOTE, PHP_UNIX_DISTRO, PHP_UNSUPPORTED, SCAN_INFO_NEW,
                      SCAN_INFO_OLD_FEED)

BASE = 'https://cloud.example.invalid'


def report_host(name, ip, end, items):
    out = [f'<ReportHost name="{name}"><HostProperties>',
           f'<tag name="host-ip">{ip}</tag><tag name="HOST_END_TIMESTAMP">{end}</tag>',
           '</HostProperties>']
    for pid, pname, output, cves in items:
        cve_xml = ''.join(f'<cve>{c}</cve>' for c in cves)
        out.append(f'<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="{pid}" '
                   f'pluginName="{pname}" pluginFamily="x">{cve_xml}<plugin_output><![CDATA[{output}]]></plugin_output></ReportItem>')
    out.append('</ReportHost>')
    return ''.join(out)


def nessus_file(tmp_path, name, hosts):
    path = tmp_path / name
    path.write_text('<?xml version="1.0" ?><NessusClientData_v2><Report name="t">' + ''.join(hosts) +
                    '</Report></NessusClientData_v2>', encoding='utf-8')
    return str(path)


def test_nessus_files_latest_scan_wins(tmp_path, profile):
    older = nessus_file(tmp_path, 'old.nessus', [
        report_host('192.0.2.10', '192.0.2.10', 1758000000, [(216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_OLD_FEED, [])]),
        report_host('192.0.2.11', '192.0.2.11', 1758000000, [(10287, 'Traceroute', 'x', [])]),  # no PHP: skipped
    ])
    newer = nessus_file(tmp_path, 'new.nessus', [
        report_host('192.0.2.10', '192.0.2.10', 1761400000, [
            (216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
            (370006, 'RHEL 9 : php (RHSA-2026:1234)', 'Remote package installed : php-8.0.30', ['CVE-2026-109618']),
            (19506, 'Nessus Scan Information', SCAN_INFO_NEW, [])]),
        report_host('192.0.2.12', '192.0.2.12', 1761400000, [(48243, 'PHP Version Detection', PHP_REMOTE, []),
                                                            (58987, 'PHP Unsupported', PHP_UNSUPPORTED, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_NEW, [])]),
    ])
    data = cc.collect_nessus([older, newer], profile)
    by_ip = {h['ip']: h for h in data['hosts']}
    assert set(by_ip) == {'192.0.2.10', '192.0.2.12'}
    assert by_ip['192.0.2.10']['scan']['feed'] == '202610250523'
    assert cc.verdict(by_ip['192.0.2.10'], profile)['verdict'] == cc.VULNERABLE
    assert cc.verdict(by_ip['192.0.2.12'], profile)['verdict'] == cc.LIKELY


def test_nessus_rejects_other_files(tmp_path, profile):
    bad = tmp_path / 'x.nessus'
    bad.write_text('<other/>', encoding='utf-8')
    with pytest.raises(SystemExit, match="can't read"):
        cc.collect_nessus([str(bad)], profile)


def test_nessus_reads_zip_downloads(tmp_path, profile):
    # Security Center downloads scan results as a zip holding the .nessus file.
    older = nessus_file(tmp_path, 'old.nessus', [
        report_host('192.0.2.10', '192.0.2.10', 1758000000, [(216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_OLD_FEED, [])]),
    ])
    newer = nessus_file(tmp_path, 'new.nessus', [
        report_host('192.0.2.10', '192.0.2.10', 1761400000, [(216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_NEW, [])]),
    ])
    archive = tmp_path / '8079.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(newer, 'scan/8079.nessus')
        zf.writestr('readme.txt', 'not a report')
    data = cc.collect_nessus([older, str(archive)], profile)
    assert [h['scan']['feed'] for h in data['hosts']] == ['202610250523']


def test_nessus_rejects_zip_without_reports(tmp_path, profile):
    archive = tmp_path / 'x.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('readme.txt', 'not a report')
    with pytest.raises(SystemExit, match='contains no .nessus files'):
        cc.collect_nessus([str(archive)], profile)


def test_nessus_names_the_bad_report_in_a_zip(tmp_path, profile):
    archive = tmp_path / 'x.zip'
    with zipfile.ZipFile(archive, 'w') as zf:
        zf.writestr('inner.nessus', '<other/>')
    with pytest.raises(SystemExit, match="can't read .*x.zip: inner.nessus: not a Nessus v2"):
        cc.collect_nessus([str(archive)], profile)


def finding(uuid, ip, plugin_id, output, state='OPEN', last='2026-10-25T00:00:00Z', name='p'):
    return {'asset': {'uuid': uuid, 'ipv4': ip, 'hostname': f'h-{ip}', 'fqdn': f'h-{ip}.example.com'},
            'plugin': {'id': plugin_id, 'name': name}, 'output': output, 'state': state, 'last_found': last}


def mock_export(uuid, chunks, status='FINISHED'):
    responses.post(f'{BASE}/vulns/export', json={'export_uuid': uuid})
    responses.get(f'{BASE}/vulns/export/{uuid}/status', json={'status': status, 'chunks_available': list(range(1, len(chunks) + 1))})
    for i, chunk in enumerate(chunks, start=1):
        responses.get(f'{BASE}/vulns/export/{uuid}/chunks/{i}', json=chunk)


def vm_args(tmp_path):
    return argparse.Namespace(env_prefix='TIO', url=BASE, since_days=400, snapshot=str(tmp_path / 'vm.json'),
                              profile=None, nessus=None, platform='vm')


@responses.activate
def test_collect_vm(tmp_path, monkeypatch, profile):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    inv_uuid, cve_uuid = '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'
    # Inventory and 19506 first, then every finding for the CVEs (filtered by CVE ID,
    # which pyTenable's own export method rejects for six-digit CVE numbers).
    mock_export(inv_uuid, [[
        finding('a1', '192.0.2.10', 216936, PHP_UNIX_DISTRO),
        finding('a1', '192.0.2.10', 19506, SCAN_INFO_OLD_FEED, last='2026-09-11T00:00:00Z'),
        finding('a1', '192.0.2.10', 19506, SCAN_INFO_NEW, last='2026-10-25T00:00:00Z'),
        finding('a2', '192.0.2.11', 48243, PHP_REMOTE),
        finding('a9', '192.0.2.99', 19506, SCAN_INFO_NEW),  # no PHP: ignored
    ]])
    mock_export(cve_uuid, [[finding('a3', '192.0.2.12', 369483, CVE_OUTPUT, name='PHP < 8.2.35 …'),
                            finding('a1', '192.0.2.10', 370006, 'pkg', state='FIXED')]])
    cc.cmd_collect(vm_args(tmp_path))
    bodies = [json.loads(c.request.body) for c in responses.calls if c.request.method == 'POST']
    assert bodies[0]['filters']['plugin_id'] == [19506, 48243, 58987, 200476, 216936]
    assert bodies[0]['filters']['state'] == ['OPEN', 'REOPENED'] and bodies[0]['filters']['since'] > 0
    assert bodies[1]['filters']['cve_id'] == ['CVE-2026-109618', 'CVE-2026-109619']
    assert bodies[1]['filters']['state'] == ['OPEN', 'REOPENED', 'FIXED']
    assert all(c.request.method in ('GET', 'POST') for c in responses.calls)
    assert not any(c.request.url.endswith('/cancel') for c in responses.calls)
    snap = cc.load_snapshot(str(tmp_path / 'vm.json'))
    by_key = {h['key']: h for h in snap['hosts']}
    assert set(by_key) == {'a1', 'a2', 'a3'}
    assert by_key['a1']['scan']['feed'] == '202610250523'
    verdicts = {r['ip']: r['verdict'] for r in cc.evaluate(snap, profile)}
    assert verdicts == {'192.0.2.10': cc.PATCHED, '192.0.2.11': cc.LIKELY, '192.0.2.12': cc.VULNERABLE}


@responses.activate
def test_vm_export_cancels_on_error_but_not_adopted_jobs(monkeypatch):
    from tenable.errors import BadRequestError
    from tenable.io import TenableIO

    tio = TenableIO(url=BASE, access_key='a' * 64, secret_key='b' * 64, retries=1)
    uuid = '33333333-3333-3333-3333-333333333333'
    responses.post(f'{BASE}/vulns/export', json={'export_uuid': uuid})
    responses.get(f'{BASE}/vulns/export/{uuid}/status', json={'status': 'PROCESSING', 'chunks_available': [1]})
    responses.get(f'{BASE}/vulns/export/{uuid}/chunks/1', status=400, json={'error': 'boom'})
    responses.post(f'{BASE}/vulns/export/{uuid}/cancel', json={})
    with pytest.raises(BadRequestError):
        list(cc.vm_export(tio, {'plugin_id': [1]}, 'test'))
    assert any(c.request.url.endswith(f'{uuid}/cancel') for c in responses.calls)

    responses.reset()
    responses.post(f'{BASE}/vulns/export', status=409, json={'active_job_id': uuid})
    responses.get(f'{BASE}/vulns/export/{uuid}/status', json={'status': 'PROCESSING', 'chunks_available': [1]})
    responses.get(f'{BASE}/vulns/export/{uuid}/chunks/1', status=400, json={'error': 'boom'})
    with pytest.raises(BadRequestError):
        list(cc.vm_export(tio, {'plugin_id': [1]}, 'test'))
    assert not any(c.request.url.endswith('/cancel') for c in responses.calls)


def test_collect_sc(tmp_path, monkeypatch, profile):
    rows = {
        'cumulative-pluginID': [
            {'pluginID': '216936', 'pluginText': '<plugin_output>' + PHP_UNIX_DISTRO + '</plugin_output>', 'ip': '192.0.2.20',
             'dnsName': 'app.example.com', 'repository': {'id': '1', 'name': 'Default'}, 'lastSeen': '1761400000'},
            {'pluginID': '19506', 'pluginText': SCAN_INFO_NEW, 'ip': '192.0.2.20', 'repository': {'id': '1'}, 'lastSeen': '1761400000'},
            {'pluginID': '19506', 'pluginText': SCAN_INFO_OLD_FEED, 'ip': '192.0.2.21', 'repository': {'id': '1'}, 'lastSeen': '1757500000'},
            {'pluginID': '48243', 'pluginText': PHP_REMOTE.replace('7.2.34', '8.4.27'), 'ip': '192.0.2.21',
             'repository': {'id': '1', 'name': 'Default'}, 'lastSeen': '1757500000'},
        ],
        'cumulative-cveID': [{'pluginID': '371456', 'pluginName': 'Ubuntu : php', 'pluginText': 'pkg', 'ip': '192.0.2.22',
                              'repository': {'id': '2', 'name': 'DMZ'}, 'lastSeen': '1761400000'}],
        'patched-cveID': [{'pluginID': '370006', 'pluginName': 'RHEL : php', 'pluginText': 'pkg', 'ip': '192.0.2.20',
                           'repository': {'id': '1'}, 'lastSeen': '1761400000'}],
    }
    calls = []

    def fake_rows(sc, source, *filters):
        calls.append((source, filters))
        return iter(rows[f'{source}-{filters[0][0]}'])

    class FakeSC:
        _url = 'https://sc.example.invalid'

    monkeypatch.setattr(cc, 'sc_rows', fake_rows)
    monkeypatch.setattr(cc, 'connect_sc', lambda *a: FakeSC())
    args = argparse.Namespace(env_prefix='TSC', url=None, ca_bundle=None, insecure=False, platform='sc',
                              snapshot=str(tmp_path / 'sc.json'), profile=None, nessus=None)
    cc.cmd_collect(args)
    assert calls[0] == ('cumulative', (('pluginID', '=', '19506,48243,58987,200476,216936'),))
    assert calls[1] == ('cumulative', (('cveID', '=', 'CVE-2026-109618,CVE-2026-109619'),))
    assert calls[2][0] == 'patched'
    snap = cc.load_snapshot(str(tmp_path / 'sc.json'))
    verdicts = {r['ip']: r['verdict'] for r in cc.evaluate(snap, profile)}
    assert verdicts == {'192.0.2.20': cc.PATCHED, '192.0.2.21': cc.UNVERIFIED, '192.0.2.22': cc.VULNERABLE}


def test_cli_report_and_targets(tmp_path, profile, capsys):
    path = nessus_file(tmp_path, 'scan.nessus', [
        report_host('192.0.2.30', '192.0.2.30', 1761400000, [(48243, 'PHP Version Detection', PHP_REMOTE, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_NEW, [])]),
        report_host('192.0.2.31', '192.0.2.31', 1761400000, [(216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
                                                            (19506, 'Nessus Scan Information', SCAN_INFO_OLD_FEED, [])]),
        report_host('=cmd|x', '192.0.2.32', 1761400000, [(216936, 'PHP Installed', PHP_UNIX_DISTRO, []),
                                                        (19506, 'Nessus Scan Information', SCAN_INFO_NEW, [])]),
    ])
    snap = str(tmp_path / 'snap.json')
    cc.main(['collect', '--nessus', path, '--snapshot', snap])
    if os.name != 'nt':
        assert oct(os.stat(snap).st_mode & 0o777) == '0o600'
    capsys.readouterr()

    cc.main(['report', '--snapshot', snap])
    md = capsys.readouterr().out
    assert '| **likely-vulnerable** | 1 |' in md and '| **unverified** | 1 |' in md and '| no-finding | 1 |' in md
    assert 'before the PHP2Shell plugins existed' in md and 'Tenable Research PHP2Shell FAQ' in md

    cc.main(['report', '--snapshot', snap, '--format', 'csv'])
    csv_out = capsys.readouterr().out
    assert "'=cmd|x" in csv_out  # spreadsheet formulas neutralized

    cc.main(['report', '--snapshot', snap, '--format', 'json', '--verdict', 'unverified'])
    assert [h['ip'] for h in json.loads(capsys.readouterr().out)['hosts']] == ['192.0.2.31']

    cc.main(['targets', '--snapshot', snap])
    assert capsys.readouterr().out.split() == ['192.0.2.30', '192.0.2.31']


def test_default_snapshot_location_and_errors(tmp_path, profile, capsys):
    path = nessus_file(tmp_path, 'scan.nessus', [report_host('192.0.2.40', '192.0.2.40', 1761400000,
                                                             [(48243, 'PHP', PHP_REMOTE, [])])])
    cc.main(['collect', '--nessus', path])
    cc.main(['report', '--format', 'json'])  # finds the newest snapshot in PHP2SHELL_CHECK_HOME
    assert json.loads(capsys.readouterr().out)['hosts'][0]['verdict'] == cc.LIKELY
    other = tmp_path / 'other.json'
    other.write_text('{"tool": "something else"}', encoding='utf-8')
    with pytest.raises(SystemExit, match="isn't a php2shell-coverage-check snapshot"):
        cc.main(['report', '--snapshot', str(other)])


def test_vm_requires_keys(tmp_path):
    with pytest.raises(SystemExit, match='TIO_ACCESS_KEY'):
        cc.cmd_collect(vm_args(tmp_path))


def test_profile_mismatch(tmp_path, profile):
    path = nessus_file(tmp_path, 'scan.nessus', [report_host('192.0.2.40', '192.0.2.40', 1761400000,
                                                             [(48243, 'PHP', PHP_REMOTE, [])])])
    snap = str(tmp_path / 's.json')
    cc.main(['collect', '--nessus', path, '--snapshot', snap])
    other = dict(profile, id='node2shell')
    (tmp_path / 'p.json').write_text(json.dumps(other), encoding='utf-8')
    with pytest.raises(SystemExit, match='profile'):
        cc.main(['report', '--snapshot', snap, '--profile', str(tmp_path / 'p.json')])
