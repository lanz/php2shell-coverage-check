"""Plugin output parsing and version grading."""

import pytest

import coverage_check as cc
from conftest import (CVE_OUTPUT, PHP_REMOTE, PHP_REMOTE_BACKPORTED, PHP_UNIX_TWO, PHP_UNSUPPORTED,
                      SCAN_INFO_LEGACY, SCAN_INFO_NEW, SCAN_INFO_UNCREDENTIALED)


def test_scan_info():
    info = cc.parse_scan_info(SCAN_INFO_NEW)
    assert info['feed'] == '202610250523'
    assert info['credentialed'] is True  # "yes, as 'svc-scan' via ssh"
    assert info['unpatched_checks'] is True and info['component_checks'] is True and info['thorough'] is True
    assert info['policy'] == 'Advanced Scan' and info['scan_type'] == 'Normal'
    assert cc.parse_scan_info(SCAN_INFO_UNCREDENTIALED)['credentialed'] is False
    assert info['paranoia'] == 1
    assert cc.parse_scan_info(SCAN_INFO_NEW.replace('Paranoia level : 1', 'Paranoia level : 2'))['paranoia'] == 2


def test_legacy_scan_info_lacks_fields():
    info = cc.parse_scan_info(SCAN_INFO_LEGACY)
    assert info['feed'] == '202301251200' and info['credentialed'] is False
    assert info['unpatched_checks'] is None and info['component_checks'] is None and info['paranoia'] is None


def test_scan_info_from_security_center_wrapping():
    info = cc.parse_scan_info('<plugin_output>' + SCAN_INFO_NEW + '</plugin_output>')
    assert info['feed'] == '202610250523'
    assert cc.parse_scan_info(None)['feed'] is None


def test_unix_installs():
    installs = cc.parse_installs(PHP_UNIX_TWO)
    assert [i['version'] for i in installs] == ['8.0.30', '8.3.12']
    assert installs[0]['managed_by_os'] is True and installs[0]['package'].startswith('php-cli-8.0.30')
    assert installs[1]['component'] is True and installs[1]['managed_by_os'] is None


def test_remote_and_unsupported_installs():
    remote = cc.parse_installs(PHP_REMOTE)
    assert len(remote) == 1 and remote[0]['version'] == '7.2.34' and remote[0]['backported'] is False
    assert remote[0]['source'] == 'X-Powered-By: PHP/7.2.34'
    assert cc.parse_installs(PHP_REMOTE_BACKPORTED)[0]['backported'] is True
    unsupported = cc.parse_installs(PHP_UNSUPPORTED)
    assert len(unsupported) == 1 and unsupported[0]['version'] == '7.2.34' and unsupported[0]['end_of_support'] == '2020/11/30'
    two_remote = cc.parse_installs(PHP_REMOTE + PHP_REMOTE_BACKPORTED)
    assert [i['version'] for i in two_remote] == ['7.2.34', '7.4.33']


def test_cve_output_fields():
    assert cc.field(CVE_OUTPUT, 'Installed version') == '8.2.31'
    assert cc.field(CVE_OUTPUT, 'Fixed version') == '8.2.35'


@pytest.mark.parametrize('version, expected', [
    ('8.2.31', ('fixed-available', '8.2.35')),
    ('8.2.35', ('fixed', None)),
    ('8.3.35', ('fixed-available', '8.3.36')),
    ('8.4.27', ('fixed', None)),
    ('8.5.11', ('fixed-available', '8.5.12')),
    ('8.5.12', ('fixed', None)),
    ('8.6.0', ('not-affected', None)),
    ('9.0.1', ('not-affected', None)),
    ('8.1.31', ('no-fix', None)),
    ('7.4.33', ('no-fix', None)),
    ('7.2.34', ('no-fix', None)),
    ('5.4.45', ('no-fix', None)),
    ('5.3.29', ('unknown', None)),   # older than the earliest affected code path
    ('PHP 8.2.20 (cli)', ('fixed-available', '8.2.35')),
    ('8.2', ('fixed-available', '8.2.35')),
    (None, ('unknown', None)),
    ('unknown', ('unknown', None)),
])
def test_grade(profile, version, expected):
    assert cc.grade(version, profile) == expected


@pytest.mark.parametrize('value, expected', [
    ('yes', True), ("yes, as 'svc' via ssh", True), ('Yes', True), ('no', False), ('None', False),
    ('', None), (None, None), ('maybe', None),
])
def test_yes_no(value, expected):
    assert cc.yes_no(value) is expected
