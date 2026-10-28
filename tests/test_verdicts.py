"""The verdict for each combination of findings, inventory and scan information."""

import coverage_check as cc
from conftest import (PHP_REMOTE, PHP_REMOTE_BACKPORTED, PHP_UNIX_COMPONENT_PATCHED, PHP_UNIX_DISTRO,
                      PHP_UNSUPPORTED, SCAN_INFO_EARLY_FEED, SCAN_INFO_LEGACY, SCAN_INFO_NEW,
                      SCAN_INFO_NO_COMPONENTS, SCAN_INFO_NO_UNPATCHED, SCAN_INFO_OLD_FEED,
                      SCAN_INFO_UNCREDENTIALED)


def host(installs=(), cves=(), scan=SCAN_INFO_NEW):
    h = cc.new_host('h1', 'web01.example.com', '192.0.2.10')
    for plugin_id, output in installs:
        cc.add_install(h, plugin_id, output, '2026-10-25T00:00:00Z')
    for plugin_id, state in cves:
        cc.add_cve(h, plugin_id, 'PHP < 8.2.35 …', state, '2026-10-25T00:00:00Z', None)
    if scan is not None:
        cc.set_scan(h, cc.parse_scan_info(scan), '2026-10-25T00:00:00Z')
    return h


def check(profile, h):
    return cc.verdict(h, profile)


def test_open_finding_is_vulnerable(profile):
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], [(369483, 'OPEN')], scan=SCAN_INFO_OLD_FEED))
    assert v['verdict'] == cc.VULNERABLE and '369483' in v['reason'] and v['notes'] == []


def test_reopened_counts_as_open(profile):
    assert check(profile, host(cves=[(370006, 'REOPENED')]))['verdict'] == cc.VULNERABLE


def test_affected_version_without_finding_is_likely(profile):
    v = check(profile, host([(48243, PHP_REMOTE), (58987, PHP_UNSUPPORTED)]))
    assert v['verdict'] == cc.LIKELY and 'no official' in v['reason']


def test_likely_notes_when_the_scan_predates_the_plugins(profile):
    v = check(profile, host([(216936, PHP_UNIX_COMPONENT_PATCHED.replace('8.2.35', '8.2.31'))], scan=SCAN_INFO_OLD_FEED))
    assert v['verdict'] == cc.LIKELY and 'below 8.2.35' in v['reason']
    assert any('predates' in n for n in v['notes'])


def test_distro_and_backported_versions_dont_decide(profile):
    # An OS package (8.0.30 on RHEL) may carry a backported fix: no likely-vulnerable from version.
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)]))
    assert v['verdict'] == cc.NO_FINDING and any('backported' in n for n in v['notes'])
    v = check(profile, host([(48243, PHP_REMOTE_BACKPORTED)], scan=SCAN_INFO_UNCREDENTIALED))
    assert v['verdict'] == cc.UNVERIFIED


def test_stale_feed_is_unverified(profile):
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=SCAN_INFO_OLD_FEED))
    assert v['verdict'] == cc.UNVERIFIED and '202609110358' in v['reason']
    assert check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=SCAN_INFO_LEGACY))['verdict'] == cc.UNVERIFIED


def test_missing_scan_info_is_unverified(profile):
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=None))
    assert v['verdict'] == cc.UNVERIFIED and 'Scan Information' in v['reason']


def test_uncredentialed_remote_only_is_unverified(profile):
    v = check(profile, host([(48243, PHP_REMOTE.replace('7.2.34', '8.4.27'))], scan=SCAN_INFO_UNCREDENTIALED))
    assert v['verdict'] == cc.UNVERIFIED and 'credentialed' in v['reason']


def test_component_checks_off_is_unverified(profile):
    v = check(profile, host([(216936, PHP_UNIX_COMPONENT_PATCHED)], scan=SCAN_INFO_NO_COMPONENTS))
    assert v['verdict'] == cc.UNVERIFIED and 'Assess component installs' in v['reason']


def test_fixed_finding_is_patched(profile):
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], [(369483, 'FIXED')]))
    assert v['verdict'] == cc.PATCHED and 'fixed' in v['reason']


def test_fixed_version_is_patched(profile):
    v = check(profile, host([(216936, PHP_UNIX_COMPONENT_PATCHED)]))
    assert v['verdict'] == cc.PATCHED and 'includes the fix' in v['reason']


def test_trusted_scan_without_finding(profile):
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)]))
    assert v['verdict'] == cc.NO_FINDING


def test_notes(profile):
    early = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=SCAN_INFO_EARLY_FEED))
    assert early['verdict'] == cc.NO_FINDING and any('first days' in n for n in early['notes'])
    no_unpatched = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=SCAN_INFO_NO_UNPATCHED))
    assert any('Unpatched' in n for n in no_unpatched['notes'])


def test_detection_only_without_version(profile):
    # The plugin fired but printed nothing parseable: still a PHP host, judged by its scan.
    h = host([(216936, '')], scan=SCAN_INFO_OLD_FEED)
    assert h['installs'] and check(profile, h)['verdict'] == cc.UNVERIFIED


def test_latest_scan_info_wins():
    h = cc.new_host('h', 'h', None)
    cc.set_scan(h, cc.parse_scan_info(SCAN_INFO_NEW), '2026-10-25T00:00:00Z')
    cc.set_scan(h, cc.parse_scan_info(SCAN_INFO_OLD_FEED), '2026-09-11T00:00:00Z')
    assert h['scan']['feed'] == '202610250523'


def test_distro_php_on_a_branch_without_a_fix_needs_unpatched_checks(profile):
    # Some vendors won't fix branches PHP no longer supports; only the unpatched checks report them.
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=SCAN_INFO_NO_UNPATCHED))
    assert v['verdict'] == cc.UNVERIFIED and 'no upstream fix' in v['reason'] and 'Unpatched' in v['action']
    assert check(profile, host([(216936, PHP_UNIX_DISTRO)]))['verdict'] == cc.NO_FINDING
    fixed = check(profile, host([(216936, PHP_UNIX_DISTRO)], [(370210, 'FIXED')], scan=SCAN_INFO_NO_UNPATCHED))
    assert fixed['verdict'] == cc.PATCHED


def test_note_when_the_scan_predates_php_fpm_detection(profile):
    before = SCAN_INFO_NEW.replace('202610250523', '202610260000')
    v = check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=before))
    assert any('PHP-FPM' in n and '202610271613' in n for n in v['notes'])
    after = SCAN_INFO_NEW.replace('202610250523', '202610280100')
    assert not any('PHP-FPM' in n for n in check(profile, host([(216936, PHP_UNIX_DISTRO)], scan=after))['notes'])
    # The Unix detection change doesn't apply to hosts with Windows installs.
    windows = check(profile, host([(200476, PHP_UNIX_COMPONENT_PATCHED)], scan=before))
    assert not any('PHP-FPM' in n for n in windows['notes'])


def test_version_wrapped_in_markup_is_still_graded(profile):
    # A version read from a phpinfo() page can carry its surrounding HTML.
    assert cc.grade('</td><td class="v">8.4.27 </td>', profile) == ('fixed', None)
    assert cc.grade('</td><td class="v">8.4.26 </td>', profile) == ('fixed-available', '8.4.27')
