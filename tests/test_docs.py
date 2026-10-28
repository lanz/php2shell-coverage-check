"""The skill's structure, and that no internal references reach the public files."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = [ROOT / 'README.md', ROOT / 'SKILL.md', *sorted((ROOT / 'references').glob('*.md')),
          *sorted((ROOT / 'profiles').glob('*.json')), ROOT / 'scripts' / 'coverage_check.py']
# Things that must never be published: API keys and private keys. Names specific to a
# contributor's own environment go in tests/internal-patterns.txt (one regular expression
# per line), which git ignores.
SECRETS = [r'accessKey=[0-9a-f]{20,}', r'secretKey=[0-9a-f]{20,}', r'BEGIN [A-Z ]*PRIVATE KEY']
LOCAL_PATTERNS = Path(__file__).resolve().parent / 'internal-patterns.txt'


def local_patterns():
    if not LOCAL_PATTERNS.exists():
        return []
    lines = LOCAL_PATTERNS.read_text(encoding='utf-8').splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith('#')]


INTERNAL = re.compile('|'.join(f'(?:{p})' for p in SECRETS + local_patterns()), re.I)


@pytest.mark.parametrize('path', PUBLIC, ids=[p.name for p in PUBLIC])
def test_no_internal_references(path):
    hit = INTERNAL.search(path.read_text(encoding='utf-8'))
    assert not hit, f'{path.name}: {hit.group(0)}'


def test_skill_frontmatter():
    text = (ROOT / 'SKILL.md').read_text(encoding='utf-8')
    front = text.split('---')[1]
    fields = dict(line.split(':', 1) for line in front.strip().splitlines() if ':' in line and not line.startswith(' '))
    assert fields['name'].strip() == 'php2shell-coverage-check'
    assert 0 < len(fields['description'].strip()) <= 1024
    assert fields['license'].strip() == 'MIT'


def test_referenced_files_exist():
    text = (ROOT / 'SKILL.md').read_text(encoding='utf-8') + (ROOT / 'README.md').read_text(encoding='utf-8')
    for ref in set(re.findall(r'(references/[\w.-]+\.md|scripts/[\w.-]+\.py|profiles/[\w.-]+\.json)', text)):
        assert (ROOT / ref).exists(), ref


def test_profile_is_consistent():
    profile = json.loads((ROOT / 'profiles' / 'php2shell.json').read_text(encoding='utf-8'))
    assert all(re.fullmatch(r'CVE-\d{4}-\d{4,}', c) for c in profile['cves'])
    det = profile['detection']
    assert re.fullmatch(r'\d{12}', det['min_feed']) and det['min_feed'] <= det['recommended_feed']
    assert det['min_feed'].startswith(det['first_plugin_published'].replace('-', ''))
    for branch, fixed in profile['versions']['fixed'].items():
        assert fixed.startswith(branch + '.')


def test_detection_changes_are_well_formed():
    profile = json.loads((ROOT / 'profiles' / 'php2shell.json').read_text(encoding='utf-8'))
    for change in profile['detection'].get('detection_changes', []):
        assert re.fullmatch(r'\d{12}', change['feed']) and change['feed'] >= profile['detection']['min_feed']
        assert change['change'] and change['missed']
