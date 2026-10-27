"""The skill's structure, and that no internal references reach the public files."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = [ROOT / 'README.md', ROOT / 'SKILL.md', *sorted((ROOT / 'references').glob('*.md')),
          *sorted((ROOT / 'profiles').glob('*.json')), ROOT / 'scripts' / 'coverage_check.py']
INTERNAL = re.compile(
    r'(accessKey=[0-9a-f]{20,}|secretKey=[0-9a-f]{20,}|\.eng\.tenable|tenablesecurity\.com|artifactory|netskope'
    r'|atlassian\.net|slack\.com|\bqa-(staging|milestone|develop)\b|\b(RES|RESSTG|CS|FR|DG|SC|NES|PM|RDC|AIP)-\d{3,}\b'
    r'|\b10\.254\.|\b172\.26\.)',
    re.I,
)


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
