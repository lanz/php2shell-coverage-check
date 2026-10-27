"""Shared fixtures. Plugin outputs copy the formats seen on live scanners, with documentation
addresses (RFC 5737) and made-up names."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))

import coverage_check  # noqa: E402

SCAN_INFO_NEW = """Information about this scan :

Nessus version : 10.13.0
Nessus build : R20073
Plugin feed version : 202610250523
Scanner edition used : Nessus
Scanner OS : LINUX
Scan type : Normal
Scan name : Weekly internal
Scan policy used : Advanced Scan
Scanner IP : 192.0.2.250
Thorough tests : yes
Experimental tests : no
Scan for Unpatched Vulnerabilities : yes
Plugin debugging enabled : no
Paranoia level : 1
Assess component installs : yes
Report verbosity : 1
Safe checks : yes
Credentialed checks : yes, as 'svc-scan' via ssh
Scan Start Date : 2026/10/25 2:10 UTC
"""

SCAN_INFO_OLD_FEED = SCAN_INFO_NEW.replace('202610250523', '202609110358')
SCAN_INFO_UNCREDENTIALED = SCAN_INFO_NEW.replace("yes, as 'svc-scan' via ssh", 'no')
SCAN_INFO_EARLY_FEED = SCAN_INFO_NEW.replace('202610250523', '202610211800')
SCAN_INFO_NO_COMPONENTS = SCAN_INFO_NEW.replace('Assess component installs : yes', 'Assess component installs : no')
SCAN_INFO_NO_UNPATCHED = SCAN_INFO_NEW.replace('Scan for Unpatched Vulnerabilities : yes', 'Scan for Unpatched Vulnerabilities : no')
# Older scanners omit several fields.
SCAN_INFO_LEGACY = """Information about this scan :

Nessus version : 10.4.2
Plugin feed version : 202301251200
Scanner edition used : Nessus
Scan type : Normal
Scan policy used : Basic Network Scan
Thorough tests : no
Credentialed checks : no
"""

PHP_UNIX_TWO = """
Nessus detected 2 installs of PHP:

  Path               : /usr/bin/php
  Version            : 8.0.30
  Associated Package : php-cli-8.0.30-1.module+el8.8.0+21196+6feda
  INI file           : /etc/php.ini
  INI source         : PHP binary grep
  Managed by OS      : True

  Path               : /opt/app/php/bin/php
  Version            : 8.3.12
  INI file           : /opt/app/php/etc/php.ini
  INI source         : PHP binary grep
  Is Component       : True
"""

PHP_UNIX_DISTRO = """
  Path               : /usr/bin/php
  Version            : 8.0.30
  Associated Package : php-cli-8.0.30-3.el9_6.x86_64
  INI file           : /etc/php.ini
  INI source         : PHP binary grep
  Managed by OS      : True
"""

PHP_UNIX_COMPONENT_PATCHED = """
  Path         : /opt/vendor/support/bin/php
  Version      : 8.2.35
  INI file     : /opt/vendor/support/etc/php.ini
  INI source   : PHP binary grep
  Is Component : True
"""

PHP_REMOTE = """
Nessus was able to identify the following PHP version
information :

  Version : 7.2.34
  Source  : X-Powered-By: PHP/7.2.34
  Backported : 0
"""

PHP_REMOTE_BACKPORTED = """
  Version : 7.4.33
  Source  : X-Powered-By: PHP/7.4.33
  Backported : 1
"""

PHP_UNSUPPORTED = """
  Source              : X-Powered-By: PHP/7.2.34
  Installed version   : 7.2.34
  End of support date : 2020/11/30
  Announcement        : http://php.net/supported-versions.php
  Supported versions  : 8.2.x / 8.3.x / 8.4.x / 8.5.x
"""

CVE_OUTPUT = """
  Path                    : /opt/vendor/support/modules/libphp.so
  Installed version       : 8.2.31
  Fixed version           : 8.2.35
  Potential Vulnerability : Component
"""


@pytest.fixture
def profile():
    return coverage_check.load_profile(None)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv('PHP2SHELL_CHECK_HOME', str(tmp_path / 'home'))
    for var in ('TIO_ACCESS_KEY', 'TIO_SECRET_KEY', 'TIO_URL', 'TSC_ACCESS_KEY', 'TSC_SECRET_KEY', 'TSC_URL'):
        monkeypatch.delenv(var, raising=False)
