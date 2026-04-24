"""
test_correlator.py — Unit tests for the campaign correlation engine.
"""
import sys
from pathlib import Path
from datetime import datetime, timezone
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from correlator import Artifact, correlate


def make_artifact(id, domains=None, ips=None, hashes=None, tags=None):
    return Artifact(
        id=id, type='email', source='test',
        timestamp=datetime(2025, 4, 1, tzinfo=timezone.utc),
        domains=domains or [], urls=[], ips=ips or [],
        hashes=hashes or [], emails=[], tags=tags or [],
    )


def test_no_shared_iocs_separate_campaigns():
    arts = [
        make_artifact('A', domains=['evil.xyz']),
        make_artifact('B', domains=['other.tk']),
    ]
    campaigns = correlate(arts)
    assert len(campaigns) == 2
    print('  PASS  no shared IOCs → separate campaigns')


def test_shared_domain_merges_campaigns():
    arts = [
        make_artifact('A', domains=['evil.xyz']),
        make_artifact('B', domains=['evil.xyz', 'other.tk']),
    ]
    campaigns = correlate(arts)
    assert len(campaigns) == 1
    assert len(campaigns[0].artifacts) == 2
    print('  PASS  shared domain → merged into one campaign')


def test_shared_ip_merges_campaigns():
    arts = [
        make_artifact('A', ips=['1.2.3.4']),
        make_artifact('B', ips=['1.2.3.4']),
    ]
    campaigns = correlate(arts)
    assert len(campaigns) == 1
    print('  PASS  shared IP → merged into one campaign')


def test_shared_hash_merges_campaigns():
    arts = [
        make_artifact('A', hashes=['abc123']),
        make_artifact('B', hashes=['abc123']),
    ]
    campaigns = correlate(arts)
    assert len(campaigns) == 1
    print('  PASS  shared hash → merged into one campaign')


def test_transitive_correlation():
    # A shares IP with B, B shares domain with C → all in same campaign
    arts = [
        make_artifact('A', ips=['1.2.3.4']),
        make_artifact('B', ips=['1.2.3.4'], domains=['evil.xyz']),
        make_artifact('C', domains=['evil.xyz']),
    ]
    campaigns = correlate(arts)
    assert len(campaigns) == 1
    assert len(campaigns[0].artifacts) == 3
    print('  PASS  transitive correlation (A→B→C) → one campaign')


def test_severity_critical_with_ransomware_tag():
    arts = [make_artifact('A', domains=['mal.xyz'], tags=['ransomware', 'dropper'])]
    campaigns = correlate(arts)
    assert campaigns[0].severity == 'critical'
    print('  PASS  ransomware tag → critical severity')


def test_severity_high_with_3_artifacts():
    arts = [
        make_artifact('A', domains=['shared.xyz']),
        make_artifact('B', domains=['shared.xyz']),
        make_artifact('C', domains=['shared.xyz']),
    ]
    campaigns = correlate(arts)
    assert campaigns[0].severity == 'high'
    print('  PASS  3+ artifacts → high severity')


def test_shared_iocs_correctly_identified():
    arts = [
        make_artifact('A', domains=['evil.xyz', 'unique-a.com'], ips=['1.2.3.4']),
        make_artifact('B', domains=['evil.xyz', 'unique-b.com'], ips=['1.2.3.4']),
    ]
    campaigns = correlate(arts)
    assert 'evil.xyz' in campaigns[0].shared_domains
    assert '1.2.3.4' in campaigns[0].shared_ips
    assert 'unique-a.com' not in campaigns[0].shared_domains
    print('  PASS  shared IOCs correctly identified vs unique IOCs')


if __name__ == '__main__':
    print('\nRunning tests...\n')
    test_no_shared_iocs_separate_campaigns()
    test_shared_domain_merges_campaigns()
    test_shared_ip_merges_campaigns()
    test_shared_hash_merges_campaigns()
    test_transitive_correlation()
    test_severity_critical_with_ransomware_tag()
    test_severity_high_with_3_artifacts()
    test_shared_iocs_correctly_identified()
    print('\nAll tests passed.\n')
