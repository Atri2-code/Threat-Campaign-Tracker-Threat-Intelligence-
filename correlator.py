"""
correlator.py — IOC correlation and campaign clustering engine.

Groups threat artifacts into campaigns by finding shared IOCs:
  - Shared domains
  - Shared IPs
  - Shared file hashes
  - Shared tags

Uses a union-find (disjoint set) structure to efficiently merge
artifacts that share any IOC into the same campaign cluster.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json


@dataclass
class Artifact:
    id: str
    type: str           # email | url | file
    source: str
    timestamp: datetime
    domains: list[str]
    urls: list[str]
    ips: list[str]
    hashes: list[str]
    emails: list[str]
    tags: list[str]

    @classmethod
    def from_dict(cls, d: dict) -> 'Artifact':
        iocs = d.get('iocs', {})
        return cls(
            id=d['id'], type=d['type'], source=d['source'],
            timestamp=datetime.fromisoformat(d['timestamp'].replace('Z', '+00:00')),
            domains=iocs.get('domains', []),
            urls=iocs.get('urls', []),
            ips=iocs.get('ips', []),
            hashes=iocs.get('hashes', []),
            emails=iocs.get('emails', []),
            tags=d.get('tags', []),
        )

    def all_iocs(self) -> dict[str, list[str]]:
        return {
            'domains': self.domains, 'ips': self.ips,
            'hashes': self.hashes, 'emails': self.emails,
        }


@dataclass
class Campaign:
    id: str
    artifacts: list[Artifact]
    shared_domains: set[str] = field(default_factory=set)
    shared_ips: set[str]     = field(default_factory=set)
    shared_hashes: set[str]  = field(default_factory=set)
    all_tags: set[str]       = field(default_factory=set)

    @property
    def first_seen(self) -> datetime:
        return min(a.timestamp for a in self.artifacts)

    @property
    def last_seen(self) -> datetime:
        return max(a.timestamp for a in self.artifacts)

    @property
    def severity(self) -> str:
        if 'ransomware' in self.all_tags or 'dropper' in self.all_tags:
            return 'critical'
        if len(self.artifacts) >= 3:
            return 'high'
        if len(self.artifacts) >= 2:
            return 'medium'
        return 'low'

    @property
    def ioc_count(self) -> int:
        return len(self.shared_domains) + len(self.shared_ips) + len(self.shared_hashes)


class UnionFind:
    def __init__(self, ids: list[str]):
        self.parent = {i: i for i in ids}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def correlate(artifacts: list[Artifact]) -> list[Campaign]:
    """
    Clusters artifacts into campaigns using shared IOC correlation.
    Two artifacts belong to the same campaign if they share at least
    one domain, IP address, or file hash.
    """
    uf = UnionFind([a.id for a in artifacts])

    # Build reverse index: IOC value → list of artifact IDs
    ioc_index: dict[str, list[str]] = defaultdict(list)
    for art in artifacts:
        for ioc_list in [art.domains, art.ips, art.hashes]:
            for ioc in ioc_list:
                ioc_index[ioc.lower()].append(art.id)

    # Union artifacts that share any IOC
    for ioc, art_ids in ioc_index.items():
        for i in range(1, len(art_ids)):
            uf.union(art_ids[0], art_ids[i])

    # Group by root
    groups: dict[str, list[Artifact]] = defaultdict(list)
    art_by_id = {a.id: a for a in artifacts}
    for art in artifacts:
        root = uf.find(art.id)
        groups[root].append(art)

    campaigns = []
    for i, (root, group) in enumerate(sorted(groups.items()), start=1):
        # Compute shared IOCs (appear in 2+ artifacts)
        domain_count: dict[str, int] = defaultdict(int)
        ip_count:     dict[str, int] = defaultdict(int)
        hash_count:   dict[str, int] = defaultdict(int)
        all_tags:     set[str]       = set()

        for art in group:
            for d in art.domains: domain_count[d] += 1
            for ip in art.ips:    ip_count[ip]    += 1
            for h in art.hashes:  hash_count[h]   += 1
            all_tags.update(art.tags)

        campaigns.append(Campaign(
            id=f'CAMP-{i:03d}',
            artifacts=sorted(group, key=lambda a: a.timestamp),
            shared_domains={d for d, c in domain_count.items() if c > 1},
            shared_ips    ={ip for ip, c in ip_count.items()   if c > 1},
            shared_hashes ={h for h, c in hash_count.items()   if c > 1},
            all_tags=all_tags,
        ))

    return sorted(campaigns, key=lambda c: c.severity,
                  reverse=False)   # critical first


def load_artifacts(path: str) -> list[Artifact]:
    with open(path) as f:
        return [Artifact.from_dict(d) for d in json.load(f)]
