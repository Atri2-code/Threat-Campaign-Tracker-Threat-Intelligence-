"""
reporter.py — Structured campaign threat report generator.
"""
from datetime import timezone
from correlator import Campaign, Artifact

SEVERITY_LABEL = {
    'critical': '🔴 CRITICAL',
    'high':     '🟠 HIGH',
    'medium':   '🟡 MEDIUM',
    'low':      '🔵 LOW',
}

ARTIFACT_ICON = {'email': '📧', 'url': '🔗', 'file': '📄'}


def _fmt_dt(dt) -> str:
    return dt.strftime('%Y-%m-%d %H:%M UTC')


def generate(campaigns: list[Campaign]) -> str:
    from datetime import datetime
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    total_artifacts = sum(len(c.artifacts) for c in campaigns)
    critical = sum(1 for c in campaigns if c.severity == 'critical')
    high     = sum(1 for c in campaigns if c.severity == 'high')

    lines = [
        '# Threat Campaign Tracking Report',
        f'*Generated: {now}*',
        '', '---', '',
        '## Executive Summary', '',
        f'| Metric | Value |',
        f'|--------|-------|',
        f'| Campaigns identified | {len(campaigns)} |',
        f'| Total artifacts correlated | {total_artifacts} |',
        f'| Critical campaigns | {critical} |',
        f'| High severity campaigns | {high} |',
        '', '---', '',
    ]

    for camp in sorted(campaigns, key=lambda c: ['critical','high','medium','low'].index(c.severity)):
        lines += [
            f'## {camp.id} — {SEVERITY_LABEL[camp.severity]}',
            '',
            f'| Field | Value |',
            f'|-------|-------|',
            f'| Artifacts | {len(camp.artifacts)} |',
            f'| First seen | {_fmt_dt(camp.first_seen)} |',
            f'| Last seen | {_fmt_dt(camp.last_seen)} |',
            f'| Tags | {", ".join(sorted(camp.all_tags))} |',
            f'| Shared IOCs | {camp.ioc_count} |',
            '',
        ]

        if camp.shared_domains:
            lines.append('**Shared domains:**')
            for d in sorted(camp.shared_domains):
                lines.append(f'- `{d}`')
            lines.append('')

        if camp.shared_ips:
            lines.append('**Shared IPs:**')
            for ip in sorted(camp.shared_ips):
                lines.append(f'- `{ip}`')
            lines.append('')

        if camp.shared_hashes:
            lines.append('**Shared hashes:**')
            for h in sorted(camp.shared_hashes):
                lines.append(f'- `{h}`')
            lines.append('')

        lines.append('**Artifact timeline:**')
        lines.append('')
        lines.append('| ID | Type | Source | Timestamp | Domains | IPs |')
        lines.append('|----|------|--------|-----------|---------|-----|')
        for art in camp.artifacts:
            icon = ARTIFACT_ICON.get(art.type, '?')
            lines.append(
                f'| {art.id} | {icon} {art.type} | {art.source} | '
                f'{_fmt_dt(art.timestamp)} | {", ".join(art.domains) or "—"} | '
                f'{", ".join(art.ips) or "—"} |'
            )

        lines += ['', '**Recommended actions:**', '']
        if camp.severity == 'critical':
            lines += [
                '- ⛔ Immediate escalation — ransomware/dropper indicators present',
                '- ⛔ Block all shared IPs and domains at perimeter',
                '- ⛔ Hunt across endpoints for shared file hashes',
                '- ⛔ Isolate any affected systems immediately',
                '- ⛔ Submit all IOCs to MISP / threat sharing platform',
            ]
        elif camp.severity in ('high', 'medium'):
            lines += [
                '- ⚠️  Block shared domains and IPs at email gateway and proxy',
                '- ⚠️  Alert SOC for active monitoring',
                '- ⚠️  Enrich IOCs via VirusTotal / Shodan',
                '- ⚠️  Search SIEM for historical hits on shared IOCs',
            ]
        else:
            lines += ['- ℹ️  Add IOCs to watchlist', '- ℹ️  Monitor for recurrence']

        lines += ['', '---', '']

    return '\n'.join(lines)
