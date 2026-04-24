#!/usr/bin/env python3
"""
track.py — Threat campaign tracking CLI.

Loads artifact JSON, correlates IOCs into campaigns,
and produces a Markdown report with timeline and recommendations.

Usage:
  python src/track.py --input data/artifacts/artifacts.json --output reports/
"""
import argparse, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from correlator import load_artifacts, correlate
from reporter  import generate

SEVERITY_ICON = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}


def main():
    p = argparse.ArgumentParser(description='Threat campaign tracker')
    p.add_argument('--input',  default='data/artifacts/artifacts.json')
    p.add_argument('--output', default='reports/')
    a = p.parse_args()

    artifacts = load_artifacts(a.input)
    campaigns = correlate(artifacts)
    report    = generate(campaigns)

    os.makedirs(a.output, exist_ok=True)
    out = Path(a.output) / 'campaign_report.md'
    out.write_text(report)

    print(f'\nthreat-campaign-tracker')
    print(f'{"─" * 40}')
    print(f'Artifacts loaded : {len(artifacts)}')
    print(f'Campaigns found  : {len(campaigns)}\n')

    sev_order = ['critical', 'high', 'medium', 'low']
    for camp in sorted(campaigns, key=lambda c: sev_order.index(c.severity)):
        icon = SEVERITY_ICON[camp.severity]
        print(f'  {icon} {camp.id} [{camp.severity.upper():8}] '
              f'{len(camp.artifacts)} artifacts | '
              f'{camp.ioc_count} shared IOCs | '
              f'tags: {", ".join(sorted(camp.all_tags))}')

    print(f'\n  Report saved → {out}\n')


if __name__ == '__main__':
    main()
