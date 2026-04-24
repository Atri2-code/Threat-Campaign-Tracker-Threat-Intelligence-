# threat-campaign-tracker (Threat Intelligence)

> Correlates IOCs across threat artifacts — emails, URLs, files — clusters them into campaigns using shared infrastructure, and tracks adversary activity over time.

Built around the core analyst workflow: ingest artifacts from multiple sources, find the connecting tissue (shared IPs, domains, hashes), and surface the campaign picture rather than isolated indicators.

---

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/threat-campaign-tracker.git
cd threat-campaign-tracker
python src/track.py --input data/artifacts/artifacts.json --output reports/
```

No external dependencies. Pure Python standard library.

---

## Sample output

```
threat-campaign-tracker
────────────────────────────────────────
Artifacts loaded : 7
Campaigns found  : 3

  🔴 CAMP-001 [CRITICAL ] 3 artifacts | 2 shared IOCs | tags: credential-harvest, dropper, paypal-lure
  🟠 CAMP-002 [HIGH     ] 3 artifacts | 2 shared IOCs | tags: credential-harvest, microsoft-lure, ransomware
  🔵 CAMP-003 [LOW      ] 1 artifact  | 0 shared IOCs | tags: amazon-lure, credential-harvest

  Report saved → reports/campaign_report.md
```

---

## How correlation works

Artifacts are clustered using a **union-find** algorithm — the same approach used in graph-based threat intelligence platforms:

1. Build a reverse index: every IOC value → list of artifact IDs that contain it
2. Union any two artifacts that share a domain, IP, or file hash
3. Find connected components → each component is a campaign
4. Compute shared IOCs (appear in 2+ artifacts within the campaign)
5. Score severity based on tags and artifact count

This correctly handles **transitive correlation**: if Artifact A shares an IP with B, and B shares a domain with C, all three are grouped into the same campaign even if A and C share nothing directly.

---

## Artifact input format

```json
[
  {
    "id": "ART-001",
    "type": "email",
    "source": "inbox_sweep",
    "timestamp": "2025-04-01T08:12:00Z",
    "iocs": {
      "domains": ["paypa1-verify.xyz"],
      "urls": ["http://paypa1-verify.xyz/login"],
      "ips": ["185.220.101.45"],
      "hashes": [],
      "emails": ["security@paypa1-verify.xyz"]
    },
    "tags": ["credential-harvest", "paypal-lure"]
  }
]
```

Sources can be mixed: email sweeps, proxy logs, sandbox reports, threat feeds.

---

## Severity scoring

| Condition | Severity |
|-----------|----------|
| `ransomware` or `dropper` tag present | Critical |
| 3+ correlated artifacts | High |
| 2 correlated artifacts | Medium |
| Single artifact, no shared IOCs | Low |

---

## Project structure

```
threat-campaign-tracker/
├── src/
│   ├── track.py          # CLI entry point
│   ├── correlator.py     # Union-find IOC correlation + campaign clustering
│   └── reporter.py       # Markdown report generator
├── data/
│   └── artifacts/
│       └── artifacts.json   # Sample artifact dataset (7 artifacts, 3 campaigns)
├── reports/              # Generated campaign reports (gitignored)
├── tests/
│   └── test_correlator.py   # 8 unit tests
└── README.md
```

---

## Running tests

```bash
python tests/test_correlator.py
```

---

## Skills demonstrated

| Security competency | Implementation |
|---|---|
| Threat campaign tracking | IOC correlation across email, URL, file artifacts |
| IOC analysis | Domain, IP, hash, email extraction and indexing |
| Graph-based clustering | Union-find algorithm for transitive correlation |
| Reverse engineering attacks | Artifact timeline reconstruction per campaign |
| Python automation | Batch artifact processing, zero external deps |
| Threat reporting | Campaign severity scoring + recommended actions |

---

## Roadmap

- [ ] MISP event export for threat sharing
- [ ] VirusTotal API enrichment per IOC
- [ ] STIX/TAXII output format
- [ ] ATT&CK TTP tagging per campaign
- [ ] Time-window decay (age out stale IOCs)

---

## License

MIT
