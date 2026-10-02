# TRACE — Forensic IPsec Tunnel Analyzer

[![CI](https://github.com/SIH-2026/trace/actions/workflows/ci.yml/badge.svg)](https://github.com/SIH-2026/trace/actions)

TRACE extracts cryptographic evidence from IPsec tunnel captures, evaluates it
against versioned security baselines (RFC 8221, RFC 8247), and produces graded
assessments with cited findings and remediation guidance.

## What TRACE Proves

Given a packet capture (pcap/pcapng) and optionally gateway configuration facts:

- **13 security controls** (C01–C13) evaluated against RFC baselines
- **Score, Coverage, Risk** with honest bounds and a coverage gate
- **Findings** with severity, packet evidence, RFC references, and `swanctl.conf` fix lines
- **Threat matrix** mapped to MITRE ATT&CK technique IDs
- Self-contained HTML reports (executive and technical)

## Quick Start

```bash
# Build
make build

# Analyze a capture
./bin/trace analyze capture.pcap

# With gateway facts for full coverage
./bin/trace analyze capture.pcap --gateway facts.json

# Strict profile
./bin/trace analyze capture.pcap --profile strict

# JSON output
./bin/trace analyze capture.pcap --json
```

## Design Decisions

| Decision | Choice |
|---|---|
| Language | Go 1.22, standard library only |
| State | Per-analysis, no global workspace |
| Evidence | Structured `{alg, key_bits, icv_bits}`, never string-matched |
| Policy | Versioned JSON baseline, profiles: `trace-default`, `strict` |
| Scoring | Coverage gate at 70% for letter grades |
| AI | Labels traffic patterns (INFERRED), never changes verdicts |

## Architecture

```
cmd/trace/          CLI entry point
internal/
  pcap/             Streaming pcap/pcapng reader
  netdec/           Link-layer, IP, fragment, decoder
  iana/             Typed IANA registry of transforms
  ike/              IKE header, payloads, negotiation
  ipsec/            ESP/AH SA inventory
  evidence/         Evidence ledger with statuses
  policy/           Versioned baselines and profiles
  assess/           Controls C01-C13, scoring, risk
  engine/           Analysis pipeline
  report/           HTML report generators
  testutil/         Capture builders for testing
```

## Controls

| ID | Control | Weight |
|---|---|---|
| C01 | IKE Version | 10 |
| C02 | IKE Encryption | 25 |
| C03 | Integrity and PRF | 15 |
| C04 | DH Group | 20 |
| C05 | Weak Offers | 15 |
| C06 | Negotiation Consistency | 10 |
| C07 | Peer Authentication | 20 |
| C08 | Child SA Suite | 15 |
| C09 | Perfect Forward Secrecy | 15 |
| C10 | SA Lifetimes | 10 |
| C11 | Anti-Replay Window | 10 |
| C12 | Identity Exposure | 5 |
| C13 | Protocol Hygiene | 5 |

## Limits

- **No decryption.** TRACE analyses only cleartext IKE negotiation and ESP/AH metadata.
- **Coverage depends on visibility.** Without gateway configuration, C08/C09/C11 are UNKNOWN.
- **No NAT claim from port 4500.** NAT is derived from hash comparison, not port numbers.
- **AI labels traffic patterns only.** It never changes control status, score, or risk.

## Prior Art

We reviewed a public MIT-licensed IPsec analyzer for design ideas (evidence
statuses, offered-vs-selected, separating score from coverage). No source code
was reused. See `docs/PRIOR-ART.md`.

## License

MIT
