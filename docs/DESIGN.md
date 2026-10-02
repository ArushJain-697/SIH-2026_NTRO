# TRACE Design Document

## What TRACE Proves

TRACE is a forensic IPsec tunnel analyzer. Given a packet capture (pcap/pcapng)
and optionally gateway configuration facts, TRACE extracts cryptographic evidence,
evaluates it against a versioned security policy, and produces a graded assessment
with cited findings and remediation guidance.

## Evidence Model

Every fact TRACE reports has a **status** and **provenance**:

| Status | Meaning |
|---|---|
| OBSERVED | Directly read from a packet field, with packet number |
| DERIVED | Computed from observed evidence (e.g., NAT from hash comparison) |
| INFERRED | Statistical guess from AI or heuristic |
| GATEWAY_VERIFIED | From a trusted gateway configuration source |
| CONFLICTING | Two sources disagree on the same property |
| UNKNOWN | No evidence available |

Evidence is structured: `{alg, key_bits, icv_bits, registry_id}`, never string-matched.

## Controls

13 security controls (C01–C13), each with:
- Status: PASS / FAIL / UNKNOWN / N/A
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Evidence IDs with packet references
- RFC reference
- Fix template (strongSwan swanctl.conf syntax)

## Scoring Gate

- `Score = 100 · P / E` (pass ratio over evaluated controls, weighted)
- `Coverage = 100 · E / A` (evaluated over all applicable controls)
- Grade requires ≥ 70% coverage; below that, only bounds are shown
- CRITICAL failure caps score at 40

## Risk

`Risk = 100 − worst-case bound`. Levels: LOW ≤ 20, MODERATE ≤ 45, HIGH ≤ 70, CRITICAL > 70.
Below 40% coverage: UNDETERMINED.

## AI Boundary

The classifier labels traffic patterns (INFERRED status). It may:
- Raise finding priority
- Add INFO/LOW indicator findings
- Show cross-check conflicts

It may NOT change any control status, score, coverage, or risk.

## Result Schema

Output is `trace.result.v1` (JSON), the contract for the CLI, API, reports, and
the future console.

## Packages

| Package | Concern |
|---|---|
| `internal/pcap` | Streaming pcap/pcapng reader |
| `internal/netdec` | Link, IP, fragment reassembly, decoder |
| `internal/iana` | Typed IANA registry of transforms |
| `internal/ike` | IKE header, payloads, negotiation |
| `internal/ipsec` | ESP/AH SA inventory |
| `internal/evidence` | Evidence ledger |
| `internal/policy` | Versioned baseline and profiles |
| `internal/assess` | Controls C01–C13, scoring, risk, findings |
| `internal/gateway` | Gateway facts import |
| `internal/flow` | Flow windows and features |
| `internal/ai` | Model format, inference, explanations |
| `internal/engine` | Analysis pipeline |
| `internal/store` | Per-analysis on-disk store |
| `internal/api` | HTTP API |
| `internal/report` | HTML/PDF/JSON reports |
| `internal/explain` | Deterministic explainer + optional LLM |
| `cmd/trace` | CLI entry point |
