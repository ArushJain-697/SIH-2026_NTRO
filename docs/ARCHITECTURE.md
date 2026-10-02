# TRACE — Architecture

TRACE is a single-binary, streaming IPsec tunnel analyzer built in Go 1.22. It is designed to be deterministic, dependency-free (standard library only), and honest about its limits.

## Core Pipeline

1. **Reader (`internal/pcap`)**: Streaming parser for classic pcap and pcapng. Zero-copy where possible. Memory is bounded.
2. **Decoder (`internal/netdec`)**: Unwraps link layers (Ethernet, VLAN, SLL, Raw IP) and IP headers. Classifies UDP 500/4500 and protocol 50/51 into IKE, ESP, AH. Tracks skipped packets with explicit reasons.
3. **IKE Parser (`internal/ike`)**: Fully parses IKEv1 and IKEv2 exchanges. Maps transform IDs to strings using the `internal/iana` typed registry to prevent string-matching bugs. Matches selected proposals against offered proposals.
4. **IPsec Inventory (`internal/ipsec`)**: Groups ESP/AH packets into directional SAs. Detects rekeys, sequence gaps, duplicates.
5. **Ledger (`internal/evidence`)**: Every fact extracted is an `Evidence` item with a status (OBSERVED, DERIVED, INFERRED, GATEWAY_VERIFIED), confidence, and packet-number provenance.
6. **Assessment (`internal/assess`)**: Evaluates 13 controls (C01–C13) based on the evidence and a versioned policy baseline (`internal/policy`). Calculates Score, Coverage, and Risk with strict lower/upper bounds.
7. **Engine & Reporting (`internal/engine`, `internal/report`)**: Coordinates the pipeline and emits the final JSON (`trace.result.v1`) and HTML reports.

## Roadmap & Features Not Yet Built

The following components are defined in the build map but deferred/unimplemented in the current codebase:

- **AI Layer (`internal/flow`, `internal/ai`, Python training toolkit)**: ML-based traffic classification and anomaly detection.
- **Gateway Sync (`internal/gateway`)**: VICI client and XFRM parsers to import gateway facts and resolve unknowns.
- **Full API Server & Lab Network**: The HTTP API, offline container lab, and test generators.

*(See TRACE-BUILDMAP-v2.md for the complete design details).*
