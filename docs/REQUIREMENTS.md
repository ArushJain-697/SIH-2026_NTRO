# TRACE — Requirements Mapping

This document maps the problem statement requirements (a–e) to the TRACE architecture, code, and tests.

## a) Parse and classify packets
- **Code**: `internal/pcap` (streaming parsing of classic pcap and pcapng), `internal/netdec` (link layers, IPv4/v6, IKE/ESP/AH classification).
- **Test**: `internal/pcap/reader_test.go`, `internal/netdec/decode_test.go`
- **Coverage**: 100% of packets accounted for (Skipped reason accounting prevents silent empty success on non-IPsec captures).

## b) Cryptographic evidence and negotiation
- **Code**: `internal/ike` (IKEv1 and IKEv2 payload parsers), `internal/iana` (typed registry), `internal/evidence` (ledger).
- **Test**: `internal/engine/engine_test.go` (asserts that AES-GCM and AES-CBC are correctly extracted and never UNKNOWN).
- **Coverage**: Full parsing of IKE SA payloads into typed proposals, checking if selected matches offered.

## c) Security baseline assessment
- **Code**: `internal/policy` (versioned JSON baseline of algorithms and classes), `internal/assess` (Controls C01-C13, worst-case risk, score, bounds).
- **Test**: `internal/engine/engine_test.go`, public PCAP golden tests.
- **Coverage**: Evaluates 13 controls. Minimum coverage gate (70%) prevents awarding an "A" on 23% coverage.

## d) Traffic indicators and AI
- **Code**: `internal/ipsec` (ESP SA pairing, sequence tracking, gaps, duplicate counters).
- **Status**: Implemented deterministic indicators (gaps, regressions, rekey detection). 
- **AI Labeling (Phase E)**: Designed to only add labels and priority, never alter control status. (Planned/Stubbed in MVP).

## e) Self-contained reporting and API
- **Code**: `internal/report` (HTML executive and technical reports), `cmd/trace` (CLI text report), `internal/engine` (trace.result.v1 output).
- **Status**: Implemented HTML generator with dark theme, evidence citations, and threat matrix.
