# SIH 26160 — TRACE · BUILD MAP v2 (From scratch, 61 commits)
### Every line of code is ours. The ideas come from the Bible and from what a public IPsec analyzer taught us to do — and to avoid.

**Supersedes** [`TRACE-BUILDMAP.md`](./TRACE-BUILDMAP.md), which planned to import someone else's code. This map has **no import phase**. We write a fresh Go codebase in `~/Documents/TRACE`, from the RFCs and our own design. Frontend is deferred (see Phase K at the end); the demo runs from the CLI, the API and the HTML reports.

**Companions:** [`SIH26160-IPsec-Analyzer-BIBLE.md`](./SIH26160-IPsec-Analyzer-BIBLE.md) (why and what) · [`ALCHEMIST-UNDERSTANDING.md`](./ALCHEMIST-UNDERSTANDING.md) (how the public analyzer behaves, what to keep, what to drop) · `docs/DESIGN.md` in the repo (our design, already committed).

**Repo state today (1 Oct 2026, deadline 5 Oct):** 3 commits done (scaffold, design doc, CI). The classic-pcap reader with tests is written and staged, not committed. **Target: 61 commits.** Commit count is not effort: each ticket is one small, tested change.

---

## 0. Independence rules (how "our own code" stays true)

1. **Write from the specs.** Protocol facts come from RFC 7296, RFC 2409, RFC 4303, RFC 4302, RFC 3948, RFC 3947, RFC 7383, RFC 8221, RFC 8247, RFC 9370, pcap and pcapng format specs, IANA registries. Algorithm tables are built from IANA and **tested against an IANA CSV snapshot** kept in `testdata/iana/`.
2. **Tests first from public captures.** The five Wireshark IPsec sample captures and small generated captures are the ground truth, never another tool's output.
3. **No source is pasted from anywhere.** Names, packages, data shapes and control IDs are ours (`C01`–`C13`, `trace.result.v1`).
4. **Credit the idea, honestly.** `docs/PRIOR-ART.md` says: *"We reviewed a public MIT-licensed IPsec analyzer for design ideas (evidence statuses, offered-vs-selected, separating score from coverage). No source code was reused."* That sentence is true, so it stays in.
5. **Their mistakes are our test cases.** Section 2 lists what went wrong there. Each one becomes a test that must fail before our fix and pass after.

---

## 1. Why this design (what we learned by running a public analyzer, 2026-10-01)

We built a scratch copy of a public IPsec analyzer and fed it the public Wireshark captures. The measured starting point is what TRACE must beat. **These numbers describe their tool, not TRACE.**

| Probe | What that tool did |
|---|---|
| AES-256-GCM IKEv2 capture (cipher plainly visible) | The heaviest control (IKE suite, weight 25) returned **UNKNOWN**. Same on **all four** IKEv2 captures. |
| Same captures, headline | **Grade A, score 100, risk LOW at 23.08% coverage** |
| IKEv1 capture | IKE suite, auth and DH all UNKNOWN; one failed control gave **F / CRITICAL** |
| IKEv2 capture re-wrapped as Linux cooked (SLL) | Upload reported 0 IKE packets, analysis "completed", **no error** |
| 5,000 ESP packets (0.8 MB) | Analysis **failed** (ledger batch cap of 10,000 items) |
| Any API route, no credentials | HTTP 200 |
| Tests | 162 test functions, none open a real capture |

TRACE's answer, in one line each: a **typed algorithm registry** shared by decoder and rules (no name matching), a **coverage gate** on the grade, **worst-case risk**, **loud input errors**, **per-SA aggregation** of ESP, **authenticated API**, and **real-capture golden tests**.

---

## 2. Flaw register → where TRACE avoids it

**V** = reproduced by running it · **S** = confirmed in source · **D** = their own docs admit it. IDs W1–W23 follow Bible §2.3.

| ID | Sev | What went wrong there | How | TRACE ticket |
|---|---|---|---|---|
| W1 | CRIT | Modern AES-GCM/CBC suites judged UNKNOWN (parser name ≠ rule name) | V | #B1 typed registry, #C3, #C9 |
| W2 | CRIT | Letter grade and LOW risk at 23% coverage | V | #C5 gate, #C6 worst-case risk |
| W3 | HIGH | IKEv1 crypto never assessed; one flag gave F/CRITICAL | V | #B5, #B7, #C3, #C6 |
| W4 | HIGH | Auth rule never fires (key name mismatch) | V | #C9 every emitted key consumed |
| W5 | HIGH | ~2,000+ ESP packets kill the analysis | V | #F2 per-SA aggregation |
| W6 | HIGH | Non-Ethernet captures → silent empty success | V | #A3, #A6 |
| W7 | HIGH | 10 s timeouts, parsing inside the upload request | S | #F4, #F5 async jobs |
| W8 | MED | "NAT-T" = port 4500 seen; NAT-D never read | S | #B6 |
| W9 | MED | KE payload not parsed | S | #B4 |
| W10 | MED | Offered transforms stored, never assessed | S | #B7, #C3 (C05) |
| W11 | MED | IKEv1 lifetimes skipped | S | #B5 |
| W12 | MED | No fragment reassembly; IKE_INTERMEDIATE rejected | S | #A5, #B2, #B4 |
| W13 | MED | Confidence depends on the wall clock | S | #C1 |
| W14 | HIGH | Model from 175 captures, one generator, 100% on 35 test captures | D | #E3, #E4 (and every number labelled) |
| W15 | HIGH | "CALIBRATED" is a hard-coded string | V | #E3, #E4 real calibration + ECE |
| W16 | MED | UNKNOWN threshold tuned without held-out OOD | D | #E3 |
| W17 | HIGH | ML never affects the result | S | #E6 (labelled context, invariance test) |
| W18 | MED | SHAP off, anomaly detector not shipped | V | #E2 built-in explanations, #E5 |
| W19 | MED | Train on first window, infer on all | S | #E3 |
| W20 | HIGH | Docker socket mounted into the public service | V | no lab over HTTP (#H3 offline), #J2 |
| W21 | MED | No API auth; all state in RAM; uploads never deleted | V | #F3, #F4 |
| W22 | MED | One global "current workspace" | S | #F1 (state per analysis) |
| W23 | HIGH | Zero real-PCAP tests | V | #I1, #I2, #C9 |
| X3 | HIGH | Plaintext, unauthenticated gRPC | S | no gRPC: one process, JSON over HTTP |
| X4 | HIGH | Capture override runs as root on host network | S | #J2 non-root, read-only image |
| X5 | MED | Report data sent to a third-party LLM, key in URL | S | #G4 built-in explainer by default; LLM optional, masked, header auth |
| X8 | LOW | Model loaded with pickle | S | #E2 JSON model, SHA-256 |

---

## 3. Fixed design decisions (no debate during the build)

| Decision | Choice | Why |
|---|---|---|
| Language | Go 1.22, **standard library only** for the engine and API | no dependency hunting, fast streaming, one static binary |
| Python | training only (`ai/`), needs numpy and scikit-learn | model exported as JSON; nothing Python at runtime |
| API | JSON over HTTP, Go 1.22 `ServeMux` patterns, bearer API keys | small surface, easy to test with `httptest` |
| State | per-analysis directory on disk (`meta.json`, `result.json`, capture) | restart-safe, no database to run |
| Evidence values | structured `{alg, key_bits, icv_bits, registry_id}` | rules compare fields, never strings |
| Policy | versioned JSON baseline + profile selection | compliance baseline is data, not code |
| Packages | `pcap`, `netdec`, `iana`, `ike`, `ipsec`, `evidence`, `policy`, `assess`, `gateway`, `flow`, `ai`, `engine`, `store`, `api`, `report`, `explain` | one concern each |
| Result schema | `trace.result.v1` (JSON) | the contract the future console reads |

### Priority and window tags

| Tag | Meaning |
|---|---|
| 🟥 **CORE** | Fixes a flaw a judge can reproduce in five minutes, or the demo cannot work without it |
| 🟦 **BUILD** | Makes the result better or provable |
| 🟩 **SHOWPIECE** | What judges see and keep |
| 🟨 **SAFETY** | Closes a security hole |
| ⬜ **STRETCH** | Only after every CORE ticket is green |

| Window | Days | Phases |
|---|---|---|
| 🧱 **FOUNDATION** | Thu 1 Oct | A |
| 🌅 **ENGINE** | Fri 2 – Sat 3 Oct | B, C, D |
| 🧪 **INTELLIGENCE** | Sat 3 – Sun 4 Oct | E, F |
| 🌇 **DELIVER** | Sun 4 – Mon 5 Oct | G, H, I, J |

### Ticket rule

- No ticket starts until its blockers pass their **Test**. One ticket = one commit. Commit message is in the ticket.
- `go vet ./... && go test ./... && gofmt -l .` is clean before every commit.
- Every fix has a test that **fails without it**. Tests use the public captures or bytes built by `internal/testutil/capbuild`.
- **Every number on a slide comes from a committed file** (#I4 generates `docs/VALIDATION.md`). Targets are labelled *Target*.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` on every commit.

### Ground rules (Bible §3, still load-bearing)

> No decryption claims. No NAT from port 4500. No unmeasured accuracy. No "calibrated" without an ECE number. No application names ("messaging-like", never "WhatsApp"). No "post-quantum ready": we only **detect** additional key-exchange transforms (RFC 9370) and say so. No certification claims.

---

## Phase 0 — Done

| # | Commit | State |
|---|---|---|
| 1 | `chore: scaffold Go module, licence, Makefile and ignore rules` | ✅ |
| 2 | `docs: TRACE design — evidence model, controls, scoring gate, AI boundary` | ✅ |
| 3 | `ci: gofmt, vet, race tests and secret scan` | ✅ |

---

## Phase A — Capture and decode (every packet accounted for)

### #A1: Classic pcap reader
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: Phase 0 · **Status: written, staged**
**Build:** `internal/pcap`: `Open(io.Reader)` sniffs the format; classic pcap in all four magics (little/big endian × micro/nano), link type from the low 28 bits, per-record limit (16 MiB), `ErrTruncated` keeps earlier packets, `ErrFormat` for garbage. Streaming only.
**Test:** all four magics, FCS bits ignored, truncation mid-record, text file, empty file, absurd length.
**Commit:** `feat(pcap): streaming classic pcap reader with truncation and format errors`

### #A2: PCAPNG reader
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: #A1
**Build:** Section Header (byte-order magic, both orders), Interface Description (link type, snaplen, option `if_tsresol` code 9, including the power-of-two form), Enhanced Packet, Simple Packet (interface 0), skip all other blocks by length. **Link type is per interface**, reset at each new section. Timestamps use the interface's resolution (µs only if the option is absent). Block length must match the trailer.
**Watch out:** a file can hold several sections and several interfaces with different link types.
**Test:** two interfaces (Ethernet + SLL) in one section; nanosecond `if_tsresol`; two sections; bad trailer length; truncated block.
**Commit:** `feat(pcap): pcapng reader with per-interface link types and timestamp resolution`

### #A3: Link layers
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: #A2
**Build:** `internal/netdec/link.go`. Ethernet (802.1Q and 802.1ad, stacked), Linux cooked SLL (113, 16-byte header) and SLL2 (276, 20-byte), BSD null/loopback (0, 108: 4-byte header, then read the IP version nibble), raw IP (101, 12, 14, 228, 229). Anything else returns a typed `UnsupportedLinkType{n}`.
**Test:** the same IPv4 and IPv6 packet wrapped in every link type decodes to the same payload; unknown type reports the number.
**Fixes:** W6. **Commit:** `feat(netdec): link-layer decoding for Ethernet, VLAN, SLL, SLL2, null and raw IP`

### #A4: IP, UDP, ESP, AH and NAT-T classification
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: #A3
**Build:** IPv4 (IHL, total length, fragment fields, **truncated-by-snaplen flag instead of dropping**), IPv6 (hop-by-hop 0, routing 43, destination 60, fragment 44). Classification: UDP 500 → IKE; UDP 4500 with four zero bytes (non-ESP marker) → IKE; one byte `0xFF` → NAT keepalive; UDP 4500 otherwise with non-zero SPI → ESP-in-UDP; protocol 50 → ESP (SPI, sequence); 51 → AH (SPI, sequence, ICV length from payload-length field). Output one `Datagram` record with endpoints, ports, kind, payload slice and packet index.
**Test:** crafted bytes for each kind in v4 and v6; snaplen-truncated packet is flagged, not lost.
**Commit:** `feat(netdec): IPv4/IPv6 decode and IKE/ESP/AH/NAT-T classification`

### #A5: Bounded fragment reassembly
Priority: 🟦 BUILD · Window: 🧱 FOUNDATION · Blocked by: #A4
**Build:** IPv4 (id, src, dst, proto) and IPv6 (fragment header id) reassembly with hard caps: 64 KiB per datagram, 256 concurrent datagrams, timeout measured in **capture time** (30 s). Overlapping fragments: keep the first, count the conflict. Evicted or expired datagrams are counted with a reason.
**Test:** in-order, out-of-order, duplicate, overlapping, over-cap, timeout.
**Fixes:** W12. **Commit:** `feat(netdec): bounded IPv4 and IPv6 fragment reassembly`

### #A6: Decoder with complete accounting
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: #A5
**Build:** `netdec.Decoder` wraps reader + link + IP + reassembly and yields `Datagram`s plus a `Stats{Seen, Decoded, IPsec, Skipped map[reason]uint64, LinkTypes, Warnings}`. Reasons: `unsupported_linktype`, `not_ip`, `truncated`, `fragment_pending`, `malformed`, `non_ipsec`. **A file with packets but zero decoded IPsec is a first-class result, never an empty success.**
**Test:** SLL file, non-IPsec TCP file, truncated file each produce the expected reason counts.
**Fixes:** W6. **Commit:** `feat(netdec): decoder with per-reason skip accounting and warnings`

### #A7: Fixtures
Priority: 🟥 CORE · Window: 🧱 FOUNDATION · Blocked by: #A6
**Build:** `testdata/public-pcaps/` (the five Wireshark IPsec sample captures: IKEv2 AES-256-GCM site-to-site with ESP, IKEv2 NAT-T multi-cipher, IKEv1 with certificates, IKEv2 AES-256-GCM-16, IKEv2 AES-256-CBC/SHA-256) with a `README.md` giving source URLs, SHA-256 and packet counts read from Wireshark. `testdata/negative/` (a non-IPsec TCP capture), `testdata/lab/` (an ESP-only capture). Extend `capbuild` with pcapng, SLL and IKE/ESP packet builders.
**Test:** every fixture opens; packet and IKE/ESP counts match the README.
**Commit:** `test: public Wireshark IPsec captures, negative fixtures and capture builders`

### #A8: Hardening and fuzzing
Priority: 🟥 CORE · 🟨 SAFETY · Window: 🧱 FOUNDATION · Blocked by: #A7
**Build:** `go test -fuzz` targets for `pcap.Open`/`Next`, the link decoder and IP decoder, seeded with the fixtures. No panic on any input; a recovered panic is counted as `malformed`. Hard limits: packets per file unbounded but **memory bounded** (streaming), per-packet 16 MiB.
**Test:** 30 s fuzz per target clean; nightly CI runs 5 min.
**Commit:** `test(fuzz): fuzz targets for pcap, link and IP decoders`

---

## Phase B — IKE intelligence (the hero)

### #B1: Typed IANA registry
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #A7
**Build:** `internal/iana`: versioned (`iana-2026.10`) tables for IKEv2 transform types 1–5 (and 6–12 additional key exchange), IKEv1 attribute values, exchange types, payload types, notify types, auth methods, signature-hash IDs. `Transform{Type, ID, Name, Family, KeyBits, ICVBits, AEAD, Legacy}` with `Lookup(type,id,keyBits)`. **No name strings are parsed anywhere else**; unknown IDs become `UNKNOWN(type,id)`. Policy classes (Recommended / Acceptable / Legacy / Prohibited) live in the **policy** file (#C2), not here.
**Watch out:** do not assert RFC section numbers in names; cite RFC numbers only. Do not name post-quantum algorithm IDs: show them as `ADDKE(id)`.
**Test:** golden comparison with an IANA CSV snapshot (`testdata/iana/`); every registry entry round-trips through `Lookup`.
**Fixes:** W1. **Commit:** `feat(iana): versioned typed registry of IKE, IPsec transforms, notifies and exchange types`

### #B2: IKE header and payload walker
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B1, #A6
**Build:** `internal/ike`. Header (SPIs, version, exchange, flags, message ID, length) with checks: length equals the UDP payload, initiator SPI non-zero, exchange valid for the major version, **including 38, 43, 44** (IKE_SESSION_RESUME, IKE_INTERMEDIATE, IKE_FOLLOWUP_KE). Generic walker for both versions: next-payload, critical bit, length bounds; stops at IKEv2 SK/SKF and sets `Encrypted`; IKEv1 encrypted flag stops the chain. Malformed chain returns the header plus a `Malformed` reason.
**Test:** table of valid and broken messages; public captures parse to the right exchange sequence.
**Fixes:** W12. **Commit:** `feat(ike): header validation and payload chain walker for IKEv1 and IKEv2`

### #B3: IKEv2 SA payload
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B2
**Build:** proposals (number, protocol, SPI size, transform count), transforms (type, ID, key-length attribute 14 in TV form), structural checks (last/more flags, reserved bytes, counts add up). Transform types 1–5 and 6–12. Produces `[]Proposal` of registry-resolved transforms.
**Test:** public captures give the expected proposals; crafted: missing key length on AES, bad counts, unknown IDs.
**Commit:** `feat(ike): IKEv2 SA payload into registry-typed proposals`

### #B4: Remaining IKEv2 clear-text payloads
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B3
**Build:** KE (group, public value length), Nonce (length), Notify (protocol, type, data) with decoded meaning for NAT_DETECTION_SOURCE_IP 16388, NAT_DETECTION_DESTINATION_IP 16389, COOKIE 16390, IKEV2_FRAGMENTATION_SUPPORTED 16430, SIGNATURE_HASH_ALGORITHMS 16431, INVALID_KE_PAYLOAD 17, NO_PROPOSAL_CHOSEN 14; Vendor ID (count and hashes only); AUTH (method), CERT (encoding), TSi/TSr (when in clear); **additional key exchange transforms (types 6–12)** recorded as a `pq_hybrid_seen` fact.
**Test:** KE group 19 on the DH19 capture; NAT-D notifies counted on the NAT-T capture; crafted INVALID_KE carries the accepted group.
**Fixes:** W9. **Commit:** `feat(ike): KE, nonce, notify, vendor, auth and traffic-selector payloads`

### #B5: IKEv1 SA, attributes, lifetimes, identity
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B2
**Build:** SA → proposal → transform → attributes in TV and TLV forms: encryption (1), hash (2), auth method (3), group (4), life type (11), life duration (12, both 2-byte and 4-byte TV and TLV), PRF (13), key length (14). Exchange kinds: Main (2), Aggressive (4), Quick (32, encrypted), Informational (5). Aggressive Mode: read the ID payload in clear → `identity_exposed`. Certificate payload encodings.
**Test:** the IKEv1 certificate capture resolves suite, group and auth; crafted aggressive-mode message exposes identity; lifetime in seconds and kilobytes.
**Fixes:** W3, W11. **Commit:** `feat(ike): IKEv1 attributes, lifetimes and aggressive-mode identity exposure`

### #B6: NAT detection from hashes
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B4
**Build:** For each IKE_SA_INIT message recompute `SHA-1(SPIi ‖ SPIr ‖ address ‖ port)` from the packet's own source and destination (IPv4 4 bytes, IPv6 16 bytes, port 2 bytes) and compare with the source and destination notifies. Result per message: source-hash match, destination-hash match. **Derived fact `nat.on_path`:** true if any mismatch; false only when all four hashes match across the request and response; otherwise unknown. UDP/4500 alone yields `udp_encapsulation`, never NAT.
**Watch out:** state the capture-point limitation in the evidence text (a mismatch shows translation between sender and capture point, or capture point and receiver).
**Test:** crafted matching and mismatching hashes; real NAT-T capture.
**Fixes:** W8. **Commit:** `feat(ike): derive NAT presence from NAT-D hash comparison`

### #B7: Negotiation matcher
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B5, #B6
**Build:** `ike/negotiation.go`. Per IKE SA: **offers** = proposals in the initiator's first SA_INIT (IKEv2) or message 1 (IKEv1, responder SPI zero); **selected** = the responder's SA payload in the reply (IKEv2: response flag and same message ID and SPIi; IKEv1: first SA from the other endpoint with a non-zero responder SPI). Checks: each selected transform appears in an offered proposal with the same number and protocol; KE group equals the selected DH. **Retransmissions** (same SPIi, message ID, direction, identical bytes) count once. **INVALID_KE_PAYLOAD retries** recorded as an attempt chain (first group, accepted group, retry group).
**Test:** crafted: selection not in offers (inconsistent), KE group ≠ selected DH, duplicated packet, retry to a weaker group.
**Fixes:** W3, W10. **Commit:** `feat(ike): match selected suite to offers, check consistency, dedupe retransmits, track KE retries`

### #B8: IKE SA table
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B7
**Build:** Table keyed by initiator SPI (responder SPI attached when seen). Per SA: version, endpoints (ports included, NAT-T float 500→4500 tracked), first/last packet index and time, exchange history with encrypted flag, negotiation result, NAT facts, notifies, auth/cert facts, fragmentation flag, malformed and duplicate counters, the packet index where encryption begins.
**Test:** the NAT-T capture (three IKE SAs, port float) gives three SAs; interleaved sessions do not mix.
**Commit:** `feat(ike): IKE SA table with endpoint float, exchange history and counters`

### #B9: ESP/AH SA inventory
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B8
**Build:** `internal/ipsec`. Directional SA = (destination, SPI, protocol). Per SA: packets, bytes, first/last time, min/max sequence, **gap ratio, duplicate count, regression count**, size summary (min, max, mean, reservoir of 1,024 sizes). Pair directions by reversed endpoints and start time within 5 s. Attach SA pairs to an IKE SA by endpoints and time. **Rekey** = a new SA pair on the same endpoints while the previous pair still carries traffic, or sequence restart near 1. **Derived lifetime** = median interval between successive pair starts, reported only with ≥ 3 pairs (≥ 2 rekeys), otherwise unknown. Sequence anomalies are **indicators**, never "replay attack".
**Test:** the NAT-T capture inventory (three child SA pairs); crafted rekey stream; crafted duplicates and gaps.
**Commit:** `feat(ipsec): ESP and AH SA inventory with pairing, rekey detection and sequence indicators`

---

## Phase C — Evidence and assessment

### #C1: Evidence ledger
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B9
**Build:** `internal/evidence`. `Evidence{ID, Property, Value, Status, Confidence, Resource{Type,ID}, Source{Kind, Packets, Exchange, MessageID, SnapshotTime, Detail}}`. Statuses OBSERVED / DERIVED / INFERRED / GATEWAY_VERIFIED / CONFLICTING / UNKNOWN. Deterministic IDs. `Resolve(resource, property)`: precedence gateway > observed > derived > inferred > unknown; two eligible sources with different values → CONFLICTING. **Confidence = f(source, status) only; no clock.** Base confidences: observed 1.0 (0.8 if the packet was truncated or conflicting retransmits), derived rule-specific and stated, gateway 1.0.
**Test:** precedence table, conflict, confidence unchanged when the machine clock changes (inject a clock and assert it is never read).
**Fixes:** W13. **Commit:** `feat(evidence): ledger with statuses, packet provenance and clock-free confidence`

### #C2: Policy baseline and profiles
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #B1
**Build:** `internal/policy` with embedded `baseline-v1.json`: for every registry transform a class (Recommended / Acceptable / Legacy / Prohibited) and severity mapping (Legacy → MEDIUM, Prohibited → HIGH, NULL cipher → CRITICAL); minimum key bits; lifetime limits (IKE ≤ 24 h, child ≤ 8 h); replay window minimum 64; fix templates in strongSwan `swanctl.conf` proposal syntax. **Two profiles:** `trace-default` and `strict` (stricter: no CBC for new deployments, DH ≥ 19, lifetimes ≤ 8 h / 1 h). The policy file carries its own ID and version, printed in every report.
**Watch out:** cite RFC numbers (8221, 8247) and NIST SP 800-77r1, no section numbers.
**Test:** loads and validates; every registry entry has a class (coverage test lives in #C9); profile switch changes verdicts for a CBC suite.
**Commit:** `feat(policy): versioned baseline with default and strict profiles`

### #C3: Controls C01–C06
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C1, #C2, #B7
**Build:** `internal/assess`. C01 IKE version (v2 PASS; v1 FAIL MEDIUM, HIGH if aggressive). C02 IKE encryption. C03 integrity and PRF (AEAD needs no integrity). C04 DH group (from the KE payload, cross-checked with the selected transform). C05 weak offers (any offered transform whose class is Legacy or Prohibited: FAIL MEDIUM; a weaker retry after INVALID_KE: HIGH). C06 negotiation consistency (selected ⊂ offered, KE group = selected DH: FAIL HIGH). Each control returns status, severity, explanation, evidence IDs.
**Test:** all five public captures: C02–C04 never UNKNOWN; crafted weak-offer capture: C05 FAIL while C02–C04 PASS (the money shot).
**Fixes:** W1, W10. **Commit:** `feat(assess): controls C01–C06 from observed negotiation, including weak offers`

### #C4: Controls C07–C13
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C3
**Build:** C07 peer authentication (IKEv1 signature/ECDSA PASS; aggressive + PSK FAIL HIGH; IKEv2 and IKEv1 PSK UNKNOWN unless gateway facts say otherwise). C08 child suite (gateway only). C09 PFS (gateway only). C10 lifetimes (IKEv1 observed, derived from rekeys, gateway: worst of available). C11 replay (gateway window ≥ 64 PASS, 1–63 FAIL MEDIUM, 0 or disabled FAIL HIGH; capture gives indicators only). C12 identity and metadata exposure (aggressive-mode identity FAIL MEDIUM; otherwise PASS once IKE is seen). C13 protocol hygiene (malformed exchanges, retransmit storms, AH with NAT: FAIL LOW).
**Test:** each control has PASS/FAIL/UNKNOWN cases built from crafted facts.
**Commit:** `feat(assess): controls C07–C13 with gateway, derived and observed inputs`

### #C5: Score, coverage, confidence, bounds, gate
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C4
**Build:** `Score = 100·P/E`, `Coverage = 100·E/A`, `Confidence` = weighted mean of evidence confidence behind evaluated controls, `bounds = [100·P/A, 100·(P+A−E)/A]`. **Gate:** ≥ 70% coverage → letter grade (A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F); 40–70% → `Provisional N (coverage X%)` and no letter; < 40% → `Insufficient evidence` plus bounds. A CRITICAL failure caps the score at 40. The label string is generated here, once.
**Test:** the Bible §8.3 worked example gives exactly 87.7 / 65% / bounds 57–92; an IKEv2 public capture yields no letter grade.
**Fixes:** W2. **Commit:** `feat(assess): score, coverage, confidence and bounds with a coverage gate`

### #C6: Risk and many-SA aggregation
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C5
**Build:** Controls are evaluated per IKE SA; the **headline** per control is the worst status across SAs (FAIL > CONFLICTING > UNKNOWN > PASS > N/A), weights counted once, per-SA table kept. **Risk** = `100 − worst-case bound`, levels LOW ≤ 20, MODERATE ≤ 45, HIGH ≤ 70, CRITICAL above; below 40% coverage the level is `UNDETERMINED` with the bound. IKEv1 is MEDIUM risk (HIGH when aggressive), never automatically CRITICAL.
**Test:** the NAT-T capture (three SAs with different ciphers) reports the worst per control; adding an UNKNOWN control never lowers risk (property test).
**Fixes:** W2, W3. **Commit:** `feat(assess): worst-case risk and per-SA aggregation`

### #C7: Findings
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C6
**Build:** One finding per failed control (and per notable indicator): ID (`TRACE-C05-…`), severity, title, why it matters (RFC number), evidence IDs with **packet numbers**, `fix.config` (a `swanctl.conf` line such as `proposals = aes256gcm16-prfsha384-ecp384`), `fix.text`, status CONFIRMED or POSSIBLE. Sorted by severity then weight.
**Test:** the weak-offer finding renders the Bible §8.4 block; every FAIL control has ≥ 1 finding.
**Commit:** `feat(assess): findings with packet evidence, RFC reference and config fix`

### #C8: Threat matrix
Priority: 🟦 BUILD · Window: 🌅 ENGINE · Blocked by: #C6
**Build:** The problem statement asks for a Threat Matrix. Threats: downgrade, passive decryption through weak cipher or group, loss of forward secrecy, replay, identity exposure, traffic analysis, weak authentication, key exposure from long lifetimes. Each: linked controls, **status derived only from those controls** (Exposed / Unverified / Mitigated), fixed qualitative likelihood and impact documented in the policy file, ATT&CK technique IDs (T1600 and T1600.001, T1040, T1557 — **verify every ID on attack.mitre.org before printing**).
**Test:** matrix cells change only when control statuses change (snapshot test).
**Commit:** `feat(assess): threat matrix derived from control results with ATT&CK references`

### #C9: Contract tests
Priority: 🟥 CORE · Window: 🌅 ENGINE · Blocked by: #C7
**Build:** (a) For every entry in `iana.All()` the policy has a class, and `assess` returns PASS/FAIL, never UNKNOWN, for a negotiation using it. (b) Every evidence property the pipeline emits is read by ≥ 1 control or listed in `ignored_properties.txt`; every property a control reads has a producer or is marked gateway-only. (c) Every control has an RFC reference and a fix template.
**Test:** renaming a property in a scratch change turns CI red.
**Fixes:** W1, W4, W23. **Commit:** `test(contract): every parsable algorithm is judgeable and every evidence key is consumed`

---

## Phase D — Gateway evidence (the honest answer to hidden settings)

### #D1: Gateway facts and conflicts
Priority: 🟦 BUILD · Window: 🌅 ENGINE · Blocked by: #C4
**Build:** `internal/gateway`: JSON schema `trace.gateway.v1` (IKE SA suite, child suites, PFS group, mode, lifetimes, replay window and ESN, selectors, auth method, snapshot time, `source: vici|xfrm|file`, `configured|runtime`). `Import(file)` adds GATEWAY_VERIFIED evidence; disagreement with a packet fact yields CONFLICTING. Matching to an IKE SA by SPIs, else by endpoints.
**Test:** fixture lifts coverage (C07–C09, C11 become PASS/FAIL); conflicting fixture yields CONFLICTING.
**Commit:** `feat(gateway): gateway facts schema, import and conflict detection`

### #D2: VICI client
Priority: 🟦 BUILD · Window: 🌅 ENGINE · Blocked by: #D1
**Build:** Read-only client for the strongSwan VICI socket: packet framing (4-byte length, type byte, command name), message encoding (section start/end, key-value, list start/item/end), `list-sas` via event registration and request, `list-conns`. Converts to `trace.gateway.v1`. Commands are an allow-list of read-only verbs; anything else is refused in code.
**Test:** a mock VICI server (Unix socket) in the test suite serving recorded-shape messages; allow-list refusal test.
**Commit:** `feat(gateway): read-only strongSwan VICI client`

### #D3: Linux XFRM reader
Priority: 🟦 BUILD · Window: 🌅 ENGINE · Blocked by: #D1
**Build:** Parse `ip -s xfrm state` text: proto, SPI, mode, reqid, replay window, ESN flag, algorithm names and key **sizes only** (key hex is discarded, never stored or logged), lifetimes. Maps to gateway facts.
**Test:** sample outputs for GCM and CBC+HMAC; a test asserts no hex key material appears in the produced JSON.
**Commit:** `feat(gateway): parse ip xfrm state without retaining key material`

---

## Phase E — AI layer (small, honest, labelled)

### #E1: Flow windows and features
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #B9
**Build:** `internal/flow`. Flow = ESP SA pair or NAT-T 5-tuple. 10 s windows by capture time. 22 features: duration, packets, bytes, pps, bps, size mean/std/min/max/p25/p50/p75/p95, inter-arrival mean/std/p50/p95, up/down packets and bytes, up-ratio, burst count and mean burst size, idle ratio. No addresses, ports, SPIs or crypto settings. The feature list lives in `internal/flow/features.json` and is read by both Go and Python.
**Test:** hand-computed window on a crafted stream.
**Commit:** `feat(flow): payload-free flow windows with a shared feature contract`

### #E2: Model format and inference
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #E1
**Build:** `internal/ai`. `trace.model.v1` JSON: feature list, class list, forest (arrays of left, right, feature, threshold, class probabilities), calibration table (monotone piecewise-linear map from raw top-class probability to calibrated), UNKNOWN threshold, training metadata (`data_origin`, split description, `n`), SHA-256 of the canonical body. Loader refuses a mismatched hash or feature list. Inference = mean of leaf probabilities, calibrate, abstain below the threshold. **Built-in explanation:** per-prediction feature contributions from the decision path (mean change in class probability along the path per feature), no external library.
**Test:** a hand-built tiny forest; tampered file rejected; contributions sum to prediction minus the prior.
**Fixes:** W18, X8. **Commit:** `feat(ai): JSON model format, forest inference, calibration, abstention and path explanations`

### #E3: Training toolkit
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #E2
**Build:** `ai/` (Python, numpy and scikit-learn). `synth.py` generates packet-level traffic for seven classes (web, video, voice, email, file transfer, messaging, ICMP-like) and three held-out unknown classes (DNS-like, interactive SSH-like, gaming-like) across several *environments* with different RTT, loss, MTU and jitter, then writes the same 22 features. `train.py`: **split by capture**, leave-one-environment-out evaluation, four disjoint partitions (train / validation / calibration / locked test), isotonic calibration of top-class probability, UNKNOWN threshold chosen on calibration known + calibration OOD and evaluated on the **held-out OOD classes**, ECE, per-class precision/recall with `n`, all windows of a capture used in training. `export.py` writes `trace.model.v1`. A `--from-windows windows.csv --manifest manifest.csv` path trains from real lab captures produced by `trace features` (#F7).
**Watch out:** synthetic data exists to exercise the pipeline. Every artifact says `data_origin: synthetic-bootstrap`.
**Test:** `pytest`: split audit fails if a capture is in two partitions; exported model loads in Go (golden test in #E4).
**Fixes:** W14, W15, W16, W19. **Commit:** `feat(ai): training toolkit with capture-level splits, calibration and held-out unknowns`

### #E4: Bootstrap model and generated model card
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #E3
**Build:** Commit `ai/models/bootstrap-v1.json` (embedded in the binary) and a `MODEL_CARD.md` **generated by script** from the training run: data origin, class list, `n` per class and partition, per-class metrics, ECE, UNKNOWN rate on held-out classes, LOEO results, limits (synthetic data, not field accuracy). The API and reports quote the model ID and `data_origin` next to every prediction.
**Test:** Go loads the committed model and reproduces the Python predictions on a committed 50-row check file to 1e-9.
**Commit:** `feat(ai): bootstrap classifier, embedded, with generated model card`

### #E5: ESP cipher-family hint and tunnel indicators
Priority: 🟦 BUILD · Window: 🧪 INTELLIGENCE · Blocked by: #B9
**Build:** `ai/espfp.go`: statistical hint from ESP packet lengths. CBC-style suites give a constant `length mod 16` (block padding); AEAD suites give lengths that vary modulo 16 while staying aligned to 4. Output `cbc_like | aead_like | unknown` with a confidence from sample size and consistency, status INFERRED. Tunnel indicators from SA statistics: gap ratio, duplicates, regressions, keepalive-sized bursts, rekey cadence deviation, reported as DERIVED indicators with INFO/LOW severity.
**Test:** synthetic streams for each cipher family; too few packets yields `unknown`.
**Commit:** `feat(ai): ESP cipher-family hint and tunnel anomaly indicators`

### #E6: AI as labelled context, never a verdict
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #E4, #C7
**Build:** Model output enters the ledger as INFERRED evidence. Effects allowed: raise **priority** of findings (e.g. real-time voice on a tunnel with no PFS evidence), add INFO/LOW indicator findings, and show a cross-check when the cipher hint disagrees with gateway facts (CONFLICTING). Effects forbidden: any change to a control status, score, coverage or risk.
**Test:** **invariance test:** run every public capture with AI on and off; control statuses, score, coverage and risk are byte-identical; finding order and priority may differ.
**Fixes:** W17. **Commit:** `feat(assess): AI context raises priority and indicators but never changes a verdict`

---

## Phase F — Engine, API and operations

### #F1: Analysis pipeline
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #C9, #E1
**Build:** `internal/engine`: `Analyze(ctx, io.Reader, Options) (*Result, error)` wires decode → IKE → SA inventory → ledger → assessment → flows → AI. `Result` is `trace.result.v1`: input summary (format, size, SHA-256, link types, packet accounting), state (`COMPLETED`, `COMPLETED_NO_IPSEC`, `FAILED`), IKE SAs, child SAs, evidence, assessment (headline, controls, findings, threats, per-SA), traffic windows, AI outputs, policy and model IDs. **All state lives in the call; there is no global workspace.**
**Test:** table test over every public and negative fixture (expected state and headline label).
**Fixes:** W22. **Commit:** `feat(engine): analysis pipeline producing trace.result.v1`

### #F2: Streaming, per-SA aggregation, benchmark
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #F1
**Build:** ESP is aggregated into SA summaries as packets stream by (evidence count grows with SAs, not packets). Memory caps: flow window buffers, SA size reservoirs, evidence count per analysis. `make bench` runs generated captures (5k, 50k, 1M ESP packets) and writes `bench/results.json` (packets/s, peak RSS, machine).
**Watch out:** "1 GB in under 2 minutes" stays a *Target* until that file says otherwise.
**Test:** a 1M-packet generated capture completes under the memory cap.
**Fixes:** W5. **Commit:** `perf(engine): stream ESP into per-SA summaries with memory caps and a benchmark`

### #F3: Store with retention
Priority: 🟥 CORE · 🟨 SAFETY · Window: 🧪 INTELLIGENCE · Blocked by: #F1
**Build:** `internal/store`: one directory per analysis (random ID) with `meta.json` (owner, state, times, sizes), the capture file, `result.json`; atomic writes (temp + rename). `Delete` removes everything; `Sweep(ttl)` removes expired analyses; a capture can be dropped right after analysis (`keep_capture=false`).
**Test:** crash-safe write test; delete leaves no files; sweep with a fake clock.
**Fixes:** W21. **Commit:** `feat(store): per-analysis on-disk store with atomic writes and retention`

### #F4: API skeleton, auth, limits
Priority: 🟥 CORE · 🟨 SAFETY · Window: 🧪 INTELLIGENCE · Blocked by: #F3
**Build:** `internal/api`: `GET /health`; middleware: bearer key (constant-time compare of SHA-256 digests from `TRACE_API_KEYS`), roles `analyst` and `admin`, per-key token bucket, request size limits, security headers, structured logs without query strings or keys. Records are scoped to the owner; another owner's ID returns 404.
**Test:** 401 without a key; two keys cannot see each other's data; burst returns 429.
**Fixes:** W21 (auth), W7 (timeouts set per route). **Commit:** `feat(api): authenticated, rate-limited HTTP skeleton with owner scoping`

### #F5: Upload and async jobs
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #F4
**Build:** `POST /api/v1/analyses` (multipart: `capture`, optional `gateway` JSON) streams to disk with a configurable cap (default 1 GiB), checks **magic bytes** (pcap four magics, pcapng `0a0d0d0a`), random names, free-space check. Returns `202` with the ID immediately. Bounded worker pool; states QUEUED / RUNNING / DONE / FAILED / CANCELLED; progress; `POST …/cancel`; queue full → 429.
**Test:** a text file renamed `.pcap` → 415; a large upload returns 202 fast; cancel works; `-race` clean.
**Fixes:** W7. **Commit:** `feat(api): streamed validated uploads and asynchronous analysis jobs`

### #F6: Results, reports, delete
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #F5
**Build:** `GET /api/v1/analyses`, `GET …/{id}`, `GET …/{id}/result`, `GET …/{id}/report?type=json|executive|technical`, `DELETE …/{id}`, `GET /api/v1/model` (model card). A janitor goroutine calls `Sweep`.
**Test:** `httptest` flow over every public capture: upload, poll, result, report, delete; the result matches the engine's direct output.
**Commit:** `feat(api): result, report, delete and model endpoints with retention sweeper`

### #F7: CLI
Priority: 🟥 CORE · Window: 🧪 INTELLIGENCE · Blocked by: #F1
**Build:** `cmd/trace`: `analyze file [--gateway facts.json] [--profile strict] [--json|--text]`, `features file --out windows.csv` (for training from lab captures), `serve`, `keygen` (prints a key once and its digest), `version`. The text output is the demo: headline, three numbers, control table, findings with fix lines, and what could not be seen.
**Test:** golden text output for two fixtures.
**Commit:** `feat(cli): analyze, features, serve and keygen commands`

### #F8: Hash-chained audit log
Priority: 🟦 BUILD · 🟨 SAFETY · Window: 🧪 INTELLIGENCE · Blocked by: #F6
**Build:** Append-only JSONL: who (key name), what (upload, view, report, delete, ask), analysis ID, time, and the SHA-256 of the previous line. `trace audit verify` recomputes the chain. No capture contents, endpoints or secrets in the log.
**Test:** tampering with a middle line fails verification.
**Commit:** `feat(audit): tamper-evident hash-chained audit log`

---

## Phase G — Reports and the explainer

### #G1: JSON evidence bundle v2
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #F6
**Build:** `docs/EVIDENCE_SCHEMA.md` (structured values, statuses, packet references, registry, policy and model IDs). The bundle = `trace.result.v1` + SHA-256 of the input capture + tool version + generation time + SHA-256 of the bundle body (printed in report footers). JSON Schema file validated in tests.
**Commit:** `feat(report): evidence bundle with input and body hashes and a JSON schema`

### #G2: Executive and technical HTML reports
Priority: 🟩 SHOWPIECE · Window: 🌇 DELIVER · Blocked by: #G1
**Build:** `internal/report`, `html/template`, self-contained (inline CSS, no external requests), light and dark. **Executive (one page):** headline label, the three numbers with bounds, top five findings with fix lines, "what we could not see and how to get it". **Technical:** every control with evidence and packet numbers, negotiation ladder (offered vs selected), SA inventory, threat matrix, AI section with model ID and `data_origin`, methodology and limits. Colour legend for the five evidence statuses.
**Test:** snapshot of the HTML for a public capture; no `http` URLs in the output.
**Commit:** `feat(report): self-contained executive and technical HTML reports`

### #G3: PDF export
Priority: 🟦 BUILD · Window: 🌇 DELIVER · Blocked by: #G2
**Build:** Small text-and-table PDF writer (PDF 1.4, standard fonts, pagination, no dependencies) for the executive report; `report?type=executive&format=pdf`.
**Test:** output starts with `%PDF-1.4`, has a valid xref table, one page for the executive report; text extractable by `pdftotext` when present.
**Commit:** `feat(report): dependency-free PDF export of the executive report`

### #G4: Built-in explainer (LLM optional)
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #F6
**Build:** `internal/explain` and `POST …/{id}/ask`. **Default mode is deterministic and free:** every control and finding has a plain-language template (what it means, why it matters, what to do) filled with the actual values from the ledger, each sentence carrying the evidence IDs it came from. Questions are matched to intents (`why_score_provisional`, `what_is_missing`, `what_to_fix_first`, `explain_finding:<id>`, `what_is_weak_offer`, …) by keyword and ID; anything else returns the intent list instead of guessing. The answer shape is always `{answer, cites[]}` so a console can link citations later.
**Optional LLM plug-in (off by default):** a provider interface with a Claude Messages API implementation, enabled only when `ANTHROPIC_API_KEY` is set and `TRACE_AIRGAP` is not. It receives ledger summaries only, **endpoints, SPIs and identities masked** unless `assistant.reveal=true`. The reply must be `{answer, cites[]}` with every cite an existing evidence ID; an uncited or unknown-cite answer is retried once, then replaced by "I can't support that from the evidence". The key goes in a header and is never logged. Model from `CLAUDE_MODEL`.
**Watch out:** the deck says "Claude analyst". Until the plug-in has been run with a real key, call it "optional LLM explainer (not enabled by default)" in the repo and in round 2.
**Test:** every intent returns cites that exist in the result; unknown question lists intents; with a mock Messages API server: uncited answer rejected, injected "ignore instructions" text in a finding does not alter the output, key never appears in logs; no key or air-gap set means the built-in explainer answers.
**Fixes:** X5. **Commit:** `feat(explain): deterministic cited explainer with optional masked LLM provider`

### #G5: Compare two analyses
Priority: 🟦 BUILD · Window: 🌇 DELIVER · Blocked by: #G1
**Build:** `trace compare a.json b.json` and `GET …/compare?to=`: resolved findings, new findings, control status changes, score, coverage and risk deltas. Answers "did our fix work?".
**Test:** before/after fixtures (weak offer removed) show C05 resolved and the score change.
**Commit:** `feat(report): compare two analyses`

---

## Phase H — TRACE Lab (known configurations, offline only)

### #H1: Profiles
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: Phase 0
**Build:** `lab/`: strongSwan **swanctl.conf** profiles: P01 IKEv2 tunnel AES-256-GCM/ECP-256 (strong control), P02 IKEv2 AES-256-CBC/SHA-256/MODP-2048, **P03 weak offer** (initiator proposes `aes256-sha256-modp2048` and `3des-sha1-modp1024`, responder policy strong: strong session, weak offer), P04 transport mode, P05 IPv6, P06 PFS off, P07 30 s lifetime (rekey), P08 IKEv1 aggressive + PSK (isolated negative control). Each profile ships an `expected.json` (version, selected suite, DH, PFS, mode).
**Watch out:** weak profiles exist only in the isolated lab network.
**Commit:** `feat(lab): strongSwan profiles including weak-offer, rekey and IKEv1 aggressive`

### #H2: Containers, generators, capture, manifest
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #H1
**Build:** Compose file with two gateways on an isolated bridge plus a **NAT router container** (nftables masquerade) for a real NAT-T profile. Traffic generators (web, HLS video, SMTP, WebSocket chat, bulk download, ICMP, RTP-like UDP voice) driven by seeds. Capture on the gateway's outer interface. Manifest v2 per capture: profile, **environment ID**, seed, tool versions, packet counts, SHA-256, and `expected.json` copied in.
**Watch out:** generators are synthetic workloads; labels say "messaging-like", "voice-like".
**Commit:** `feat(lab): containers, traffic generators, capture scripts and manifest v2`

### #H3: Verify gate and offline controller
Priority: 🟥 CORE · 🟨 SAFETY · Window: 🌇 DELIVER · Blocked by: #H2
**Build:** Before capture, compare the installed SA (from `swanctl --list-sas`) with `expected.json`; any mismatch or fallback fails the run and deletes partial output. `make lab-up|run|verify|down` are the only controllers: **no HTTP endpoint and no Docker socket in the service**. Document that lab gateways run privileged and must never be exposed.
**Commit:** `feat(lab): pre-capture verification gate and offline make targets`

---

## Phase I — Proof

### #I1: Golden tests on real captures
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #F1
**Build:** For each public capture, expected facts (version, selected suite, KE group, NAT-T, SA count) and expected control outcomes as JSON, checked against Wireshark once. One test runs the full engine and compares.
**Test:** C02–C04 are never UNKNOWN on the four IKEv2 captures; the IKEv1 capture evaluates them too; no IKEv2 public capture gets a letter grade.
**Fixes:** W23. **Commit:** `test(golden): expected facts and control outcomes for the public captures`

### #I2: Adversarial corpus
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #F2
**Build:** Go generator (`internal/testutil`) producing: truncated pcap, snaplen-96, SLL/SLL2/null/raw, fragmented IKE, retransmissions, INVALID_KE retry, garbage on UDP 500, zero-SPI ESP, 5k and 50k ESP, empty file. `adversarial.json` lists expected state and reason per case.
**Test:** every case ends in the expected state; none is an empty success.
**Commit:** `test(adversarial): broken and unusual captures must decode correctly or fail loudly`

### #I3: Lab oracle comparison
Priority: 🟦 BUILD · Window: 🌇 DELIVER · Blocked by: #H3, #I1
**Build:** `trace oracle --manifest manifest.csv --captures dir` runs the engine on each lab capture and compares the extracted facts with `expected.json`; writes `docs/ORACLE_RESULTS.md` (n, per-fact agreement). Needs real lab captures (run the lab on your machine).
**Commit:** `feat(oracle): compare analyzer facts with lab ground truth`

### #I4: VALIDATION.md generated
Priority: 🟦 BUILD · Window: 🌇 DELIVER · Blocked by: #I3, #F2
**Build:** `make validate` regenerates `docs/VALIDATION.md` from test output, `bench/results.json`, the model card and oracle results: measured values with `n` and source in one table, **targets** in another. Slides may quote only this file.
**Commit:** `docs(validation): generated table of measured and target numbers`

---

## Phase J — Docs and release

### #J1: README, requirements map, prior art
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #I1
**Build:** `README.md` (what TRACE proves, how to run, limits, built vs planned), `docs/REQUIREMENTS.md` (problem statement items a–e → code → test), `docs/PRIOR-ART.md` (the one honest paragraph from §0), `docs/ARCHITECTURE.md` (matches slide 3, marks anything not built as roadmap).
**Commit:** `docs: README, requirements mapping, architecture and prior-art note`

### #J2: Deploy and demo kit
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: #G2, #F7
**Build:** `Dockerfile` (static binary, distroless, **non-root**, read-only root filesystem, no shell), `compose.yaml` (127.0.0.1 only, key from env), `demo/` with three sample captures, their cached `result.json` and reports, `TRACE-demo-script.md`, and `make demo` (works offline).
**Fixes:** X4. **Commit:** `feat(deploy): non-root image, compose and offline demo kit`

### #J3: Release
Priority: 🟥 CORE · Window: 🌇 DELIVER · Blocked by: all
**Build:** Tag `v1.0`, `CHANGELOG.md`, CI green, secret scan clean, repository link into the PPT placeholders.
**Commit:** `release: v1.0`

---

## Commit budget

| Block | Commits |
|---|---:|
| Phase 0 (done) | 3 |
| A Capture and decode | 8 |
| B IKE intelligence | 9 |
| C Evidence and assessment | 9 |
| D Gateway evidence | 3 |
| E AI layer | 6 |
| F Engine, API, operations | 8 |
| G Reports and explainer | 5 |
| H Lab | 3 |
| I Proof | 4 |
| J Docs and release | 3 |
| **Total** | **61** |

### Day plan (indicative)

| Day | Work |
|---|---|
| Thu 1 Oct | A1–A8 |
| Fri 2 Oct | B1–B9, C1–C2 |
| Sat 3 Oct | C3–C9, D1–D3 |
| Sun 4 Oct | E1–E6, F1–F8 |
| Mon 5 Oct | G1–G5, H1–H3, I1–I4, J1–J3 |

If time slips, cut in this order: G3 (PDF), G5, F8, E5, D3, I3, C8.

## The credit-saving path (if tokens run out)

Do these in order; the rest is polish. They give a tool that beats the measured starting point:
**A1–A4, A6, A7** (decode, loud errors) → **B1–B3, B5, B7, B8** (registry, IKE, offers vs selected) → **C1–C7** (ledger, policy, controls, gate, risk, findings) → **F1, F7** (pipeline, CLI) → **I1** (golden tests) → **G2** (HTML report) → **J1**.

---

## Phase K — Console (deferred, not counted)

Decided for later. The finished TRACE console mock (Vite, React, SEAM design tokens) currently sits in a **temporary scratchpad folder**: `/private/tmp/claude-501/-Users-arushjain-Documents-SIH26160-Alchemist/2ab2d252-c74a-47fb-b80c-bddc7d49ac66/scratchpad/trace-app`. Copy it somewhere permanent before that folder is cleaned.

| ID | Item |
|---|---|
| #K1 | `frontend/`: bring in the console, typed client for `trace.result.v1`, `?demo=1` fixtures with a "Sample analysis" chip |
| #K2 | Upload, job progress, specific error states |
| #K3 | Overview: three numbers, bounds, gate text, control table |
| #K4 | Negotiation ladder (offered vs selected, weak offers in red) |
| #K5 | Findings → packet numbers and copyable fix lines |
| #K6 | Traffic AI with UNKNOWN shown, Ask TRACE with clickable citations |

No analysis history in `localStorage`; API key kept in memory.

## Stretch

| ID | Item |
|---|---|
| #S1 | Live capture agent (separate process, raw-socket capability only, ring buffer) |
| #S2 | IKE_INTERMEDIATE reassembly and a fuller RFC 9370 readiness fact |
| #S3 | OIDC login so "SSO" on the slide is true |
| #S4 | SARIF and CSV export of findings |
| #S5 | Risk-ranker model for fix ordering |
| #S6 | Prometheus metrics |

## What this plan deliberately will not do

- No copy-paste from any other repository, and no claim of results we did not measure.
- No ESP decryption, no NAT claim from port 4500, no application identification, no "calibrated" without an ECE number.
- No weak crypto profile outside the isolated lab, no lab control over HTTP, no Docker socket in a service.

---

*Probe results in §1 come from a scratch build of a public analyzer on 2026-10-01 and describe that tool. Re-run the same probes on TRACE after phases A, C and F: the four public IKEv2 captures, an SLL re-wrap, and a 5,000-packet ESP file (`~/Downloads/trace-probes/`).*
