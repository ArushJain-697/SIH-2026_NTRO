# Prior Art

We reviewed a public MIT-licensed IPsec analyzer for design ideas:

- Evidence statuses (OBSERVED, DERIVED, etc.)
- Offered-vs-selected proposal analysis
- Separating score from coverage

**No source code was reused.** The TRACE codebase is written from the RFCs (7296, 2409, 4303, 4302, 8221, 8247, 9370) and our own design.

## What We Learned and Changed

The public analyzer demonstrated several design pitfalls that TRACE avoids:

1. **String matching for algorithm names** → TRACE uses a typed IANA registry
2. **Grade at low coverage** → TRACE has a coverage gate (70% for letters)
3. **Fixed "CALIBRATED" label** → TRACE reports ECE and data origin
4. **Silent empty success for non-IPsec** → TRACE reports the skip reason
5. **No real-capture tests** → TRACE uses golden tests on public captures
6. **NAT from port 4500** → TRACE derives NAT from hash comparison
