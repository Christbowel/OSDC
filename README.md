<div align="center">

# 🎣 Open Source Daily Catch

**Automated Patch Intelligence — what got fixed in open source today, and why it matters**

[![Analysis](https://github.com/christbowel/osdc/actions/workflows/daily.yml/badge.svg)](https://github.com/christbowel/osdc/actions/workflows/daily.yml)

5 advisories analyzed · 4 unique patterns tracked

[Browse all patches →](https://christbowel.github.io/osdc)

</div>

---

OSDC watches security patches landing in open source every day. It extracts vulnerability patterns, compares them to its historical database, and flags recurring antipatterns across languages and ecosystems.

## Latest critical & high severity patches

| Date | Advisory | Package | Severity | Pattern | Seen |
|------|----------|---------|----------|---------|------|
| 2026-04-10 | [GHSA-9cp7-j3f8-p5jx](https://github.com/advisories/GHSA-9cp7-j3f8-p5jx) | github.com/daptin/daptin (Go) | **CRITICAL** 10.0 | `PATH_TRAVERSAL→FILE_WRITE` | 2x |
| 2026-04-10 | [GHSA-fvcv-3m26-pcqx](https://github.com/advisories/GHSA-fvcv-3m26-pcqx) | axios (JavaScript) | **CRITICAL** 10.0 | `UNSANITIZED_INPUT→HEADER` | 1x |
| 2026-04-10 | [GHSA-8wrq-fv5f-pfp2](https://github.com/advisories/GHSA-8wrq-fv5f-pfp2) | lollms (Python) | **CRITICAL** 9.6 | `UNSANITIZED_INPUT→XSS` | 1x |
| 2026-04-10 | [GHSA-m5gr-86j6-99jp](https://github.com/advisories/GHSA-m5gr-86j6-99jp) | gramps-webapi (Python) | **CRITICAL** 9.1 | `PATH_TRAVERSAL→FILE_WRITE` | 2x |
| 2026-04-10 | [GHSA-wvhv-qcqf-f3cx](https://github.com/advisories/GHSA-wvhv-qcqf-f3cx) | github.com/patrickhener/goshs (Go) | **CRITICAL** 0.0 | `MISSING_AUTHZ→RESOURCE` | 1x |

## Stats

| Metric | Value |
|--------|-------|
| Total advisories | 5 |
| Unique patterns | 4 |
| Pending analysis | 0 |
| Last updated | 2026-04-12 |

## How it works

Three automated runs per day (06:00, 14:00, 23:00 UTC) pull new advisories from the GitHub Advisory Database, extract and filter the fix diffs, analyze them with an LLM, and match the vulnerability pattern against a growing historical database.

---

*Built by [Christbowel](https://christbowel.com) · [Full index](https://christbowel.github.io/osdc)*