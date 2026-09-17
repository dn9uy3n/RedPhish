# tools/patches — HISTORICAL, FROZEN

These patch scripts are **how the fork was originally built** (2026-09-07/08 lab):
they patch a pristine upstream `evilginx2` CE 3.3.0 source tree feature by feature
(AES params, REST API, multidomain, botguard v1/v2, rewrite_urls, jsobf, webhook…).

**They are not the source of truth anymore.** `src/` in this repository is the
living, already-patched tree — edit it directly. These scripts and the `.go`
reference copies are kept for archaeology and for re-deriving the fork from
upstream if ever needed.

- Do not run them against `src/` (they expect an upstream tree at `~/evilginx2-src`).
- Do not update them when changing `src/`.
