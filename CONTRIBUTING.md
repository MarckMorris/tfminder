# Contributing

- One rule, one test. A new `gcp-guard` rule needs a test for the case it catches and one for the
  unchanged/already-bad case it must stay quiet on (rules blame a plan only for what it changes).
- Evidence first: every finding carries the values it was derived from in `evidence`.
- Run `ruff check . && pytest` before opening a PR. The end-to-end tests need `terraform` or `tofu` on PATH.
- Plan JSON captured from a real `terraform plan` against Google Cloud is the most useful contribution
  right now. Strip project IDs and secrets, then add it under `tests/fixtures/`.
