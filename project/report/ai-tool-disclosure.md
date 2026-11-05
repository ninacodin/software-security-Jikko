# AI-tool Usage Disclosure — Team Jikko

> The submitted version of this table is in [`../REPORT.md`](../REPORT.md) → *AI-tool usage disclosure*;
> keep the two in sync. Academic integrity: state honestly how AI tools were used. **Each member owns
> their own row** — edit it to match what actually happened; do not under- or over-state. "None" is a
> valid answer for a row.

| Member | Tool | How it was used |
|---|---|---|
| Supawan | Claude (Claude Code, Opus) | Drafting the threat model (DFD + STRIDE, §2–3); writing up the 3 injection findings (§4) and remediation explanations (§5); reviewing the parameterized-query and `shell=False` fixes; **running the before/after exploit verification in Docker** and capturing the results; generating the DFD diagram (SVG); organising the report sections; and guidance on PowerShell / Git / Docker commands and Thai–English explanation. All AI output was read, **verified by running**, and edited by the author before use; the author can explain every fix and payload unaided. |
| Phuriphat | Claude Code | Reviewed the code, implemented and tested the auth/session/crypto fixes (F-04 – F-08), drafted the first report skeleton. All fixes reviewed and run by the member. |
| Danaiphong | Codex | Reviewed the access-control code, proposed patches and the regression test suite, drafted notes. The member checked the results and explains the fixes in their own words. |
| Sadayu | Claude Code | Helped run Trivy / pip-audit / Cosign, write the Dockerfile and CI workflow, and merge the four members' sections into the report. All tool output in `person-d/evidence/` comes from real runs. |

**Honesty notes (read before submitting):**
- If AI helped **write the actual fix code** (not just the report), say so in the row — don't hide it.
- If anyone used **ChatGPT / Copilot / Gemini / etc.**, list that tool too, not just Claude.
- Keep it specific ("drafted the STRIDE table", "generated the CI YAML") rather than vague ("used AI to help").
- The instructor cross-checks against each member's **commit history** — the disclosure should be consistent with who committed what.
