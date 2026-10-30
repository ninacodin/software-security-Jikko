# AI-tool Usage Disclosure — Team Jikko

> Goes into the report's "AI-tool usage disclosure" section. Academic integrity: state honestly
> how AI tools were used. **Each member fills their own rows** — the entries below are Person A's
> (Supawan); B/C/D must add theirs. Edit to match what actually happened; do not under- or
> over-state. "None" is a valid answer for a row.

| Tool | How it was used |
|---|---|
| Claude (Claude Code, Opus) — **Person A** | Drafting the threat model (DFD + STRIDE, §2–3); writing up the 3 injection findings (§4) and remediation explanations (§5); reviewing the parameterized-query and `shell=False` fixes; **running the before/after exploit verification in Docker** and capturing the results; generating the DFD diagram (SVG); organising the report sections; and guidance on PowerShell / Git / Docker commands and Thai–English explanation. All AI output was read, **verified by running**, and edited by the author before use; the author can explain every fix and payload unaided. |
| Claude / other AI — **Person B** | *(fill in: e.g. drafting auth/session/crypto findings, researching JWT `none` / CWE-347, etc. — or "None")* |
| Claude / other AI — **Person C** | *(fill in: access-control / XSS findings, IDOR research, etc. — or "None")* |
| Claude / other AI — **Person D** | *(fill in: SBOM/Cosign commands, GitHub Actions CI drafting, dependency-CVE lookup, etc. — or "None")* |

**Honesty notes (read before submitting):**
- If AI helped **write the actual fix code** (not just the report), say so in the row — don't hide it.
- If anyone used **ChatGPT / Copilot / Gemini / etc.**, list that tool too, not just Claude.
- Keep it specific ("drafted the STRIDE table", "generated the CI YAML") rather than vague ("used AI to help").
- The instructor cross-checks against each member's **commit history** — the disclosure should be consistent with who committed what.
