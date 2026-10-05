<!--
Thanks for the PR. Keep it small and focused (see CONTRIBUTING.md).
Do not open public PRs that fix security vulnerabilities — report those
privately via SECURITY.md instead.
-->

## Summary

<!-- What does this change, and why? Link the issue it closes: "Closes #N". -->

## Checklist

- [ ] Tests added or updated for the behavior change.
- [ ] Golden files updated if applicable (e.g. `UPDATE_GOLDEN=1`), and the golden diff reviewed deliberately.
- [ ] No site-specific values anywhere in the diff — fixtures, examples, and comments use documentation ranges only (`2001:db8::/32`, `192.0.2.0/24`, `198.51.100.0/24`, AS 64496–64511).
- [ ] No secrets committed (gossip key, session keys, tokens).
- [ ] Docs updated if behavior, configuration, or operations changed.
- [ ] `gofumpt`-formatted and `make test` / `make lint` (or the `go` equivalents) pass locally.
- [ ] CI is green.

## Notes for the reviewer

<!-- Anything non-obvious: safety implications, alternatives rejected, follow-ups. -->
