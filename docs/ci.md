# CI notes

## Decision goldens

`internal/decide/testdata/golden/decide/*.json` is the regression baseline for
the ranking engine. Each file is one scenario: the tuning, the persisted state
at scenario start, and an ordered list of steps. Every step carries the observed
transit health and the exact `Decision` the engine must return.

`TestGoldenDecide` walks the directory, replays each scenario through
`decide.Evaluate`, and compares the result against the committed file
byte-for-byte. There is no fuzzy matching: a single changed field fails the
build. The set deliberately includes the all-features-off baseline, which must
stay identical to today's decisions, plus the hysteresis / dwell / win-cycles /
freeze / loss-exclusion interactions.

**Every decide-touching PR must update the goldens deliberately.** If a change
to the ranking surface alters a golden, that diff is the point of the review:
either the change is intended, in which case regenerate and explain the diff in
the PR body, or it is a regression, in which case fix the code. CI fails on an
unexpected diff, so a behavior change cannot land silently.

Regenerate on purpose:

```
make golden-update        # UPDATE_GOLDEN=1 go test ./... -run TestGolden
```

Review `git diff internal/decide/testdata/golden/` before committing — the
diff is the behavior change, in reviewable form.

Rule of thumb: one ranking-behavior change per release window. Sequencing two
decide-surface changes together makes any golden diff ambiguous, so land them
separately.

## Golden vtysh batches

`internal/act/testdata/*.golden` is the regression baseline for the runtime
mutation batches act issues. Each file is one side of one batch — the ordered
command list WITHOUT the `configure terminal` / `end` framing, which the
executor's runner owns.

`TestGoldenBatches` builds each named batch, validates it, and compares both
sides byte-for-byte against the committed files. The set covers the batches
issue #4 names: neighbor shutdown (apply `neighbor <ip> shutdown`, rollback
`no neighbor <ip> shutdown`) and the tcp-mss clamp (apply `neighbor <ip>
tcp-mss <value>`, rollback `no neighbor <ip> tcp-mss <value>`).

Two invariants are enforced around these goldens, not by the golden files
themselves:

- **Paired.** Every `Batch` carries a `Rollback` that is the textual inverse of
  its `Apply`; `Batch.Validate` refuses a batch with an empty side.
- **Runtime-only.** `Batch.Validate` refuses any command whose verb is a
  config-persisting one (`write file` and its neighbours) before anything is
  exec'd, so a golden can never encode a mutation that survives a config
  re-apply.

A golden diff is a behavior change and belongs in the PR body, the same way a
decide golden diff does.
