# unproven

For each check in code an AI wrote: delete it, and see whether anything notices.

AI agents write more and more of the code we ship. It compiles, the tests pass, and it may still
not do what it says. unproven makes that concrete. You list the checks in a piece of code (each
`require`, each binding of one account to another). unproven deletes them one at a time, rebuilds,
and runs your tests, and your fuzzer if you have one. Each check ends up in one of four rows:

| What noticed the deletion | What it means |
|---|---|
| the fuzzer | a missing binding the fuzzer can find on its own |
| a test | a rule someone wrote down |
| something else refused the call | another check, the runtime or a library stands in for it |
| **nothing** | **unproven**: as far as the repository can tell, the code behaves the same without it |

The table lives in an `unproven.toml` next to your code. Run it in CI and it is measured again on
every pull request, so it cannot drift from the code without the build saying so.

We say plainly what the AI wrote. The point is not to hide it. It is to check it and understand it.

## Use it

```bash
cargo install --git https://github.com/fabrknt/unproven --tag v0.1.0
unproven path/to/unproven.toml                  # every row, after a baseline run
unproven path/to/unproven.toml --only "Close:"  # some rows, while you write them
```

The last line counts the rows by kind. The exit code is 1 if any row no longer reads the way
the file says, and 2 if something could not run.

The file holds the commands (`build`, `test`, optionally `fuzz`, `probe` and `prepare`) and one
`[[claim]]` per check. [`examples/unproven.toml`](examples/unproven.toml) is a real one, with 17
rows. What it reads, today:

- tests: `cargo test`'s output (`test <path> ... FAILED`). A test command that fails with no
  failing test is a build error, and stops the run.
- fuzz: [Crucible](https://github.com/asymmetric-research/crucible)'s (`[FUZZ_FINDING] [...]`). A
  fuzzer that exits early or never prints `fuzz_alive` (default `[FUZZ_PULSE]`) stops the run,
  so a fuzzer that did not run is never read as "no finding".
- probe: your own command, one line per call: `PROBE <spec> | <variant> | ok=<bool> | <log>...`.

A check is deleted by replacing `find` inside the function that starts at `in_fn`, to its
matching closing brace. Both must occur exactly once. The original is written next to the file
first and put back after each row, on an error, on Ctrl-C and on SIGTERM. After a signal, and
after a run killed outright, `<file>.unproven-orig` stays next to it; the next run puts it back
(after a signal it is the same as the file, and can also simply be deleted).

## With an AI agent

The agent does the reading: it chooses the checks, writes the rows, predicts, and explains what came back.
unproven does the deleting and running and decides each row, so the agent does not grade its
own work. Give a Claude Code agent the skill:

```bash
mkdir -p .claude/skills/unproven
curl -fsSL https://raw.githubusercontent.com/fabrknt/unproven/v0.1.0/skills/unproven/SKILL.md \
    -o .claude/skills/unproven/SKILL.md
```

[`skills/unproven/SKILL.md`](skills/unproven/SKILL.md) is also readable as plain instructions for
any other agent. It lists the traps that made our own rows read wrong.

## Where we use it

- [psyto/openhl-solana](https://github.com/psyto/openhl-solana), Chapter 11 (positions and
  liquidation): the handlers were written with Claude on 2026-05-23. A fuzzer found a
  cross-market oracle hole in them five and a half months later. All 17 rows are re-measured in CI
  ([`fuzz/positions/claims.toml`](https://github.com/psyto/openhl-solana/blob/main/fuzz/positions/claims.toml)).
  Of the 17, 11 are caught by the fuzzer, 2 by a test only and 4 are refused by something else.

## Status

0.1, used on one repository so far. Planned next: test output from Foundry and other runners, and
finding the checks automatically (from [solinv](https://github.com/psyto/solinv) for Solana programs).

## License

Apache-2.0.
