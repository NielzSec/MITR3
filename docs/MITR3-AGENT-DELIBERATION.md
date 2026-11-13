# MITR3 agent deliberation

Agents discuss on an append-only JSONL board before a recommendation is recorded. Morfeus opens the topic. At least two other catalog agents each post a stance. The coordinator then records one decision id. That record is not scope approval, not a finding, and not permission to run a phase.

`human_approved` stays false. `executes` stays false. The pilot cap of two running workers is unchanged: posting on the board does not start a worker.

There is no phantom board on `main` or `master` today. This board is that layer. Orca remains the panel for sessions and worktrees; this file is the decision log.

## Board

Default path:

- `~/MITR3/state/offensive/board.jsonl` when that checkout exists
- otherwise `<repo>/state/offensive/board.jsonl`
- `MITR3_BOARD` or `--board` overrides both

The file mode is `0600`. Symlinks are refused. A corrupt line fails the read instead of being skipped, so a decision cannot hide behind a broken record. The directory is gitignored.

Generic notes and deliberation events share the file. Kinds used by the protocol:

| Kind | Who | What |
| --- | --- | --- |
| `deliberation.open` | Morfeus | topic, phase, impact, invited agents |
| `deliberation.propose` | invited agent | `proceed`, `hold`, or `abort` |
| `deliberation.critique` | invited agent | optional reply to one proposal |
| `deliberation.decide` | Morfeus | outcome, rationale, dissent, stable `decision_id` |

The decision id is the first 16 hex chars of a SHA-256 over the canonical decision fields (`dec-` prefix). `show` recomputes that id from the thread. A rewritten outcome, a missing proposer, or `executes: true` fails closed as `TAMPERED`. The id is not a signature; anyone who can rewrite the whole thread can write a consistent replacement. Quorum is enforced by the protocol before the line is appended.

## Quorum

A decision requires two distinct proposers. Opening the topic does not count. A second proposal from the same agent does not count. `decide` with fewer than two proposers returns `QUORUM` and writes nothing. A second `decide` on the same topic returns `CLOSED` and leaves the original id in place.

Dissent is derived from proposals whose stance differs from the outcome. The coordinator cannot omit it.

High-impact phase names are fixed: `web-exploit`, `exec`, `network-active`, `auth-test`. Passing `--impact low` does not downgrade them. Unattended stub rounds cannot recommend `proceed` on those phases. An explicit `decide --outcome proceed` can still be recorded after two proposals; swarm will not launch anything from it.

## CLI

Stub rounds do not call a model. `--dry-run` prints the round and does not create the board. Without `--dry-run`, the same stubs are appended.

```bash
python3 bin/mitr3-deliberate.py run \
  --topic "Review the local fixture inventory" \
  --phase js-inventory --impact low --agents glyph,ward

python3 bin/mitr3-deliberate.py show --topic-id tpc-xxxxxxxxxxxx
python3 bin/mitr3-deliberate.py show --decision-id dec-xxxxxxxxxxxxxxxx
python3 bin/mitr3-deliberate.py tail -n 20 --topic-id tpc-xxxxxxxxxxxx

python3 bin/mitr3-deliberate.py --dry-run run \
  --topic "Gate before web-exploit" \
  --phase web-exploit --agents specter,cipher

python3 tools/phantom/board.py --self-test
python3 bin/mitr3-deliberate.py self-test
```

Manual round:

```bash
python3 bin/mitr3-deliberate.py open \
  --topic "Should this stay a recommendation?" \
  --phase review --agents glyph,ward

python3 bin/mitr3-deliberate.py propose --topic-id tpc-... --agent glyph --stance hold --body "Hold."
python3 bin/mitr3-deliberate.py propose --topic-id tpc-... --agent ward --stance hold --body "Hold."
python3 bin/mitr3-deliberate.py critique --topic-id tpc-... --agent ward --target-agent glyph --body "Agreed."
python3 bin/mitr3-deliberate.py decide --topic-id tpc-... --outcome hold --rationale "Both held."
```

`python3 tools/phantom/board.py deliberate ...` is the same CLI.

Catalog ids come from `hackbots/bots.json`. The opener and the decider are the catalog coordinator (`morfeus`). Specialists in the sample are Glyph, Ward, Specter, and Cipher. Unknown ids are rejected. Text that looks like a credential (`api_key=...`, a private-key block) is rejected and is not written.

## Swarm hook

`tools/phantom/swarm.py` is only the gate. It does not contain an executor.

```bash
python3 tools/phantom/swarm.py phases
python3 tools/phantom/swarm.py run --phase web-exploit --deliberate --agents specter,cipher
python3 tools/phantom/swarm.py run --phase web-exploit --deliberate --dry-run
```

`--exec` without `--deliberate` exits `2` with `DELIBERATION_REQUIRED` and writes nothing. `--exec` with `--deliberate` writes the recommendation, then exits `3` with `EXEC_NOT_IMPLEMENTED`. A future runner must call `before_exec()` in that module and still refuse unless a human Nexus accept exists outside this repository path. Do not treat `outcome=proceed` as that accept.

## Tests

```bash
python3 -m unittest tests.test_deliberation -v
python3 tools/phantom/board.py --self-test
```

No network. The board self-test covers post, tail, mode `0600`, corrupt lines, and symlink refusal. The protocol tests cover quorum, a stable decision id on re-query, and the high-impact hold.
