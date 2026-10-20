# tg-rotate

**Rotate a Telegram bot token like it matters — because it does.**

`tg-rotate` is a small, dependency-free CLI that supervises the full
lifecycle of rotating a Telegram Bot API token: it **finds** every copy
of the old token on your machines, **replaces** them all atomically, and
**verifies** that the running service actually answers on the new token —
with an automatic rollback if anything looks wrong.

> Rotating a token means nothing if a stale copy keeps working.
> `tg-rotate` makes sure that doesn't happen.

---

## Why this exists

When a bot token leaks, the standard advice is "just revoke it and make
a new one." In practice that means:

1. Find every `.env`, config file, systemd unit, CI secret, and copy-pasted
   script that mentions the old token — on *every* machine.
2. Replace them all without typos, without breaking file permissions,
   and without missing one.
3. Restart the service and confirm the bot actually works on the new token.
4. Confirm the old token is truly dead.

Steps 1 and 3 are where incidents go wrong: a forgotten copy in a backup
directory keeps a compromised token alive, and a bot that silently fails
to start means downtime nobody notices until users complain.

`tg-rotate` does all four steps as one supervised operation.

---

## Install

No dependencies — pure Python 3.9+.

```bash
git clone https://github.com/shouvikkkk/tg-rotate
cd tg-rotate
pip install -e .          # or: pip install tg-rotate (when published)
```

The CLI is `tg-rotate`. You can also run it as a module: `python -m tg_rotate`.

---

## Quick start

```bash
# 1. See every place the old token lives (dry run, no changes)
tg-rotate audit --old-token "$OLD" --paths ~/bots /etc/mybot

# 2. Rotate: replace everywhere, verify, rollback on failure
tg-rotate rotate --old-token "$OLD" --new-token "$NEW" \
    --paths ~/bots /etc/mybot

# 3. Just run the verification suite (no replacement)
tg-rotate verify --old-token "$OLD" --new-token "$NEW" --paths ~/bots
```

Get the new token first from [@BotFather](https://t.me/BotFather) with
`/revoke` — revoking the old token is what makes step 2 safe.

### A typical incident run

```bash
# The old token leaked in a log file. New token already issued.

# Preview what will change (nothing is modified)
tg-rotate rotate --old-token "$OLD" --new-token "$NEW" \
    --paths /opt/bot /home/deploy --dry-run

# Do it for real. Exits non-zero and rolls back on verification failure.
tg-rotate rotate --old-token "$OLD" --new-token "$NEW" \
    --paths /opt/bot /home/deploy

# Rotate the token the shell sees, then restart the service
tg-rotate rotate --old-token "$OLD" --new-token-file ./new_token.txt \
    --paths /opt/bot
systemctl restart mybot   # tg-rotate never restarts services itself
```

---

## What it does

### 1. Discovery (`audit`)

Scans the given paths — recursively — for files containing the old token:

- Skips binary files, giant files, and common junk directories
  (`.git`, `node_modules`, `__pycache__`, `.venv`, …).
- Redacts the token in all output: locations are shown as paths with
  match counts, never token values.
- Exit code `2` when copies are found (handy for CI gates), `0` when clean.

### 2. Atomic replacement (`rotate`)

For every file containing the old token:

1. A backup copy is written next to the original (`<file>.bak-<run-id>`).
2. The file is rewritten with **all** occurrences replaced, preserving
   permissions, ownership, and line endings.
3. If verification fails, every file is restored from its backup
   automatically — the filesystem ends up exactly as it started.

### 3. Verification (the important part)

After replacement, `tg-rotate` runs four checks against the real world:

| # | Check | What it proves |
|---|-------|----------------|
| 1 | `old-token-gone` | No file under the scanned paths still contains the old token |
| 2 | `new-token-works` | `getMe` on the new token returns a valid bot identity |
| 3 | `old-token-dead` | `getMe` on the old token returns 401 — it is really revoked |
| 4 | `state-consistent` | The state file records fingerprints of both tokens |

Any check that cannot reach Telegram **fails closed**: an unverifiable
rotation is treated as a failed rotation, and rollback kicks in. There is
also `--skip-api` for air-gapped environments, which runs only the local
checks.

### 4. State file

Every run appends to `~/.tg-rotate/state.json` (mode `0600`):

- Which files changed, the run id, timestamps, verification results.
- **Token fingerprints (SHA-256 prefixes), never full tokens.**

This gives you an audit trail: "on Tuesday we rotated from `a3f9…` to
`77c1…`, all checks passed."

---

## CLI reference

```
tg-rotate audit  --old-token T --paths P [P ...] [--format text|json]
tg-rotate rotate --old-token T (--new-token T | --new-token-file F)
                 --paths P [P ...] [--dry-run] [--skip-api]
                 [--state-path S] [--format text|json]
tg-rotate verify --old-token T --new-token T --paths P [P ...]
                 [--skip-api] [--state-path S] [--format text|json]
```

- Tokens can come from `--old-token`/`--new-token`, a file, or the
  `TG_OLD_TOKEN` / `TG_NEW_TOKEN` environment variables.
- The new token is validated for shape (`<digits>:<35 chars>`) and is
  rejected if it is identical to the old one.
- `--dry-run` shows the plan without touching anything.
- `--format json` emits machine-readable output for scripts and CI.
- Exit codes: `0` success · `1` error · `2` audit found copies / verification failed.

---

## Design notes

- **Fail closed.** Every ambiguity — network down, API unreachable,
  half-written file — is treated as failure, never as success.
- **The token is never logged.** Output shows fingerprints and paths only.
  The state file stores hashes, not secrets.
- **No magic restarts.** `tg-rotate` changes files; *you* restart the
  service. That keeps the blast radius obvious and auditable.
- **Stdlib only.** No `requests`, no dependencies to audit — the Bot API
  probe uses `urllib` with short timeouts.

---

## Testing

```bash
pytest -q
```

The suite is hermetic: no network, no Telegram, no real tokens. Bot API
calls are stubbed; fixtures use synthetic tokens like
`111111111:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`.

---

## Token hygiene (worth reading once)

- Generate the new token with `/revoke` in BotFather **before** rotating,
  so the old one dies at a known moment.
- Store tokens in environment variables or a secret manager, not in
  checked-in files. `tg-rotate` can clean up the copies, but fewer copies
  is better than faster cleanup.
- After rotation, check BotFather's active sessions if your bot uses
  webhooks — update the webhook URL secret too.
- Rotate on a schedule, not just on incidents. A token that has lived in
  twelve places for two years is twelve chances for a leak.

---

## License

MIT — see [LICENSE](LICENSE).
