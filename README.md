# icloud_wipe

Fast, resumable deletion of an entire iCloud Photos library from the command
line. Built for large libraries: enumeration uses a trimmed CloudKit query
(~100 assets per page) and deletion is batched at 100 operations per HTTP
POST, so a 35,000-photo library takes about 350 batched requests instead of
35,000 single-photo operations.

Every run re-enumerates the live library, so an interrupted pass resumes from
the library's actual state on the next run — no resume bookkeeping to lose.

Safety by default:

- no flags → dry run (enumerate, count, sample filenames, delete nothing)
- `--go` deletes, with a 10-second abort window (Ctrl-C cancels)
- `--limit N` caps a run to N items (micro-test: `--go --limit 3`)
- deleted photos go to iCloud's "Recently Deleted" album, recoverable for ~30 days
- `--rd` (experimental) targets the Recently Deleted album instead; that step
  is irreversible

## Requirements

- Python 3.10+ (tested on 3.14)
- A vendored checkout of the
  [timlaing/pyicloud](https://github.com/timlaing/pyicloud) fork at `./pyicloud`
  (the script inserts that path into `sys.path` and imports it; the fork's SRP
  sign-in is what talks to Apple's current auth endpoint — older pyicloud
  releases fail with 503)
- pip packages (system Python is PEP 668 managed here, hence the venv):

  ```sh
  python3 -m venv .venv
  .venv/bin/pip install requests tzlocal pydantic cryptography fido2 srp "protobuf<8" tinyhtml
  ```

  `keyring` is not required — the script stubs it out because the password is
  always passed explicitly.

## Credentials

Either create `secrets.txt` (line 1: Apple ID email, line 2: password):

```
your.name@icloud.com
yourpassword
```

Or run `icloud_wipe.py` with no secrets file in an interactive terminal: it
prompts for the Apple ID and password (input hidden), then offers to save
`secrets.txt` with 0600 permissions for future headless runs.
`--ask-credentials` re-prompts even when the file exists (Enter accepts the
saved email). A headless run without `secrets.txt` exits with code 7 and
instructions.

## Two-factor auth

Apple requires a 6-digit 2FA code on first sign-in; after that the session is
trusted for ~30 days (state lives in `.icloud_session/`) and reruns skip 2FA.

- Interactive terminal: the code is prompted (3 tries). After 3 rejections it
  falls back to the drop-file wait below instead of giving up.
- Headless (cron, nohup): the script logs a loud `[WAIT-2FA]` banner and polls
  `2fa_code.txt` in the project directory every 20 s for up to 1 h; write the
  code into the file and it is picked up and consumed automatically. Exit
  code 3 on timeout.

## Commands

```sh
# dry run: enumerate + count + sample names, deletes nothing
.venv/bin/python icloud_wipe.py

# interactive: prints an estimate, asks y/N (default N declines),
# deletes with a 10 s countdown on y
.venv/bin/python icloud_wipe.py --limit 3   # micro-test: 3 items

# headless: no prompts at all; credentials/2FA as above
.venv/bin/python icloud_wipe.py --go

# reuse the previous enumeration instead of re-querying Apple
.venv/bin/python icloud_wipe.py --go --from-manifest

# experimental: expunge the Recently Deleted album (irreversible)
.venv/bin/python icloud_wipe.py --go --rd
```

Behavior matrix:

| flow        | credentials                                  | 2FA                                 | destructive step                          |
|-------------|----------------------------------------------|-------------------------------------|-------------------------------------------|
| interactive | prompt (hidden password) + 0600 save offer   | pin prompt, 3 tries → drop file     | y/N confirm (default N), then 10 s countdown |
| headless    | `secrets.txt` required (else exit 7)         | `2fa_code.txt`, 20 s poll, 1 h cap  | `--go`, 10 s countdown                    |

## Batching, retries, resume

- Enumeration: `CPLAssetAndMasterByAddedDate`, ~100 assets/page, trimmed
  record keys, deduplicated across pages.
- Deletion: 100 operations per `records/modify` POST (`--batch-size N`).
- Retries: 429/503/507/509 back off 5 s, 20 s, 80 s … capped at 600 s, 8
  attempts per batch; a batch that still fails is bisected down to single
  operations.
- `failed.jsonl` lists operations that failed permanently — a rerun retries
  them.
- Pacing: 1.5 s between batches. Apple throttles sustained bulk deletes: the
  original 0.5 s pace tripped a ~38-minute silent throttle window at ~8
  batches/min. Stay conservative.
- Resume: rerun the same command (fresh enumeration).
  `--from-manifest` reuses `manifest.jsonl` when nothing else has touched the
  library since that enumeration.

## Files

| path                      | purpose                                            |
|---------------------------|----------------------------------------------------|
| `manifest.jsonl`          | enumeration from the last run (atomic write)       |
| `deleted_manifest.jsonl`  | audit of every committed library deletion          |
| `deleted_rd_manifest.jsonl` | audit of every committed expunge (`--rd`)        |
| `failed.jsonl`            | permanently failed ops; a rerun retries them       |
| `.icloud_session/`        | cookies + ~30-day trust token; delete to re-2FA   |
| `2fa_code.txt`            | headless 2FA drop file (consumed on use)          |
| `wipe*.log`               | run logs                                           |

`WIPE_SKIP_VERIFY=1` skips the final verification re-enumeration (saves one
full enumeration pass).

## Exit codes

| code | meaning                                            |
|------|----------------------------------------------------|
| 0    | success                                            |
| 2    | login/auth failure                                 |
| 3    | 2FA wait timeout (1 h)                             |
| 4    | legacy 2SA required and session is headless        |
| 5    | photos index still in progress                     |
| 7    | credentials unavailable (no secrets.txt, headless) |
| 10   | finished with permanently failed operations        |
| 130  | interrupted                                        |
