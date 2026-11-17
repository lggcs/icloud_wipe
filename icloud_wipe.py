#!/usr/bin/env python3
"""Fast, resumable iCloud Photos library wipe.

Why this beats one-photo-per-request (old delete.py):
  * enumerates the whole library with a trimmed-metadata query (~100 assets/page)
  * deletes in BATCHES: records/modify accepts an operations[] array, so
    100 photos cost ONE HTTP POST instead of one
    -> ~35,000 photos = ~350 batch POSTs (minutes), not 35,000 (days)
  * enumerates fresh on every run, so the library itself is the resume state
  * retries transient errors with exponential backoff, bisects failing
    batches down to single operations, keeps a JSONL audit manifest
  * reuses a persistent iCloud session (icloud_session/) so the ~30-day
    trust token removes repeated 2FA prompts; if Apple ever invalidates the
    session mid-run it waits for a code in 2fa_code.txt and keeps going

Modes:
  default          dry-run: enumerate, count, sample names, delete nothing
  --go             actually delete the entire library (goes to Recently Deleted)
  --rd --go        (experimental) purge 'Recently Deleted' album instead
  --limit N        delete at most N (live micro-test: try --go --limit 3)
  --from-manifest  reuse the prior enumeration (manifest.jsonl) instead of
                   re-querying Apple - only correct when no other device or
                   process has touched the library since that enumeration
  --ask-credentials  re-prompt for Apple ID / password even with secrets.txt
  (no secrets.txt)  prompts for them interactively and can save secrets.txt

Exit codes: 0 ok | 2 login/auth failure | 3 2FA wait timeout | 4 2SA headless
            5 indexing in progress | 7 credentials unavailable
            10 finished but some operations permanently failed | 130 interrupted
"""
import argparse
import base64
import getpass
import json
import os
import sys
import time
import types
from pathlib import Path
from urllib.parse import urlencode

PROJECT = Path(__file__).resolve().parent
VENDORED_PYICLOUD = PROJECT / "pyicloud"
sys.path.insert(0, str(VENDORED_PYICLOUD))

# The vendored pyicloud imports keyring at import time but never needs it
# when the password is passed explicitly - stub it out to skip the
# cryptography dependency chain.
try:
    import keyring  # noqa: F401
except ImportError:
    _stub = types.ModuleType("keyring")
    for _name in ("get_password", "set_password", "delete_password"):
        def _reject(*_a, **_k):
            raise RuntimeError("keyring stub: password must be passed explicitly")
        setattr(_stub, _name, _reject)
    sys.modules["keyring"] = _stub

import requests  # noqa: E402
from pyicloud import PyiCloudService  # noqa: E402
from pyicloud.exceptions import (  # noqa: E402
    PyiCloud2FARequiredException,
    PyiCloud2SARequiredException,
    PyiCloudAPIResponseException,
    PyiCloudAuthRequiredException,
    PyiCloudException,
    PyiCloudFailedLoginException,
    PyiCloudServiceNotActivatedException,
    PyiCloudServiceUnavailable,
)

SECRETS_FILE = PROJECT / "secrets.txt"
COOKIE_DIR = str(PROJECT / ".icloud_session")
TWOFAC_FILE = PROJECT / "2fa_code.txt"
MANIFEST = PROJECT / "manifest.jsonl"
AUDIT_FAILED = PROJECT / "failed.jsonl"

LIST_TYPE_LIBRARY = "CPLAssetAndMasterByAddedDate"
LIST_TYPE_RECENTLY_DELETED = "CPLAssetAndMasterDeletedByExpungedDate"
DESIRED_KEYS = ["recordName", "recordType", "recordChangeTag", "masterRef",
                "filenameEnc", "isDeleted"]
PAGE_PAIRS = 100          # masters per enumeration page (resultsLimit = *2)
DEFAULT_BATCH = 100       # delete operations per records/modify POST
THROTTLE_CODES = {429, 503, 507, 509}
AUTH_CODES = {401, 421, 450, 500}
MAX_PAGES = 10000         # safety guard for the enumeration loop


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def wrap_field(value):
    return {"value": value}


def read_secrets(path):
    try:
        lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
                 if l.strip()]
    except OSError as e:
        log(f"FATAL: cannot read {path}: {e}")
        raise SystemExit(7)
    if len(lines) < 2 or "@" not in lines[0]:
        log(f"FATAL: {path} must have email on line 1, password on line 2")
        raise SystemExit(7)
    return lines[0], lines[1]


def resolve_credentials(force_prompt=False):
    """secrets.txt wins unless --ask-credentials; otherwise prompt on a TTY
    (hidden password, offer a 0600 save so headless reruns work)."""
    if not force_prompt and SECRETS_FILE.is_file():
        return read_secrets(SECRETS_FILE)
    if sys.stdin.isatty() and sys.stdout.isatty():
        default_email = ""
        if SECRETS_FILE.is_file():
            first = SECRETS_FILE.read_text(encoding="utf-8").splitlines()
            if first and "@" in first[0]:
                default_email = first[0].strip()
        suffix = f" [Enter = {default_email}]" if default_email else ""
        email = input(f"Apple ID email{suffix}: ").strip() or default_email
        if not email or "@" not in email:
            log("FATAL: a valid Apple ID email is required")
            raise SystemExit(7)
        password = getpass.getpass("Apple ID password (input hidden): ")
        if not password:
            log("FATAL: a password is required")
            raise SystemExit(7)
        if input(f"Save credentials to {SECRETS_FILE.name} for future "
                 "headless runs? [Y/n]: ").strip().lower() not in ("n", "no"):
            SECRETS_FILE.write_text(f"{email}\n{password}\n",
                                    encoding="utf-8")
            os.chmod(SECRETS_FILE, 0o600)
            log(f"saved {SECRETS_FILE.name} (chmod 600) - delete it to "
                "return to always-interactive mode")
        return email, password
    log(f"FATAL: {SECRETS_FILE.name} is missing and stdin is not a "
        "terminal - create the file (line 1 email, line 2 password) or "
        "run icloud_wipe.py once from an interactive terminal")
    raise SystemExit(7)


def _wait_2fa_file(api):
    """Headless 2FA: loud, bounded (1h) wait for the TWOFAC_FILE drop."""
    waited = 0
    while waited < 3600:
        if TWOFAC_FILE.exists():
            code = TWOFAC_FILE.read_text(encoding="utf-8").strip()
            if code:
                log(f"Read code from {TWOFAC_FILE.name}, validating...")
                if api.validate_2fa_code(code):
                    TWOFAC_FILE.unlink()
                    log("2FA accepted, session trusted")
                    return
                log("2FA code rejected - replace/remove "
                    f"{TWOFAC_FILE.name} with a fresh code")
        if waited % 60 == 0:
            log(f"[WAIT-2FA] still waiting - write the 6-digit code to "
                f"{TWOFAC_FILE.name} ({waited}s elapsed, cap 1h)")
        time.sleep(20)
        waited += 20
    log("[WAIT-2FA] timed out after 1h - exiting; nothing was deleted "
        "unless --go is set, rerun the same command once the file exists")
    raise SystemExit(3)


def ensure_trust(api):
    """2FA: TTY pin prompts, headless drop-file wait - either way the
    session ends trusted (~30 days, no repeated codes)."""
    if not (api.requires_2fa or api.requires_2sa):
        return

    if api.requires_2fa:
        log("Apple requires a 2FA code for this session - a prompt should "
            "be popping up on your iPhone/iPad/Mac screens")
        if sys.stdin.isatty():
            for _ in range(3):
                code = input("Enter the 6-digit 2FA code: ").strip()
                if api.validate_2fa_code(code):
                    log("2FA accepted, session trusted")
                    return
                print("Code rejected.")
            log(f"3 codes rejected - write a fresh code to "
                f"{TWOFAC_FILE.name} and it will be picked up")
        _wait_2fa_file(api)

    # Legacy two-step auth (2SA) - modern accounts are 2FA, keep it tty-only.
    if not sys.stdin.isatty():
        log("FATAL: legacy 2SA required and this session is headless. "
            "Run icloud_wipe.py from an interactive terminal once to trust "
            "this machine, then resume headless.")
        raise SystemExit(4)
    devices = api.trusted_devices
    for i, device in enumerate(devices):
        name = device.get("deviceName") or device.get("phoneNumber")
        print(f"  {i}: {name}")
    pick = int(input("Which device? "))
    if not api.send_verification_code(devices[pick]):
        raise SystemExit(2)
    if not api.validate_verification_code(devices[pick], input("Code: ").strip()):
        raise SystemExit(2)


def build_api(email, password):
    log(f"Signing in as {email.split('@')[0]}@<redacted> "
        f"(session dir: {Path(COOKIE_DIR).name}/)")
    for attempt in range(1, 4):
        try:
            api = PyiCloudService(email, password, cookie_directory=COOKIE_DIR)
            ensure_trust(api)
            return api
        except PyiCloudException as e:
            log(f"Login attempt {attempt}/3 failed ({type(e).__name__}): {e}")
            if attempt == 3:
                raise SystemExit(2)
            time.sleep(5)
    raise SystemExit(2)  # unreachable


class WipePhotos:
    """Thin wrapper mirroring PhotosService: same endpoint/params/session,
    but we send trimmed queries + batched modifies. Replaces per-photo objects
    entirely (they are what makes the old script slow)."""

    def __init__(self, api):
        try:
            svc = api.photos  # triggers the indexing-state check
        except (PyiCloudServiceNotActivatedException,
                PyiCloudServiceUnavailable) as e:
            log(f"FATAL: photos service not available yet ({e}); if the "
                "library is being indexed, wait a few minutes and rerun.")
            raise SystemExit(5)
        self.endpoint = svc.service_endpoint
        self.params = dict(svc.params)
        self.session = svc.session

    def _post(self, tail_url, body, timeout=(15, 90)):
        url = f"{self.endpoint}{tail_url}"
        return self.session.post(url, data=json.dumps(body),
                                 headers={"Content-type": "text/plain"},
                                 timeout=timeout)


def enumerate_assets(wph, list_type, skip_deleted=True):
    """Yield dicts of every asset in the given listing; paginated,
    deduped, trimmed. The yielded shape is the delete op's input."""
    url_tail = f"/records/query?{urlencode(wph.params)}"
    offset = 0
    seen = set()
    pages = 0
    while True:
        body = {
            "query": {
                "filterBy": [
                    {"fieldName": "startRank",
                     "fieldValue": {"type": "INT64", "value": offset},
                     "comparator": "EQUALS"},
                    {"fieldName": "direction",
                     "fieldValue": {"type": "STRING", "value": "ASCENDING"},
                     "comparator": "EQUALS"},
                ],
                "recordType": list_type,
            },
            "resultsLimit": PAGE_PAIRS * 2,
            "desiredKeys": DESIRED_KEYS,
            "zoneID": {"zoneName": "PrimarySync"},
        }
        raw = wph._post(url_tail, body)
        records = raw.json().get("records", [])
        pages += 1
        if pages > MAX_PAGES:
            log("FATAL: enumeration exceeded max pages - aborting to avoid "
                "an infinite pagination loop")
            raise SystemExit(6)
        assets = {}
        masters = []
        for rec in records:
            rtype = rec.get("recordType")
            if rtype == "CPLAsset":
                try:
                    mname = rec["fields"]["masterRef"]["value"]["recordName"]
                except (KeyError, TypeError):
                    continue
                assets[mname] = rec
            elif rtype == "CPLMaster":
                masters.append(rec)
        if not masters:
            break
        offset += len(masters)
        for m in masters:
            asset = assets.get(m["recordName"])
            if asset is None:
                continue
            is_deleted = bool(asset.get("fields", {}).get("isDeleted", {})
                              .get("value"))
            if is_deleted and skip_deleted:
                continue
            asset_id = asset["recordName"]
            if asset_id in seen:
                continue
            seen.add(asset_id)
            filename_enc = (m.get("fields", {}).get("filenameEnc", {})
                            .get("value"))
            try:
                filename = base64.b64decode(filename_enc).decode("utf-8",
                                                                 "replace")
            except (TypeError, ValueError):
                filename = "<unreadable>"
            yield {
                "asset": asset_id,
                "atype": asset.get("recordType", "CPLAsset"),
                "asset_tag": asset.get("recordChangeTag"),
                "tag": m.get("recordChangeTag"),
                "zone": asset.get("zoneID") or {"zoneName": "PrimarySync"},
                "filename": filename,
            }


def make_op(item, rd_mode):
    record = {
        "recordName": item["asset"],
        "recordType": item["atype"],
        "recordChangeTag": item.get("asset_tag") or item["tag"],
        "fields": {"isDeleted": {"value": 1}},
    }
    if rd_mode:
        record["fields"]["isExpunged"] = {"value": 1}
    return {"operationType": "update", "record": record}


def retryable(e):
    code = getattr(e, "code", None)
    if isinstance(code, int) and code in THROTTLE_CODES:
        return True
    text = f"{getattr(e, 'reason', e)}"
    return any(tok in text for tok in
               ("throttle", "Throttle", "ACCESS_DENIED", "Too Many Requests"))


def auth_required(e):
    return isinstance(e, (PyiCloud2SARequiredException,
                          PyiCloud2FARequiredException,
                          PyiCloudAuthRequiredException)) or (
        isinstance(getattr(e, "code", None), int)
        and getattr(e, "code") in AUTH_CODES)


def bisect_delete(wph, ops, rd_mode, ctx):
    """Recursive: shrink a failing batch until singles isolate the bad ops."""
    if len(ops) == 1:
        ctx["failed"].append(ops[0])
        item_id = ops[0]["record"]["recordName"]
        log(f"  single-op failure, giving up on {ctx['target'][item_id]} "
            f"(asset {item_id})")
        return False
    mid = len(ops) // 2
    log(f"  bisecting batch of {len(ops)} into {mid}+{len(ops)-mid}")
    return (delete_batch_checked(wph, ops[:mid], rd_mode, ctx)
            & delete_batch_checked(wph, ops[mid:], rd_mode, ctx))


def delete_batch_checked(wph, ops, rd_mode, ctx):
    """One records/modify call with backoff; bisect on persistent failure."""
    backoff = 5
    for attempt in range(1, 9):
        try:
            body = {"operations": ops,
                    "zoneID": ctx["zone_of"][ops[0]["record"]["recordName"]],
                    "atomic": True}
            wph._post(f"/records/modify?{urlencode(wph.params)}", body)
            return True
        except requests.RequestException as e:
            log(f"  network error (attempt {attempt}/8): {e}")
        except PyiCloudAPIResponseException as e:
            reason = getattr(e, "reason", "")
            if auth_required(e):
                log(f"  session expired (code {getattr(e, 'code', '?')}) - "
                    "re-establishing auth")
                api = ctx["api"]
                ensure_trust(api)
                backoff = 5
                continue
            if retryable(e) and attempt < 8:
                log(f"  backend throttling (attempt {attempt}/8), backing "
                    f"off {backoff}s: {reason}")
                time.sleep(backoff)
                backoff = min(600, backoff * 4)
                continue
            log(f"  batch failed permanently: {reason!r}")
            break
        if backoff == 5 and attempt < 8:
            backoff = 5
    return bisect_delete(wph, ops, rd_mode, ctx)


def delete_all(wph, items, api, rd_mode, batch_size, mode_name):
    total = len(items)
    if total == 0:
        log("Nothing to delete.")
        return True
    log(f"Deleting {total} items from '{mode_name}' "
        f"in batches of {batch_size} -> ~{-(-total // batch_size)} requests")
    ctx = {
        "api": api,
        "target": {i["asset"]: i["filename"] for i in items},
        "zone_of": {i["asset"]: i["zone"] for i in items},
        "failed": [],
    }
    audit_name = "deleted_rd_manifest.jsonl" if rd_mode \
        else "deleted_manifest.jsonl"
    audit = open(PROJECT / audit_name, "a", encoding="utf-8")
    batch_no = 0
    t0 = time.monotonic()
    done = 0
    try:
        for start in range(0, total, batch_size):
            chunk = items[start:start + batch_size]
            delete_batch_checked(wph, [make_op(i, rd_mode) for i in chunk],
                                 rd_mode, ctx)
            failed_names = {op["record"]["recordName"] for op in ctx["failed"]}
            committed = [i for i in chunk if i["asset"] not in failed_names]
            if committed:
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
                for i in committed:
                    audit.write(json.dumps(
                        {"ts": stamp, "filename": i["filename"],
                         "asset": i["asset"]}, ensure_ascii=False) + "\n")
                audit.flush()
            done += len(chunk)
            batch_no += 1
            rate = done / max(1e-9, time.monotonic() - t0)
            log(f"batch {batch_no}: committed {len(committed)}/{len(chunk)} "
                f"(total {done}/{total}, {done / total:.1%}) "
                f"{rate:.0f}/min · ETA "
                f"{int((total - done) / max(rate, 1e-9) / 60)}min")
            # ~8 batches/min sustained tripped a ~38-min Apple throttle
            # window; 1.5s keeps the pace below that threshold
            time.sleep(1.5)
    finally:
        audit.close()
    failures = ctx["failed"]
    if failures:
        with open(AUDIT_FAILED, "a", encoding="utf-8") as f:
            for rec in failures:
                f.write(json.dumps({"asset": rec["record"]["recordName"],
                                    "filename": ctx["target"].get(
                                        rec["record"]["recordName"])},
                                   ensure_ascii=False) + "\n")
        log(f"{len(failures)} operations failed permanently - written to "
            f"{AUDIT_FAILED.name}; rerunning the script retries them")
        return False
    return True


def count_listing(wph, list_type, skip_deleted=True):
    return sum(1 for _ in enumerate_assets(wph, list_type, skip_deleted))


def selftest():
    """Offline checks: pairing/pagination/dedupe/skip-deleted + op shape +
    error classification + full bisect decomposition."""
    class FakeResp:
        def __init__(self, data):
            self._d = data

        def json(self):
            return self._d

    def make_page(pairs, deleted_names=()):
        records = []
        for name, fn in pairs:
            records.append({
                "recordType": "CPLMaster", "recordName": name,
                "recordChangeTag": "mtag-" + name,
                "fields": {"filenameEnc": {"value": base64.b64encode(
                    fn.encode()).decode()}},
            })
            fields = {"masterRef": {"value": {"recordName": name}}}
            if name in deleted_names:
                fields["isDeleted"] = {"value": 1}
            records.append({
                "recordType": "CPLAsset", "recordName": "asset-" + name,
                "recordChangeTag": "atag-" + name,
                "zoneID": {"zoneName": "PrimarySync"},
                "fields": fields,
            })
        return FakeResp({"records": records})

    def fake_wph(pages):
        seq = iter(pages)
        wph = WipePhotos.__new__(WipePhotos)
        wph.endpoint = "https://offline.invalid"
        wph.params = {}
        wph.session = type("S", (), {
            "post": staticmethod(lambda *a, **k: next(seq))})()
        return wph

    # 1) pairing + pagination + dedupe across pages
    wph = fake_wph([
        make_page([("m1", "a.jpg"), ("m2", "b.jpg")]),
        make_page([("m3", "c.mov"), ("m2", "dup")]),
        FakeResp({"records": []})])
    items = list(enumerate_assets(wph, LIST_TYPE_LIBRARY))
    assert [i["asset"] for i in items] == \
        ["asset-m1", "asset-m2", "asset-m3"], items
    assert items[0]["tag"] == "mtag-m1" and items[0]["filename"] == "a.jpg"
    assert items[0]["asset_tag"] == "atag-m1"
    assert all(i["atype"] == "CPLAsset" for i in items)
    assert all(i["zone"] == {"zoneName": "PrimarySync"} for i in items)

    # 2) the library listing skips already-deleted assets
    wph = fake_wph([make_page([("m1", "x.jpg")], deleted_names={"m1"}),
                    FakeResp({"records": []})])
    assert list(enumerate_assets(wph, LIST_TYPE_LIBRARY)) == []

    # 3) the Recently Deleted listing keeps them
    wph = fake_wph([make_page([("m1", "x.jpg")], deleted_names={"m1"}),
                    FakeResp({"records": []})])
    rd_items = list(enumerate_assets(wph, LIST_TYPE_RECENTLY_DELETED,
                                     skip_deleted=False))
    assert [i["asset"] for i in rd_items] == ["asset-m1"]

    # 4) op shape identical to pyicloud's PhotoAsset.delete() body format,
    #    with isExpunged added in Recently Deleted mode
    item = {"asset": "A1", "atype": "CPLAsset", "asset_tag": "A",
            "tag": "M", "filename": "f"}
    want = {"operationType": "update", "record": {
        "recordName": "A1", "recordType": "CPLAsset",
        "recordChangeTag": "A", "fields": {"isDeleted": {"value": 1}}}}
    assert json.loads(json.dumps(make_op(item, False))) == want
    # a record with no asset-level tag falls back to the master tag
    bare = make_op({"asset": "A1", "atype": "CPLAsset", "tag": "M",
                    "filename": "f"}, False)
    assert bare["record"]["recordChangeTag"] == "M"
    rd = json.loads(json.dumps(make_op(item, True)))
    assert rd["record"]["fields"]["isExpunged"] == {"value": 1}

    # 5) error classification
    assert retryable(PyiCloudAPIResponseException("throttled", 509)) is True
    assert retryable(PyiCloudAPIResponseException(
        "ACCESS_DENIED: please wait a few minutes", "ACCESS_DENIED")) is True
    assert retryable(PyiCloudAPIResponseException(
        "ZONE_NOT_FOUND", "ZONE_NOT_FOUND")) is False
    assert auth_required(PyiCloudAPIResponseException("reason", 421)) is True
    assert auth_required(PyiCloud2SARequiredException("acct")) is True

    # 6) a failing batch decomposes all the way down to singles
    global delete_batch_checked
    calls, orig = [], delete_batch_checked

    def probe(_wph, ops_, _rd_mode, ctx_):
        calls.append(tuple(o["record"]["recordName"] for o in ops_))
        return bisect_delete(_wph, ops_, _rd_mode, ctx_)

    delete_batch_checked = probe
    ctx = {"failed": [], "target": {f"a{i}": f"f{i}" for i in range(4)}}
    ops4 = [make_op(dict(item, asset=f"a{i}"), False) for i in range(4)]
    assert bisect_delete(wph, ops4, False, ctx) is False
    delete_batch_checked = orig
    assert calls == [("a0", "a1"), ("a0",), ("a1",),
                     ("a2", "a3"), ("a2",), ("a3",)], calls
    assert [o["record"]["recordName"] for o in ctx["failed"]] == \
        ["a0", "a1", "a2", "a3"]

    # 7) the modify POST carries the chunk's zone, atomic flag, and tags
    posted = []

    class Capture:
        @staticmethod
        def post(url, data=None, headers=None, timeout=None):
            posted.append(json.loads(data))
            return FakeResp({"records": []})

    wph = fake_wph([])
    wph.session = Capture
    ctx2 = {"target": {},
            "zone_of": {f"a{i}": {"zoneName": "Z1"} for i in range(2)},
            "failed": []}
    ops2 = [make_op(dict(item, asset=f"a{i}", asset_tag=f"t{i}", tag=f"t{i}"),
                    False) for i in range(2)]
    assert delete_batch_checked(wph, ops2, False, ctx2) is True
    assert posted[0]["zoneID"] == {"zoneName": "Z1"}
    assert posted[0]["atomic"] is True
    assert [o["record"]["recordChangeTag"]
            for o in posted[0]["operations"]] == ["t0", "t1"]

    print("selftest OK - pairing/pagination, op shape, classification, "
          "bisect, batch body all verified")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", action="store_true",
                   help="actually delete (default: dry-run)")
    p.add_argument("--rd", action="store_true",
                   help="operate on the 'Recently Deleted' album "
                        "(experimental permanent purge)")
    p.add_argument("--limit", type=int, default=0,
                   help="cap deletions at N (live test, e.g. 3)")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH,
                   help=f"operations per POST (default {DEFAULT_BATCH})")
    p.add_argument("--from-manifest", action="store_true",
                   help="reuse the previous run's enumeration from "
                        "manifest.jsonl instead of re-querying Apple "
                        "(falls back to a fresh enumeration)")
    p.add_argument("--ask-credentials", action="store_true",
                   help="prompt for Apple ID + password even if secrets.txt "
                        "exists (Enter accepts the saved email)")
    p.add_argument("--selftest", action="store_true",
                   help="run offline logic tests and exit")
    args = p.parse_args()

    if args.selftest:
        sys.exit(selftest())

    batch_size = max(1, min(800, args.batch_size))
    list_type = LIST_TYPE_RECENTLY_DELETED if args.rd else LIST_TYPE_LIBRARY
    mode_name = "Recently Deleted (experimental purge)" if args.rd \
        else "photo library"
    skip_deleted = not args.rd

    print(__doc__.strip().splitlines()[0])
    email, password = resolve_credentials(args.ask_credentials)
    api = build_api(email, password)
    wph = WipePhotos(api)
    t0 = time.monotonic()
    items = None
    if args.from_manifest and MANIFEST.is_file():
        with open(MANIFEST, "r", encoding="utf-8") as fh:
            loaded = [json.loads(line) for line in fh if line.strip()]
        if len(loaded) >= 2:
            items = loaded
            age_s = max(0, int(time.time() - MANIFEST.stat().st_mtime))
            log(f"Reusing manifest.jsonl: {len(items)} items, "
                f"{age_s // 60} min old ({time.monotonic() - t0:.0f}s)")
        else:
            log("manifest.jsonl is short/empty - enumerating fresh instead")
    if items is None:
        log(f"Enumerating {mode_name} (~{PAGE_PAIRS}/page, trimmed keys)...")
        items = []
        tmp_manifest = MANIFEST.with_suffix(".jsonl.tmp")
        manifest = open(tmp_manifest, "w", encoding="utf-8")
        try:
            for item in enumerate_assets(wph, list_type, skip_deleted):
                items.append(item)
                if len(items) % 1000 == 0:
                    log(f"  enumerated {len(items)} so far...")
            for item in items:
                manifest.write(json.dumps(item, ensure_ascii=False) + "\n")
        finally:
            manifest.close()
        os.replace(tmp_manifest, MANIFEST)
        log(f"Enumeration complete: {len(items)} items "
            f"in {time.monotonic() - t0:.0f}s -> {MANIFEST.name}")

    sample = ", ".join(i["filename"] for i in items[:3]) or "-"
    log(f"sample filenames: {sample}")

    targeted = items
    if args.limit:
        targeted = items[:args.limit]
        log(f"--limit {args.limit}: deleting only the first "
            f"{len(targeted)} of {len(items)} enumerated items")
    est_req = -(-len(targeted) // batch_size)
    noun = "Recently Deleted items" if args.rd else "library items"
    if not args.go:
        if sys.stdin.isatty():
            log(f"that would take ~{est_req} batched requests "
                f"(~{est_req * 1.2 / 60:.0f}-min guess)")
            confirm = input(f"Delete {len(targeted)} {noun} now? [y/N]: ")
            if confirm.strip().lower() not in ("y", "yes"):
                log("declined - nothing deleted; rerun with --go to "
                    "delete without asking")
                sys.exit(0)
            log("confirmed - proceeding")
        else:
            log(f"DRY RUN - nothing deleted. To delete {len(targeted)} "
                f"items it would take ~{est_req} batched requests "
                f"(~{est_req * 1.2 / 60:.0f}-min guess). Review the "
                f"sample above, then run:  python3 icloud_wipe.py --go")
            sys.exit(0)
    log(f"*** DELETING {len(targeted)} items from {mode_name} "
        f"in 10 seconds (Ctrl-C to abort) ***")
    time.sleep(10)
    ok = delete_all(wph, targeted, api, args.rd, batch_size, mode_name)
    if os.environ.get("WIPE_SKIP_VERIFY") == "1":
        log("WIPE_SKIP_VERIFY=1 - verification re-enumeration skipped per "
            "user instruction; the purge pass itself re-lists Recently "
            "Deleted, which confirms what the library pass landed")
        sys.exit(0 if ok else 10)
    log("Verifying: re-enumerating the listing...")
    remaining = count_listing(wph, list_type, skip_deleted)
    expected_remaining = len(items) - len(targeted)
    if args.limit:
        log(f"limit-test finished: {expected_remaining} were supposed to "
            f"remain; the listing now shows {remaining}; rerun the same "
            "command to continue")
        sys.exit(10 if not ok else 0)
    if remaining != expected_remaining:
        log(f"Anomaly: expected ~{expected_remaining} items to remain, the "
            f"listing shows {remaining} - rerun the same command to mop up")
        sys.exit(10)
    log("Verification: listing is empty - everything deleted.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted - state preserved on Apple's side; just rerun the "
            "same command to resume.")
        sys.exit(130)
