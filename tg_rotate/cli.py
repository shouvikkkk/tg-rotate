"""tg-rotate CLI: scan | rotate | watch | status.

Full tokens are never printed by any subcommand -- only fingerprints
(``a1b2c3d4…Wxyz``). Pass tokens via environment variables
(TG_ROTATE_OLD_TOKEN / TG_ROTATE_NEW_TOKEN) to keep them out of shell history.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__, discover, probe, state as statemod, verify
from .fingerprint import TOKEN_RE, fingerprint, label
from .rotate_engine import RotateConfig, RotateError, rotate


def _token(value: str | None, env_name: str, what: str) -> str:
    tok = (value or os.environ.get(env_name) or "").strip()
    if not tok:
        raise RotateError(
            f"missing {what}: pass --{what.replace('_', '-')} or set {env_name}"
        )
    return tok


def _search_dirs(args) -> list[str]:
    dirs = args.search_dirs or ["."]
    out: list[str] = []
    for d in dirs:
        if os.path.isdir(d):
            out.append(os.path.abspath(d))
        else:
            print(f"warning: search dir not found, skipping: {d}", file=sys.stderr)
    return out or [os.path.abspath(".")]


def _print_hits(hits: list[discover.Hit], as_json: bool) -> None:
    if as_json:
        print(json.dumps([h.public_dict() for h in hits], indent=2))
        return
    if not hits:
        print("no token copies found.")
        return
    by_fp: dict[str, list[discover.Hit]] = {}
    for h in hits:
        by_fp.setdefault(h.fingerprint, []).append(h)
    for fp, hs in by_fp.items():
        print(f"\ntoken {label(fp, hs[0].raw if hs[0].raw else None)} -- {len(hs)} copie(s):")
        for h in hs:
            line = f"  [{h.source}] {h.location} ({h.detail})"
            if h.preview:
                line += f"\n      {h.preview}"
            print(line)


# ---------------------------------------------------------------- scan

def cmd_scan(args) -> int:
    if args.find_any:
        wanted = None
        if not args.json:
            print("scanning for every token-shaped string ...")
    else:
        tok = _token(args.old_token, "TG_ROTATE_OLD_TOKEN", "old_token")
        wanted = {fingerprint(tok)}
        if not args.json:
            print(f"scanning for token {label(next(iter(wanted)), tok)} ...")
    dirs = _search_dirs(args)
    hits = discover.scan_configs(dirs, wanted)
    if not args.skip_env:
        hits += discover.scan_shell_env(wanted)
    if not args.skip_proc:
        hits += discover.scan_processes(wanted)
    _print_hits(hits, args.json)
    stale = [h for h in hits if h.source in ("config", "proc-cmdline", "proc-environ")]
    if not args.json:
        print(f"\n{len(hits)} total hit(s) across {len(dirs)} searched dir(s).")
        if wanted and stale:
            print("staleness: these copies still hold the OLD token -- rotate to replace them.")
    return 0


# ---------------------------------------------------------------- rotate

def _confirm_revocation(args) -> None:
    if args.i_revoked_in_botfather:
        return
    if not sys.stdin.isatty():
        raise RotateError(
            "refusing to rotate: pass --i-revoked-in-botfather to confirm you revoked "
            "the old token in BotFather (non-interactive session, cannot prompt)"
        )
    print(
        "\nTelegram has NO API to revoke a token -- this step is manual and tg-rotate\n"
        "cannot do it for you. In BotFather: /mybots -> select the bot -> API Token\n"
        "-> 'Revoke current token', then paste the NEW token below.\n"
    )
    ans = input("Type REVOKED to confirm the old token is revoked in BotFather: ").strip()
    if ans != "REVOKED":
        raise RotateError("confirmation not given -- rotation cancelled, nothing touched")


def cmd_rotate(args) -> int:
    old_token = _token(args.old_token, "TG_ROTATE_OLD_TOKEN", "old_token")
    new_token = _token(args.new_token, "TG_ROTATE_NEW_TOKEN", "new_token")
    if not args.bot_username:
        raise RotateError("missing --bot-username (expected bot username, e.g. mybot)")
    _confirm_revocation(args)

    cfg = RotateConfig(
        old_token=old_token,
        new_token=new_token,
        bot_username=args.bot_username,
        search_dirs=_search_dirs(args),
        restart_cmd=args.restart_cmd,
        systemd_unit=args.systemd_unit,
        reload_pid=args.reload_pid,
        api_base=args.api_base or probe.DEFAULT_API_BASE,
        timeout=args.timeout,
    )
    print(f"pre-flight: probing tokens against {cfg.api_base} ...")
    result = rotate(cfg)

    print("\n-- service reload --")
    for note in result.service_notes:
        print(f"  {note}")
    print("\n-- verification --")
    if result.report:
        for s in result.report.steps:
            mark = "✓" if s.passed else "✗"
            print(f"  {mark} {s.name}: {s.detail}")
    if result.ok:
        print(f"\nSUCCESS: {result.message}")
        print(f"journal: {result.journal_path}")
        return 0
    print(f"\nFAILED: {result.message}")
    print(f"journal: {result.journal_path}")
    return 1


# ---------------------------------------------------------------- watch

def cmd_watch(args) -> int:
    data = statemod.load()
    if not data["active_fp"]:
        print("no declared active token -- run `tg-rotate rotate` once first.", file=sys.stderr)
        return 2
    active_fp: str = data["active_fp"]
    retired: set[str] = set(data["retired_fps"])
    known = {c["path"]: c for c in data["known_copies"]}
    alert_token = args.alert_token or os.environ.get("TG_ROTATE_TOKEN")

    def check_once() -> list[str]:
        alerts: list[str] = []
        dirs = _search_dirs(args)
        for h in discover.scan_configs(dirs, None):
            if h.fingerprint in retired:
                alerts.append(
                    f"RETIRED token {label(h.fingerprint)} still present: "
                    f"{h.location} ({h.detail}) [{h.source}]"
                )
        for h in discover.scan_processes(None):
            if h.fingerprint in retired:
                alerts.append(
                    f"RETIRED token {label(h.fingerprint)} held by running process: "
                    f"{h.location} [{h.source}]"
                )
        # active token must still be where we left it
        for path in known:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError:
                alerts.append(f"known copy unreadable (deleted?): {path}")
                continue
            fps = {fingerprint(t) for t in TOKEN_RE.findall(content)}
            if active_fp not in fps:
                alerts.append(
                    f"ACTIVE token {label(active_fp)} missing from known copy {path} "
                    "-- changed externally?"
                )
        # brand-new unknown copies of the active token (info, not alert)
        return alerts

    def run_round() -> int:
        alerts = check_once()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        if alerts:
            msg = f"[{ts}] tg-rotate watch: DRIFT DETECTED\n" + "\n".join(f"  ! {a}" for a in alerts)
            print(msg, flush=True)
            if args.alert_chat_id and alert_token:
                probe.send_message(
                    alert_token, args.alert_chat_id,
                    "🚨 tg-rotate drift:\n" + "\n".join(alerts)[:3500],
                    base_url=args.api_base or probe.DEFAULT_API_BASE,
                )
            return 1
        print(f"[{ts}] ok: active {label(active_fp)} consistent, no retired copies found", flush=True)
        return 0

    if args.once:
        return run_round()
    interval = max(10, args.interval)
    print(f"watching every {interval}s (Ctrl-C to stop) -- active token {label(active_fp)}")
    try:
        while True:
            run_round()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nwatch stopped.")
        return 0


# ---------------------------------------------------------------- status

def cmd_status(args) -> int:
    data = statemod.load()
    if not data["active_fp"]:
        print("no state yet -- run `tg-rotate rotate` once to declare an active token.")
        return 0
    print(f"active token : {data['active_hint'] or label(data['active_fp'])}")
    print(f"bot          : @{data['bot_username']}")
    print(f"retired      : {len(data['retired_fps'])} token(s)")
    print(f"known copies : {len(data['known_copies'])}")
    for c in data["known_copies"]:
        print(f"  - {c['path']} ({c.get('detail', '')})")
    if data["verifications"]:
        last = data["verifications"][-1]
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last["ts"]))
        print(f"last verify  : {'PASSED' if last['passed'] else 'FAILED'} at {ts}")
        if args.verbose:
            for s in last["steps"]:
                print(f"  {'✓' if s['passed'] else '✗'} {s['name']}: {s['detail']}")
    if data["last_rotate"]:
        lr = data["last_rotate"]
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lr["ts"]))
        print(f"last rotate  : {'ok' if lr['ok'] else 'FAILED (rolled back)'} at {ts}")
    return 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tg-rotate",
        description=(
            "Telegram bot token rotation supervisor: find every copy of a bot token, "
            "replace them atomically, and VERIFY the running service uses the new token."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="discover every copy of a bot token")
    s.add_argument("--old-token", default=None, help="token to hunt (or TG_ROTATE_OLD_TOKEN)")
    s.add_argument("--find-any", action="store_true", help="report every token-shaped string found")
    s.add_argument("--search-dirs", nargs="+", default=None, help="dirs to scan (default: .)")
    s.add_argument("--skip-env", action="store_true")
    s.add_argument("--skip-proc", action="store_true")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rotate", help="orchestrated, verified token rotation")
    r.add_argument("--old-token", default=None, help="revoked token (or TG_ROTATE_OLD_TOKEN)")
    r.add_argument("--new-token", default=None, help="new token from BotFather (or TG_ROTATE_NEW_TOKEN)")
    r.add_argument("--bot-username", default=None, help="expected bot username, e.g. mybot")
    r.add_argument("--search-dirs", nargs="+", default=None)
    r.add_argument("--restart-cmd", default=None, help="shell command to restart the bot service")
    r.add_argument("--systemd-unit", default=None, help="user systemd unit to restart")
    r.add_argument("--reload-pid", type=int, default=None, help="pid to SIGHUP after replace")
    r.add_argument("--i-revoked-in-botfather", action="store_true",
                   help="confirm the old token was revoked in BotFather (manual step)")
    r.add_argument("--api-base", default=None, help="override Telegram API base (testing)")
    r.add_argument("--timeout", type=float, default=10.0)
    r.set_defaults(func=cmd_rotate)

    w = sub.add_parser("watch", help="drift watchdog for the declared active token")
    w.add_argument("--search-dirs", nargs="+", default=None)
    w.add_argument("--interval", type=int, default=300, help="seconds between checks")
    w.add_argument("--once", action="store_true", help="single check, then exit")
    w.add_argument("--alert-chat-id", default=None, help="Telegram chat id for drift alerts")
    w.add_argument("--alert-token", default=None, help="token used to send alerts (or TG_ROTATE_TOKEN)")
    w.add_argument("--api-base", default=None)
    w.set_defaults(func=cmd_watch)

    st = sub.add_parser("status", help="show declared token, copies, last verification")
    st.add_argument("-v", "--verbose", action="store_true")
    st.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RotateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
