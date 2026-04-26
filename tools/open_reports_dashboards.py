#!/usr/bin/env python3
"""Sync LinkCheck report files, generate two HTML dashboards, and open Chrome tabs."""

from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import os
import shlex
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "backend" / "data"
DEFAULT_HOST = "164.92.194.213"
DEFAULT_USER = "israel_zeev"
REMOTE_DIR = "/root/erlix/linkcheck/backend/data"
FILES = {
    "issue_reports": {
        "remote": f"{REMOTE_DIR}/issue_reports.jsonl",
        "jsonl": DATA_DIR / "issue_reports.jsonl",
        "html": DATA_DIR / "issue_reports.html",
        "title": "LinkCheck Issue Reports",
        "subtitle": "דיווחי תקלות שנשלחו מהטופס באתר",
    },
    "scan_events": {
        "remote": f"{REMOTE_DIR}/scan_events.jsonl",
        "jsonl": DATA_DIR / "scan_events.jsonl",
        "html": DATA_DIR / "scan_events.html",
        "title": "LinkCheck Usage Report",
        "subtitle": "שימושים ובדיקות שבוצעו בכלי (ללא טקסט הודעה מלא)",
    },
}
CHROME_CANDIDATES = (
    Path(os.environ.get("ProgramFiles", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    Path(os.environ.get("ProgramFiles(x86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
    Path(os.environ.get("LocalAppData", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
)


def ensure_paramiko():
    try:
        import paramiko  # type: ignore
    except ImportError:
        print("Installing required Python package: paramiko")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])
        import paramiko  # type: ignore
    return paramiko


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def nl2br(value: Any) -> str:
    return esc(value).replace("\n", "<br>")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        raw = line.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            item = {"ts": "", "description": f"Invalid JSON on line {line_no}: {exc}", "_parse_error": True}
        if isinstance(item, dict):
            rows.append(item)
    rows.sort(key=lambda item: str(item.get("ts") or ""), reverse=True)
    return rows


def parse_timestamp(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value, ""
    return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.strftime("%Y-%m-%d")


def sync_file(client: Any, *, password: str, remote_path: str, local_path: Path) -> tuple[int, int]:
    quoted_remote = shlex.quote(remote_path)
    command = (
        "sudo -S -p '' python3 -c "
        + shlex.quote(
            "import base64, pathlib, sys; "
            f"p=pathlib.Path({quoted_remote!r}); "
            "sys.exit(0) if not p.exists() else print(base64.b64encode(p.read_bytes()).decode())"
        )
    )
    stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=30)
    stdin.write(password + "\n")
    stdin.flush()
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    exit_code = stdout.channel.recv_exit_status()
    if exit_code != 0:
        raise RuntimeError(f"Failed reading {remote_path}: {error.strip() or output.strip()}")

    encoded = "".join(line.strip() for line in output.splitlines() if line.strip() and line.strip() != password)
    data = base64.b64decode(encoded.encode("ascii")) if encoded else b""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)
    return len(data), len(data.splitlines()) if data else 0


def render_meta_grid(items: list[tuple[str, Any]], wide_last: bool = False) -> str:
    rendered = []
    for index, (label, value) in enumerate(items):
        cls = ' class="meta-grid__wide"' if wide_last and index == len(items) - 1 else ""
        rendered.append(f"<div{cls}><dt>{esc(label)}</dt><dd>{esc(value) or '-'}</dd></div>")
    return "\n".join(rendered)


def host_text(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    host = value.get("host") or ""
    registrable = value.get("registrable_domain") or ""
    if host and registrable and host != registrable:
        return f"{host} ({registrable})"
    return host or registrable


def render_issue_card(row: dict[str, Any], index: int) -> str:
    ts_display, date_value = parse_timestamp(str(row.get("ts") or ""))
    description = row.get("description") or "No description"
    context = row.get("checked_context_text") or ""
    if not context:
        parts = []
        if row.get("url_field"):
            parts.append(f"[URL checked]\n{row.get('url_field')}")
        if row.get("message_field"):
            parts.append(f"[Message checked]\n{row.get('message_field')}")
        context = "\n\n".join(parts)
    search = " ".join(str(row.get(k) or "") for k in ("ts", "language", "client_ip", "user_agent", "description", "checked_context_text"))
    return f"""
      <article class="report-card" data-search="{esc(search).lower()}" data-date="{esc(date_value)}">
        <header class="report-card__header">
          <div><div class="report-card__eyebrow">#{index}</div><h2>{esc(description)}</h2></div>
          <div class="report-card__time">{esc(ts_display)}</div>
        </header>
        <dl class="meta-grid">
          {render_meta_grid([("Language", row.get("language")), ("Client IP", row.get("client_ip")), ("User Agent", row.get("user_agent"))], wide_last=True)}
        </dl>
        <section class="content-block"><h3>Checked Context</h3><pre>{nl2br(context) or "No checked URL/message was included."}</pre></section>
      </article>
    """


def render_scan_card(row: dict[str, Any], index: int) -> str:
    ts_display, date_value = parse_timestamp(str(row.get("ts") or ""))
    risk = row.get("risk_level") or "Unknown"
    hosts = row.get("message_url_hosts") if isinstance(row.get("message_url_hosts"), list) else []
    hosts_text = ", ".join(filter(None, (host_text(item) for item in hosts)))
    search = " ".join(
        str(part or "")
        for part in (
            row.get("ts"),
            row.get("language"),
            row.get("client_ip"),
            row.get("user_agent"),
            risk,
            hosts_text,
            ",".join(row.get("reason_keys") or []),
        )
    )
    return f"""
      <article class="report-card" data-search="{esc(search).lower()}" data-date="{esc(date_value)}">
        <header class="report-card__header">
          <div><div class="report-card__eyebrow">#{index}</div><h2>Risk: {esc(risk)}</h2></div>
          <div class="report-card__time">{esc(ts_display)}</div>
        </header>
        <dl class="meta-grid">
          {render_meta_grid([
              ("Source", row.get("source")),
              ("Language", row.get("language")),
              ("Client IP", row.get("client_ip")),
              ("Message length", row.get("message_length")),
              ("URL count", row.get("message_url_count")),
              ("Analyzed links", row.get("message_links_analyzed_count")),
              ("Submitted host", host_text(row.get("submitted_url"))),
              ("Analyzed host", host_text(row.get("analyzed_url"))),
              ("Selected host", host_text(row.get("selected_message_url"))),
              ("URL hosts in message", hosts_text),
              ("Reason keys", ", ".join(row.get("reason_keys") or [])),
              ("User Agent", row.get("user_agent")),
          ], wide_last=True)}
        </dl>
      </article>
    """


def render_html(*, title: str, subtitle: str, rows: list[dict[str, Any]], source_path: Path, kind: str) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    renderer = render_scan_card if kind == "scan_events" else render_issue_card
    cards = "\n".join(renderer(row, idx) for idx, row in enumerate(rows, start=1))
    return f"""<!doctype html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{esc(title)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#071023; --panel:#101f3d; --panel-2:#0c1933; --border:rgba(96,165,250,.22); --text:#edf4ff; --muted:#9fb0ce; --accent:#38bdf8; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:"Segoe UI",Tahoma,Arial,sans-serif; background:radial-gradient(circle at top, rgba(45,140,240,.18), transparent 38rem), var(--bg); color:var(--text); line-height:1.55; }}
    main {{ width:min(1120px, calc(100% - 32px)); margin:32px auto 56px; }}
    .hero {{ display:flex; gap:16px; justify-content:space-between; align-items:end; margin-bottom:18px; }}
    h1 {{ margin:0 0 6px; font-size:clamp(1.7rem,4vw,2.5rem); }}
    .subtitle {{ margin:0; color:var(--muted); }}
    .stats {{ min-width:160px; padding:14px 18px; border:1px solid var(--border); border-radius:18px; background:rgba(16,31,61,.72); text-align:center; }}
    .stats strong {{ display:block; font-size:2rem; color:var(--accent); line-height:1; }}
    .toolbar {{ display:grid; grid-template-columns:1fr 180px; gap:12px; margin:22px 0; direction:ltr; }}
    input {{ width:100%; padding:13px 15px; color:var(--text); background:var(--panel-2); border:1px solid var(--border); border-radius:14px; outline:none; }}
    input:focus {{ border-color:rgba(56,189,248,.75); }}
    .report-list {{ display:grid; gap:14px; }}
    .report-card {{ border:1px solid var(--border); border-radius:22px; background:linear-gradient(180deg, rgba(16,31,61,.92), rgba(12,25,51,.92)); box-shadow:0 16px 50px rgba(0,0,0,.22); overflow:hidden; }}
    .report-card__header {{ display:flex; justify-content:space-between; gap:18px; padding:18px 20px; border-bottom:1px solid var(--border); }}
    .report-card__eyebrow {{ color:var(--accent); font-size:.85rem; direction:ltr; text-align:left; }}
    h2 {{ margin:3px 0 0; font-size:1.15rem; }}
    .report-card__time {{ color:var(--muted); white-space:nowrap; direction:ltr; }}
    .meta-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; padding:16px 20px 20px; }}
    .meta-grid div, .content-block {{ background:rgba(7,16,35,.45); border:1px solid rgba(96,165,250,.12); border-radius:14px; padding:12px; }}
    .meta-grid__wide {{ grid-column:1 / -1; }}
    dt, h3 {{ color:var(--muted); font-size:.82rem; margin:0 0 6px; }}
    dd {{ margin:0; direction:ltr; text-align:left; word-break:break-word; }}
    .content-block {{ margin:14px 20px 20px; }}
    pre {{ margin:0; white-space:pre-wrap; word-break:break-word; font:inherit; direction:auto; }}
    .empty {{ padding:28px; border:1px dashed var(--border); border-radius:18px; color:var(--muted); text-align:center; }}
    .hidden {{ display:none; }}
    @media (max-width:720px) {{ .hero {{ align-items:stretch; flex-direction:column; }} .toolbar,.meta-grid {{ grid-template-columns:1fr; }} .report-card__header {{ flex-direction:column; }} }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div><h1>{esc(title)}</h1><p class="subtitle">{esc(subtitle)}<br>Generated at {esc(generated_at)} from <code>{esc(source_path)}</code></p></div>
      <div class="stats"><strong id="visibleCount">{len(rows)}</strong><span>visible records</span></div>
    </section>
    <section class="toolbar"><input id="searchInput" type="search" placeholder="Search..." /><input id="dateInput" type="date" /></section>
    <section class="report-list">{cards if cards else '<div class="empty">No records found.</div>'}</section>
  </main>
  <script>
    const searchInput=document.getElementById('searchInput'), dateInput=document.getElementById('dateInput'), visibleCount=document.getElementById('visibleCount'), cards=Array.from(document.querySelectorAll('.report-card'));
    function applyFilters() {{ const q=(searchInput.value||'').trim().toLowerCase(), d=dateInput.value||''; let n=0; for (const c of cards) {{ const show=(!q||c.dataset.search.includes(q))&&(!d||c.dataset.date===d); c.classList.toggle('hidden',!show); if(show)n++; }} visibleCount.textContent=n; }}
    searchInput.addEventListener('input',applyFilters); dateInput.addEventListener('input',applyFilters);
  </script>
</body>
</html>
"""


def open_in_chrome(paths: list[Path]) -> None:
    uris = [path.resolve().as_uri() for path in paths]
    for candidate in CHROME_CANDIDATES:
        if candidate.is_file():
            subprocess.Popen([str(candidate), *uris])
            print(f"Opened dashboards in Chrome: {candidate}")
            return
    for uri in uris:
        webbrowser.open(uri)
    print("Chrome was not found; opened dashboards in the default browser.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()

    paramiko = ensure_paramiko()
    password = os.getenv("LINKCHECK_SERVER_PASSWORD") or getpass.getpass(f"Password for {args.user}@{args.host}: ")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=args.host, username=args.user, password=password, timeout=15, look_for_keys=False, allow_agent=False)
    try:
        for name, cfg in FILES.items():
            bytes_count, line_count = sync_file(client, password=password, remote_path=str(cfg["remote"]), local_path=cfg["jsonl"])
            rows = read_jsonl(cfg["jsonl"])
            cfg["html"].write_text(
                render_html(title=str(cfg["title"]), subtitle=str(cfg["subtitle"]), rows=rows, source_path=cfg["jsonl"], kind=name),
                encoding="utf-8",
            )
            print(f"{name}: synced {bytes_count} bytes / {line_count} lines, generated {cfg['html']}")
    finally:
        client.close()

    if not args.no_open:
        open_in_chrome([FILES["scan_events"]["html"], FILES["issue_reports"]["html"]])


if __name__ == "__main__":
    main()
