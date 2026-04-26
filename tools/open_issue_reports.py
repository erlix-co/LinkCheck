#!/usr/bin/env python3
"""Sync LinkCheck issue reports from the server, generate HTML, and open it."""

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
DEFAULT_LOCAL_JSONL = ROOT / "backend" / "data" / "issue_reports.jsonl"
DEFAULT_LOCAL_HTML = ROOT / "backend" / "data" / "issue_reports.html"
DEFAULT_REMOTE_PATH = "/root/erlix/linkcheck/backend/data/issue_reports.jsonl"
DEFAULT_HOST = "164.92.194.213"
DEFAULT_USER = "israel_zeev"
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


def sync_from_server(*, host: str, user: str, remote_path: str, local_path: Path) -> tuple[int, int]:
    paramiko = ensure_paramiko()
    password = os.getenv("LINKCHECK_SERVER_PASSWORD") or getpass.getpass(
        f"Password for {user}@{host}: "
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        quoted_remote = shlex.quote(remote_path)
        command = (
            "sudo -S -p '' python3 -c "
            + shlex.quote(
                "import base64, pathlib; "
                f"print(base64.b64encode(pathlib.Path({quoted_remote!r}).read_bytes()).decode())"
            )
        )
        stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=30)
        stdin.write(password + "\n")
        stdin.flush()
        output = stdout.read().decode("utf-8", "replace")
        error = stderr.read().decode("utf-8", "replace")
        exit_code = stdout.channel.recv_exit_status()
    finally:
        client.close()

    if exit_code != 0:
        raise RuntimeError(f"Failed reading remote reports file: {error.strip() or output.strip()}")

    encoded = "".join(
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.strip() != password
    )
    data = base64.b64decode(encoded.encode("ascii")) if encoded else b""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(data)
    return len(data), len(data.splitlines()) if data else 0


def parse_timestamp(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value, ""
    return dt.strftime("%Y-%m-%d %H:%M:%S"), dt.strftime("%Y-%m-%d")


def read_reports(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    reports: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        raw = line.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            reports.append(
                {
                    "ts": "",
                    "language": "",
                    "client_ip": "",
                    "user_agent": "",
                    "checked_context_text": "",
                    "description": f"Invalid JSON on line {line_no}: {exc}",
                    "_parse_error": True,
                }
            )
            continue
        if isinstance(item, dict):
            reports.append(item)
    reports.sort(key=lambda item: str(item.get("ts") or ""), reverse=True)
    return reports


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def nl2br(value: Any) -> str:
    return esc(value).replace("\n", "<br>")


def render_report(report: dict[str, Any], index: int) -> str:
    ts_display, date_value = parse_timestamp(str(report.get("ts") or ""))
    description = report.get("description") or ""
    checked_context = report.get("checked_context_text") or ""
    if not checked_context:
        parts = []
        if report.get("url_field"):
            parts.append(f"[URL checked]\n{report.get('url_field')}")
        if report.get("message_field"):
            parts.append(f"[Message checked]\n{report.get('message_field')}")
        checked_context = "\n\n".join(parts)

    search_blob = " ".join(
        str(report.get(key) or "")
        for key in (
            "ts",
            "language",
            "client_ip",
            "user_agent",
            "checked_url",
            "checked_message",
            "checked_context_text",
            "description",
        )
    )
    parse_error_class = " report-card--error" if report.get("_parse_error") else ""
    return f"""
      <article class="report-card{parse_error_class}" data-search="{esc(search_blob).lower()}" data-date="{esc(date_value)}">
        <header class="report-card__header">
          <div>
            <div class="report-card__eyebrow">#{index}</div>
            <h2>{esc(description) or "No description"}</h2>
          </div>
          <div class="report-card__time">{esc(ts_display)}</div>
        </header>

        <dl class="meta-grid">
          <div><dt>Language</dt><dd>{esc(report.get("language")) or "-"}</dd></div>
          <div><dt>Client IP</dt><dd>{esc(report.get("client_ip")) or "-"}</dd></div>
          <div class="meta-grid__wide"><dt>User Agent</dt><dd>{esc(report.get("user_agent")) or "-"}</dd></div>
        </dl>

        <section class="content-block">
          <h3>Checked Context</h3>
          <pre>{nl2br(checked_context) or "No checked URL/message was included."}</pre>
        </section>
      </article>
    """


def render_html(reports: list[dict[str, Any]], source_path: Path) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards = "\n".join(render_report(report, idx) for idx, report in enumerate(reports, start=1))
    return f"""<!doctype html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LinkCheck Issue Reports</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #071023;
      --panel: #101f3d;
      --panel-2: #0c1933;
      --border: rgba(96, 165, 250, 0.22);
      --text: #edf4ff;
      --muted: #9fb0ce;
      --accent: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Arial, sans-serif;
      background: radial-gradient(circle at top, rgba(45, 140, 240, 0.18), transparent 38rem), var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    main {{ width: min(1120px, calc(100% - 32px)); margin: 32px auto 56px; }}
    .hero {{ display: flex; gap: 16px; justify-content: space-between; align-items: end; margin-bottom: 18px; }}
    h1 {{ margin: 0 0 6px; font-size: clamp(1.7rem, 4vw, 2.5rem); }}
    .subtitle {{ margin: 0; color: var(--muted); }}
    .stats {{
      min-width: 160px; padding: 14px 18px; border: 1px solid var(--border);
      border-radius: 18px; background: rgba(16, 31, 61, 0.72); text-align: center;
    }}
    .stats strong {{ display: block; font-size: 2rem; color: var(--accent); line-height: 1; }}
    .toolbar {{ display: grid; grid-template-columns: 1fr 180px; gap: 12px; margin: 22px 0; direction: ltr; }}
    input {{
      width: 100%; padding: 13px 15px; color: var(--text); background: var(--panel-2);
      border: 1px solid var(--border); border-radius: 14px; outline: none;
    }}
    input:focus {{ border-color: rgba(56, 189, 248, 0.75); }}
    .report-list {{ display: grid; gap: 14px; }}
    .report-card {{
      border: 1px solid var(--border); border-radius: 22px;
      background: linear-gradient(180deg, rgba(16, 31, 61, 0.92), rgba(12, 25, 51, 0.92));
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.22); overflow: hidden;
    }}
    .report-card--error {{ border-color: rgba(248, 113, 113, 0.55); }}
    .report-card__header {{ display: flex; justify-content: space-between; gap: 18px; padding: 18px 20px; border-bottom: 1px solid var(--border); }}
    .report-card__eyebrow {{ color: var(--accent); font-size: 0.85rem; direction: ltr; text-align: left; }}
    h2 {{ margin: 3px 0 0; font-size: 1.15rem; }}
    .report-card__time {{ color: var(--muted); white-space: nowrap; direction: ltr; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; padding: 16px 20px 0; }}
    .meta-grid div, .content-block {{
      background: rgba(7, 16, 35, 0.45); border: 1px solid rgba(96, 165, 250, 0.12);
      border-radius: 14px; padding: 12px;
    }}
    .meta-grid__wide {{ grid-column: 1 / -1; }}
    dt, h3 {{ color: var(--muted); font-size: 0.82rem; margin: 0 0 6px; }}
    dd {{ margin: 0; direction: ltr; text-align: left; word-break: break-word; }}
    .content-block {{ margin: 14px 20px 20px; }}
    pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; font: inherit; direction: auto; }}
    .empty {{ padding: 28px; border: 1px dashed var(--border); border-radius: 18px; color: var(--muted); text-align: center; }}
    .hidden {{ display: none; }}
    @media (max-width: 720px) {{
      .hero {{ align-items: stretch; flex-direction: column; }}
      .toolbar {{ grid-template-columns: 1fr; }}
      .report-card__header {{ flex-direction: column; }}
      .meta-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div>
        <h1>LinkCheck Issue Reports</h1>
        <p class="subtitle">Generated at {esc(generated_at)} from <code>{esc(source_path)}</code></p>
      </div>
      <div class="stats"><strong id="visibleCount">{len(reports)}</strong><span>visible reports</span></div>
    </section>

    <section class="toolbar" aria-label="Report filters">
      <input id="searchInput" type="search" placeholder="Search reports, IP, URL, message, user agent..." />
      <input id="dateInput" type="date" />
    </section>

    <section class="report-list" id="reportList">
      {cards if cards else '<div class="empty">No reports found.</div>'}
    </section>
  </main>

  <script>
    const searchInput = document.getElementById('searchInput');
    const dateInput = document.getElementById('dateInput');
    const visibleCount = document.getElementById('visibleCount');
    const cards = Array.from(document.querySelectorAll('.report-card'));
    function applyFilters() {{
      const query = (searchInput.value || '').trim().toLowerCase();
      const date = dateInput.value || '';
      let visible = 0;
      for (const card of cards) {{
        const show = (!query || card.dataset.search.includes(query)) && (!date || card.dataset.date === date);
        card.classList.toggle('hidden', !show);
        if (show) visible += 1;
      }}
      visibleCount.textContent = visible;
    }}
    searchInput.addEventListener('input', applyFilters);
    dateInput.addEventListener('input', applyFilters);
  </script>
</body>
</html>
"""


def generate_html(*, jsonl_path: Path, html_path: Path) -> int:
    reports = read_reports(jsonl_path)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(render_html(reports, jsonl_path), encoding="utf-8")
    return len(reports)


def open_in_chrome(path: Path) -> bool:
    uri = path.resolve().as_uri()
    for candidate in CHROME_CANDIDATES:
        if candidate.is_file():
            subprocess.Popen([str(candidate), uri])
            print(f"Opened report dashboard in Chrome: {candidate}")
            return True
    return webbrowser.open(uri)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_PATH)
    parser.add_argument("--jsonl", type=Path, default=DEFAULT_LOCAL_JSONL)
    parser.add_argument("--html", type=Path, default=DEFAULT_LOCAL_HTML)
    parser.add_argument("--no-open", action="store_true", help="Generate HTML but do not open it.")
    args = parser.parse_args()

    bytes_count, line_count = sync_from_server(
        host=args.host,
        user=args.user,
        remote_path=args.remote_path,
        local_path=args.jsonl,
    )
    report_count = generate_html(jsonl_path=args.jsonl, html_path=args.html)

    print(f"Synced {bytes_count} bytes / {line_count} lines to {args.jsonl}")
    print(f"Generated {args.html} ({report_count} reports)")
    if not args.no_open:
        if open_in_chrome(args.html):
            return
        print("Could not open a browser automatically. Open this file manually:")
        print(args.html)


if __name__ == "__main__":
    main()
