#!/usr/bin/env python3
"""Render every Mermaid fenced block in the research and Decaid documents.

The generated SVGs are validation artifacts and should remain outside Git.
This wrapper keeps the exact Mermaid CLI invocation reproducible without
requiring authors to split Markdown files by hand.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path


BLOCK = re.compile(
    r"(?P<fence>`{3}|~{3})mermaid\s*\n(.*?)\n(?P=fence)",
    re.DOTALL | re.IGNORECASE,
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/private/tmp/mahlkoenig-mermaid"),
        help="directory for generated SVGs (kept outside Git by default)",
    )
    parser.add_argument(
        "--chrome-path",
        type=Path,
        help="Chrome/Chromium executable for Puppeteer; auto-detected when omitted",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="maximum seconds allowed for one Mermaid block (default: 20)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="number of Mermaid CLI processes to run concurrently (default: 4)",
    )
    parser.add_argument(
        "--source",
        action="append",
        type=Path,
        help="limit validation to this Markdown path (repeatable; relative to repo)",
    )
    args = parser.parse_args()
    markdown_roots = [root / "docs", root / "decaid" / "docs"]
    markdown_files = sorted(
        path
        for directory in markdown_roots
        if directory.exists()
        for path in directory.rglob("*.md")
    )
    if args.source:
        selected = {(root / source).resolve() for source in args.source}
        markdown_files = [path for path in markdown_files if path.resolve() in selected]
    blocks = [
        (path, index, match.group(2).strip())
        for path in markdown_files
        for index, match in enumerate(BLOCK.finditer(path.read_text()))
    ]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    puppeteer_cache = Path.home() / ".cache" / "puppeteer"
    cached_headless_chrome = sorted(
        puppeteer_cache.glob(
            "chrome-headless-shell/*/chrome-headless-shell-*/chrome-headless-shell"
        ),
        reverse=True,
    )
    chrome_candidates = [
        args.chrome_path,
        Path(os.environ["PUPPETEER_EXECUTABLE_PATH"])
        if os.environ.get("PUPPETEER_EXECUTABLE_PATH")
        else None,
        *cached_headless_chrome,
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        Path(shutil.which("google-chrome") or "/nonexistent/google-chrome"),
        Path(shutil.which("chromium") or "/nonexistent/chromium"),
    ]
    chrome_path = next(
        (candidate for candidate in chrome_candidates if candidate and candidate.is_file()),
        None,
    )
    with tempfile.TemporaryDirectory(prefix="mahlkoenig-mermaid-") as temp:
        temp_dir = Path(temp)
        puppeteer_config = None
        if chrome_path is not None:
            puppeteer_config = temp_dir / "puppeteer.json"
            puppeteer_config.write_text(
                json.dumps(
                    {
                        "executablePath": str(chrome_path),
                        "args": ["--no-sandbox", "--disable-setuid-sandbox"],
                    }
                )
                + "\n"
            )
        render_jobs = []
        for number, (source, index, content) in enumerate(blocks, start=1):
            stem = f"{source.stem}-{index + 1:02d}-{number:03d}"
            input_path = temp_dir / f"{stem}.mmd"
            output_path = args.output_dir / f"{stem}.svg"
            input_path.write_text(content + "\n")
            command = [
                "mmdc",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--backgroundColor",
                "transparent",
            ]
            if puppeteer_config is not None:
                command.extend(["--puppeteerConfigFile", str(puppeteer_config)])
            render_jobs.append((source, index, command, output_path))

        def render_one(job: tuple[Path, int, list[str], Path]) -> str | None:
            source, index, command, output_path = job
            process = None
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                stdout, stderr = process.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.communicate()
                try:
                    output_is_svg = output_path.read_text(errors="replace").lstrip().startswith("<svg")
                except OSError:
                    output_is_svg = False
                if output_is_svg:
                    return None
                return (
                    f"{source.relative_to(root)} block {index + 1}: "
                    f"timeout after {args.timeout:g}s"
                )
            except OSError as error:
                return f"{source.relative_to(root)} block {index + 1}: launch failed: {error}"
            if process.returncode:
                detail = (stderr or stdout).strip().splitlines()
                return (
                    f"{source.relative_to(root)} block {index + 1}: "
                    + (detail[-1] if detail else "mmdc failed")
                )
            return None

        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
            futures = [executor.submit(render_one, job) for job in render_jobs]
            for future in as_completed(futures):
                failure = future.result()
                if failure is not None:
                    failures.append(failure)

    failures.sort()

    print(f"Mermaid blocks: {len(blocks)}")
    print(f"Rendered SVGs: {len(blocks) - len(failures)}")
    if failures:
        print("Failures:")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print(f"Output directory: {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
