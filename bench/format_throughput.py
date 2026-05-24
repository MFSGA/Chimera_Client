#!/usr/bin/env python3
"""Format proxy test results as Markdown.

This accepts the throughput JSON-lines format used by the reference project,
but also produces a useful placeholder summary while this repository only runs
the currently available Docker E2E tests.
"""

import argparse
import json
from collections import defaultdict


PROTOCOL_META = {
    "trojan": ("Trojan", 0),
    "vless": ("VLESS", 1),
    "hysteria2": ("Hysteria2", 2),
    "socks5": ("SOCKS5", 3),
}


def split_label(label: str) -> tuple[str, str]:
    parts = label.split("-", 1)
    return parts[0], parts[1] if len(parts) > 1 else "plain"


def fmt_mbps(value: float, stdev: float) -> str:
    if stdev > 0:
        return f"{value:.1f} +/- {stdev:.1f}"
    return f"{value:.1f}"


def render_throughput(results_path: str) -> str:
    rows = []
    with open(results_path, encoding="utf-8") as results:
        for line in results:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    if not rows:
        return "## Proxy Throughput Results\n\nNo throughput results were recorded.\n"

    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        proto, _ = split_label(row.get("label", "unknown"))
        groups[proto].append(row)

    lines = ["## Proxy Throughput Results", ""]
    for proto in sorted(groups, key=lambda item: PROTOCOL_META.get(item, (item, 99))[1]):
        display_name, _ = PROTOCOL_META.get(proto, (proto.upper(), 99))
        lines.extend(
            [
                f"### {display_name}",
                "",
                "| Transport | Payload | Runs | Upload Mbps | Download Mbps |",
                "|-----------|---------|:----:|:-----------:|:-------------:|",
            ]
        )
        for row in groups[proto]:
            _, transport = split_label(row.get("label", "?"))
            payload_mb = row.get("total_bytes", 0) // (1024 * 1024)
            upload = fmt_mbps(row.get("upload_mbps", 0.0), row.get("upload_stdev_mbps", 0.0))
            download = fmt_mbps(
                row.get("download_mbps", 0.0),
                row.get("download_stdev_mbps", 0.0),
            )
            lines.append(
                f"| `{transport}` | {payload_mb} MB | {row.get('runs', 1)} | {upload} | {download} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_placeholder() -> str:
    return "\n".join(
        [
            "## Proxy E2E Results",
            "",
            "Throughput result collection is not enabled in this repository yet.",
            "",
            "This trimmed workflow currently runs the available Docker E2E tests:",
            "",
            "- `test_vless_ws`",
            "- `test_trojan_ws`",
            "",
            "Switch this workflow back to the full throughput command after the",
            "throughput helpers and `e2e_throughput_*` tests are migrated.",
            "",
        ]
    )


def append_env(markdown: str, env_json: str | None) -> str:
    if not env_json:
        return markdown

    try:
        env = json.loads(env_json)
    except json.JSONDecodeError:
        return markdown

    lines = [markdown.rstrip(), "", "### Test Environment", "", "| | |", "|---|---|"]
    os_info = env.get("os", {})
    if os_info.get("system"):
        os_value = f"{os_info['system']} {os_info.get('release', '')}".strip()
        lines.append(f"| OS | {os_value} |")
        lines.append(f"| Architecture | {os_info.get('machine', 'unknown')} |")
    for key, label in [
        ("kernel", "Kernel"),
        ("cpu", "CPU"),
        ("cpu_cores", "CPU Cores"),
        ("memory_gb", "Memory GB"),
        ("docker", "Docker"),
        ("rustc", "Rust"),
    ]:
        value = env.get(key)
        if value:
            lines.append(f"| {label} | {value} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", help="JSON-lines throughput result file")
    parser.add_argument("--output", "-o", required=True, help="Markdown output file")
    parser.add_argument("--run-url", help="GitHub Actions workflow run URL")
    parser.add_argument("--env-json", help="JSON environment details")
    args = parser.parse_args()

    try:
        markdown = render_throughput(args.results)
    except FileNotFoundError:
        markdown = render_placeholder()

    markdown = append_env(markdown, args.env_json)
    if args.run_url:
        markdown = markdown.rstrip() + f"\n\n[View workflow run]({args.run_url})\n"

    with open(args.output, "w", encoding="utf-8") as output:
        output.write(markdown)


if __name__ == "__main__":
    main()
