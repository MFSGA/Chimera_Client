#!/usr/bin/env python3
"""Collect CI environment details as JSON for workflow summaries."""

import json
import os
import platform
import subprocess


def run_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None

    value = result.stdout.strip()
    return value or None


def main() -> None:
    env = {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "cpu_cores": os.cpu_count(),
        "cpu": platform.processor(),
    }

    try:
        with open("/proc/cpuinfo", encoding="utf-8") as cpuinfo:
            content = cpuinfo.read()
        for line in content.splitlines():
            if line.startswith("model name"):
                env["cpu"] = line.split(":", 1)[1].strip()
                break
        env["cpu_cores"] = content.count("processor\t:")
    except Exception:
        pass

    try:
        with open("/proc/meminfo", encoding="utf-8") as meminfo:
            for line in meminfo:
                if line.startswith("MemTotal"):
                    env["memory_gb"] = round(int(line.split()[1]) / 1024 / 1024, 2)
                    break
    except Exception:
        pass

    env["kernel"] = run_output(["uname", "-r"])
    env["docker"] = run_output(["docker", "version", "--format", "{{.Server.Version}}"])
    env["rustc"] = run_output(["rustc", "--version"])

    print(json.dumps(env))


if __name__ == "__main__":
    main()
