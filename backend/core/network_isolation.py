from __future__ import annotations

import platform
import subprocess
from typing import Any


def _command_for_os(os_type: str) -> list[str] | None:
    if os_type == "Windows":
        return ["netsh", "interface", "set", "interface", "Wi-Fi", "admin=disable"]
    if os_type == "Linux":
        return ["nmcli", "networking", "off"]
    if os_type == "Darwin":
        # Best-effort fallback for macOS demo environments.
        return ["networksetup", "-setairportpower", "en0", "off"]
    return None


def isolate_network(mode: str = "safe") -> dict[str, Any]:
    """
    mode:
    - safe: log only (default)
    - aggressive: attempt to disable network
    """
    if mode not in {"safe", "aggressive"}:
        raise ValueError("mode must be either 'safe' or 'aggressive'")

    os_type = platform.system()
    command = _command_for_os(os_type)
    command_text = " ".join(command) if command else ""

    if mode == "safe":
        print("Network isolation triggered")
        return {
            "mode": "safe",
            "os": os_type,
            "isolated": False,
            "simulated": True,
            "command": command_text,
            "message": "Network isolation triggered",
        }

    if not command:
        return {
            "mode": "aggressive",
            "os": os_type,
            "isolated": False,
            "simulated": False,
            "command": "",
            "message": "Unsupported OS for network isolation",
        }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return {
            "mode": "aggressive",
            "os": os_type,
            "isolated": result.returncode == 0,
            "simulated": False,
            "command": command_text,
            "message": "Network isolation attempted",
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
            "exit_code": int(result.returncode),
        }
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "mode": "aggressive",
            "os": os_type,
            "isolated": False,
            "simulated": False,
            "command": command_text,
            "message": f"Network isolation failed: {error}",
        }
