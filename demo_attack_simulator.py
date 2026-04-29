from __future__ import annotations

import runpy
import sys
from pathlib import Path


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent
    target_script = repo_root / "test_folder" / "demo_attack_simulator.py"

    if not target_script.exists():
        raise FileNotFoundError(
            f"Expected simulator script not found: {target_script}"
        )

    # Keep user arguments intact, only point argv[0] to the actual script path.
    sys.argv[0] = str(target_script)
    runpy.run_path(str(target_script), run_name="__main__")
