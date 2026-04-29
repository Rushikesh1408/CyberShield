#!/usr/bin/env python3
"""Minimal QA test to debug harness issues."""
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

print("Starting minimal QA test...")
print(f"Working directory: {ROOT}")

# Step 1: Test backend startup
print("\n[1] Testing backend startup...")
env = {
    "FLASK_DEBUG": "0",
    "FLASK_RELOADER": "0",
    "CYBERSHIELD_MONITOR_PATHS": str(ROOT / "test_folder" / "qa_runtime" / "monitored"),
    "PYTHONUNBUFFERED": "1",
}

process = subprocess.Popen(
    [sys.executable, "-m", "backend.app"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

# Read output for 5 seconds
start = time.time()
output_lines = []
while time.time() - start < 5:
    try:
        line = process.stdout.readline()
        if line:
            output_lines.append(line.strip())
            print(f"  Backend: {line.strip()}")
    except:
        break

if process.poll() is None:
    print("  ✓ Backend process is running")
    process.terminate()
    process.wait()
else:
    print("  ✗ Backend process exited")
    sys.exit(1)

print("\n[2] Testing probe file creation...")
monitored = ROOT / "test_folder" / "qa_runtime" / "monitored"
monitored.mkdir(parents=True, exist_ok=True)

# Try creating both timestamped and non-timestamped files
import os
timestamp_ms = int(time.time() * 1000)

test_files = [
    (monitored / "entropy_probe.bin", os.urandom(512)),
    (monitored / f"entropy_probe_{timestamp_ms}.bin", os.urandom(512)),
]

for path, data in test_files:
    try:
        path.write_bytes(data)
        print(f"  ✓ Created {path.name}")
    except PermissionError as e:
        print(f"  ✗ Failed to create {path.name}: {e}")

print("\nMinimal test completed")
