"""
check_active_bank_via_server.py
================================
Queries the Flask OTA server's /api/device/status endpoint to find out
which bank is currently active, as last reported by the ESP32 bridge
(which itself asked the STM32 via CMD_BANK_QUERY over UART1).

This avoids needing a direct serial/COM connection to the STM32 - the
ESP32 already uploads this status periodically (every
STATUS_UPLOAD_INTERVAL, plus at boot and right after every OTA update).

NOTE: this reflects the last time the ESP32 uploaded status, not the
live state at the exact moment you run this script. If you need a
guaranteed-fresh answer (e.g. right after manually flashing a bank),
power-cycle the ESP32 first so it re-queries and re-uploads on boot,
or just wait up to STATUS_UPLOAD_INTERVAL (60s by default).

Usage:
    pip install requests
    python check_active_bank_via_server.py
    python check_active_bank_via_server.py --server 172.20.10.2:5000 --device STM32_F411RE_001
"""

import sys
import argparse
import requests


def check_active_bank(server: str, device_id: str) -> None:
    url = f"http://{server}/api/device/status"

    try:
        resp = requests.get(url, params={"device_id": device_id}, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: could not reach server at {url}")
        print(f"       {e}")
        sys.exit(1)

    if resp.status_code == 404:
        print(f"ERROR: device '{device_id}' not found on server.")
        print("       Has the ESP32 uploaded status at least once yet?")
        print("       (It does this once at boot, then every "
              "STATUS_UPLOAD_INTERVAL after.)")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"ERROR: server returned HTTP {resp.status_code}")
        print(resp.text)
        sys.exit(1)

    data = resp.json()

    active = data.get("active_bank", "?")
    device_version = data.get("device_version", "?")
    last_seen = data.get("last_seen", "?")
    recommended = data.get("recommended_build", "?")
    update_available = data.get("update_available", "?")

    print("=" * 50)
    print(" STM32 Active Bank Status (via server)")
    print("=" * 50)
    print(f" Device ID        : {device_id}")
    print(f" Device version   : {device_version}")
    print(f" Active bank      : {active}")
    print(f" Last seen        : {last_seen}")
    print(f" Update available : {update_available}")
    print("-" * 50)
    print(f" ==> Build with CubeIDE config: {recommended}")
    print(f" ==> Flash with launch config : Flash_{recommended}")
    print("=" * 50)
    print()
    print("(Reflects the last status the ESP32 uploaded - not")
    print(" necessarily this exact second. Power-cycle the ESP32")
    print(" first if you need a guaranteed-fresh read.)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server", default="172.20.10.2:5000",
        help="Flask server host:port (default: 172.20.10.2:5000)"
    )
    parser.add_argument(
        "--device", default="STM32_F411RE_001",
        help="Device ID (default: STM32_F411RE_001)"
    )
    args = parser.parse_args()

    check_active_bank(args.server, args.device)