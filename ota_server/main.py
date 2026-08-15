"""
Secure OTA Firmware Update Server
=================================

Flask-based OTA server for STM32F411RE + ESP32 Bridge

Features
--------
• Full Firmware OTA
• Delta OTA
• SHA-256 Verification
• Device Status Monitoring
• Active Bank Tracking
• Multi-device Support
• Firmware Upload (with vector-table validation + target-bank detection)
• Device Database

CDAC ACTS DESD Project
"""

import os
import json
import time
import hashlib
import struct

from datetime import datetime

from flask import (
    Flask,
    request,
    jsonify,
    send_file
)

from werkzeug.utils import secure_filename

app = Flask(__name__)

# ==========================================================
# Directories
# ==========================================================

BASE_DIR = os.path.dirname(__file__)

FIRMWARE_DIR = os.path.join(BASE_DIR, "firmware")
PATCHES_DIR = os.path.join(FIRMWARE_DIR, "patches")

METADATA_FILE = os.path.join(FIRMWARE_DIR, "metadata.json")

DEVICE_STATUS_FILE = os.path.join(BASE_DIR, "device_status.json")

PAGE_SIZE = 1024

DEFAULT_DEVICE_ID = "STM32_F411RE_001"

os.makedirs(FIRMWARE_DIR, exist_ok=True)
os.makedirs(PATCHES_DIR, exist_ok=True)

# ==========================================================
# Firmware Validation
# ==========================================================
# Same class of check as OTA_ValidateFirmwareAddress() in ota_receiver.c
# and IsValidApp() in bootloader.c - reads the uploaded file's own vector
# table and confirms it looks like a real STM32F411RE application image
# for this project (plausible SRAM stack pointer, Thumb-bit reset handler
# inside Bank A or Bank B's address range, size within one bank). This
# CANNOT prove the file was compiled from THIS project's source - a
# compiled .bin has no filenames/symbols left in it after objcopy, only
# raw code/data bytes - but it reliably rejects non-firmware uploads
# (wrong chip, corrupt/truncated builds, unrelated files entirely).
# Enforced HERE (server-side) because client-side checks can always be
# bypassed by anyone hitting this endpoint directly (e.g. curl) - the
# server is the actual trust boundary.

SRAM_START_ADDR = 0x20000000
SRAM_END_ADDR = 0x20020000

APP_BANK_A_START = 0x08020000
APP_BANK_B_START = 0x08040000
APP_BANK_SIZE = 128 * 1024
MAX_APP_SIZE = APP_BANK_SIZE


def validate_firmware_bytes(data):
    """
    Returns (True, "OK", bank) if data's vector table looks like a
    legitimate STM32F411RE app image for this project, else
    (False, reason, None).

    `bank` is "A" or "B" - which bank this image's own linker origin
    says it was built for, read straight from its Reset_Handler address.
    This is the SAME detection OTA_ValidateFirmwareAddress() on the STM32
    does after a real OTA transfer - surfacing it here means a wrong-bank
    build can be caught at upload time instead of only after a failed
    UART transfer.
    """
    if len(data) < 8:
        return False, "File too small to contain a vector table", None

    if len(data) > MAX_APP_SIZE:
        return False, f"File is {len(data)} bytes, exceeds max app size of {MAX_APP_SIZE} bytes (128KB/bank)", None

    stack_ptr, reset_handler = struct.unpack('<II', data[0:8])

    if not (SRAM_START_ADDR <= stack_ptr <= SRAM_END_ADDR):
        return False, f"Initial stack pointer 0x{stack_ptr:08X} is outside valid SRAM range", None

    if (reset_handler & 1) == 0:
        return False, f"Reset_Handler address 0x{reset_handler:08X} missing Thumb bit - not valid Cortex-M code", None

    reset_addr = reset_handler & ~1
    in_bank_a = APP_BANK_A_START <= reset_addr < APP_BANK_A_START + APP_BANK_SIZE
    in_bank_b = APP_BANK_B_START <= reset_addr < APP_BANK_B_START + APP_BANK_SIZE

    if not (in_bank_a or in_bank_b):
        return False, f"Reset_Handler address 0x{reset_handler:08X} doesn't fall inside Bank A or Bank B", None

    bank = "A" if in_bank_a else "B"

    return True, "OK", bank

# ==========================================================
# Metadata
# ==========================================================

def load_metadata():

    if os.path.exists(METADATA_FILE):

        with open(METADATA_FILE, "r") as f:
            return json.load(f)

    return {
        "versions": [],
        "latest_version": None,
        "latest_file": None
    }


def save_metadata(metadata):

    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=4)

# ==========================================================
# Device Status Database
# ==========================================================

def load_device_database():

    if os.path.exists(DEVICE_STATUS_FILE):

        with open(DEVICE_STATUS_FILE, "r") as f:
            return json.load(f)

    return {}


def save_device_database(db):

    with open(DEVICE_STATUS_FILE, "w") as f:
        json.dump(db, f, indent=4)

def update_device_status(device_id, status):

    database = load_device_database()

    status["last_seen"] = datetime.utcnow().isoformat()

    database[device_id] = status

    save_device_database(database)

def get_device_status(device_id):

    database = load_device_database()

    if device_id not in database:
        return None

    return database[device_id]

def list_devices():

    database = load_device_database()

    return database


def get_active_bank_for_device(device_id):
    """
    Returns "A" or "B" for the device's currently active bank, read from
    device_status.json (populated by the ESP32's periodic status
    uploads - see post_device_status() / updateAndUploadBankStatus() on
    the ESP32 side).

    Returns None if no status has ever been reported for this device
    (e.g. very first boot, before the ESP32 has posted anything). Callers
    should treat None as "unknown - don't block the upload", since we
    have no basis to reject anything yet.
    """

    status = get_device_status(device_id)

    if status is None:
        return None

    return status.get("active_bank")

# ==========================================================
# Firmware Utilities
# ==========================================================

def firmware_path(version):

    return os.path.join(
        FIRMWARE_DIR,
        f"firmware_v{version}.bin"
    )

def compute_sha256(path):

    sha = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            block = f.read(4096)

            if not block:
                break

            sha.update(block)

    return sha.hexdigest()

def compute_sha256_bytes(data):

    return hashlib.sha256(data).hexdigest()

def pad_firmware(data):

    rem = len(data) % PAGE_SIZE

    if rem:

        data += b'\xFF' * (PAGE_SIZE - rem)

    return data

# ==========================================================
# Helper Functions
# ==========================================================

def latest_firmware():

    metadata = load_metadata()

    if metadata["latest_version"] is None:
        return None

    return metadata["latest_version"]

def firmware_exists(version):

    return os.path.exists(firmware_path(version))

def firmware_size(version):

    return os.path.getsize(
        firmware_path(version)
    )

def firmware_hash(version):

    return compute_sha256(
        firmware_path(version)
    )

# ==========================================================
# Delta Patch Generator
# ==========================================================

def generate_delta_patch(old_fw_path, new_fw_path):

    with open(old_fw_path, "rb") as f:
        old_data = f.read()

    with open(new_fw_path, "rb") as f:
        new_data = f.read()

    old_data = pad_firmware(old_data)
    new_data = pad_firmware(new_data)

    old_pages = len(old_data) // PAGE_SIZE
    new_pages = len(new_data) // PAGE_SIZE

    changed_pages = []

    for page in range(new_pages):

        if page < old_pages:
            old_page = old_data[
                page * PAGE_SIZE:
                (page + 1) * PAGE_SIZE
            ]
        else:
            old_page = b'\xFF' * PAGE_SIZE

        new_page = new_data[
            page * PAGE_SIZE:
            (page + 1) * PAGE_SIZE
        ]

        if old_page != new_page:
            changed_pages.append((page, new_page))

    patch = bytearray()

    patch += struct.pack("<I", 0x4F544150)
    patch += struct.pack("<H", 1)
    patch += struct.pack("<H", len(changed_pages))
    patch += struct.pack("<I", len(new_data))
    patch += struct.pack("<H", new_pages)
    patch += struct.pack("<H", PAGE_SIZE)

    for page_index, page_data in changed_pages:

        patch += struct.pack("<H", page_index)
        patch += page_data

    fw_hash = hashlib.sha256(new_data).digest()

    patch += fw_hash

    stats = {

        "old_firmware_size": len(old_data),
        "new_firmware_size": len(new_data),
        "total_pages": new_pages,
        "changed_pages": len(changed_pages),
        "unchanged_pages": new_pages - len(changed_pages),
        "patch_size": len(patch),
        "new_firmware_sha256": fw_hash.hex()
    }

    return bytes(patch), stats


# ==========================================================
# API
# ==========================================================

@app.route("/api/health", methods=["GET"])
def api_health():

    return jsonify({

        "status": "OK",

        "server": "Secure OTA Server",

        "project": "CDAC DESD",

        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/version", methods=["GET"])
def api_version():

    metadata = load_metadata()

    if metadata["latest_version"] is None:

        return jsonify({

            "error": "No firmware available"

        }), 404

    version = metadata["latest_version"]

    return jsonify({

        "version": version,

        "filename": metadata["latest_file"],

        "sha256": firmware_hash(version),

        "size": firmware_size(version),

        "page_size": PAGE_SIZE,

        "available_versions": metadata["versions"]
    })


@app.route("/api/firmware/upload", methods=["POST"])
def upload_firmware():
    """
    Upload new firmware binary.

    Form Data:
        file: firmware .bin file
        version: version string (e.g., "1.0.0")
        device_id: optional, defaults to DEFAULT_DEVICE_ID - which
            device's active-bank status to check the upload against

    Validates the uploaded bytes' vector table before ever writing to
    disk (stack pointer in SRAM range, Thumb-bit reset handler, address
    inside Bank A or Bank B) and rejects invalid images with 400. The
    response and stored metadata also report which bank ("A" or "B")
    this image is linked for, detected from its own vector table.

    Also rejects uploads that target the SAME bank the device is
    currently running (per its last-reported device status) with 400 -
    an OTA update always targets the INACTIVE bank; a same-bank upload
    is either a build/version-bump mistake or a stale binary, and
    accepting it would let the device "update" into the bank it's
    already running, which the OTA flow isn't designed to handle safely.
    If the device's active bank isn't known yet (no status reported),
    the check is skipped rather than blocking the very first upload.
    """

    if "file" not in request.files:

        return jsonify({

            "error": "No file uploaded"

        }), 400

    file = request.files["file"]

    version = request.form.get("version")

    if version is None:

        return jsonify({

            "error": "Version missing"

        }), 400

    device_id = request.form.get("device_id", DEFAULT_DEVICE_ID)

    # Read into memory first for validation, before ever touching disk -
    # reject bad uploads without writing/overwriting any firmware file.
    file_data = file.read()

    valid, reason, target_bank = validate_firmware_bytes(file_data)

    if not valid:

        print(f"[OTA] Rejected upload for v{version}: {reason}")

        return jsonify({

            "error": f"Invalid firmware image: {reason}"

        }), 400

    active_bank = get_active_bank_for_device(device_id)

    if active_bank is not None and target_bank == active_bank:

        inactive_bank = "B" if active_bank == "A" else "A"

        print(
            f"[OTA] Rejected upload for v{version}: targets Bank "
            f"{target_bank}, but device '{device_id}' is currently "
            f"running Bank {active_bank}"
        )

        return jsonify({

            "error": (
                f"Device is currently running Bank {active_bank} - "
                f"upload a Bank{inactive_bank} binary instead"
            ),

            "active_bank": active_bank,

            "uploaded_target_bank": target_bank

        }), 400

    filename = secure_filename(

        f"firmware_v{version}.bin"

    )

    save_path = os.path.join(

        FIRMWARE_DIR,

        filename
    )

    with open(save_path, "wb") as f:
        f.write(file_data)

    metadata = load_metadata()

    info = {

        "version": version,

        "filename": filename,

        "size": os.path.getsize(save_path),

        "sha256": compute_sha256(save_path),

        "uploaded_at": datetime.utcnow().isoformat(),

        "target_bank": target_bank,

        "page_count":
        (
            os.path.getsize(save_path)
            +
            PAGE_SIZE
            -
            1
        )
        //
        PAGE_SIZE
    }

    metadata["versions"] = [

        x

        for x in metadata["versions"]

        if x["version"] != version

    ]

    metadata["versions"].append(info)

    metadata["latest_version"] = version

    metadata["latest_file"] = filename

    save_metadata(metadata)

    print(

        f"[OTA] Firmware v{version} uploaded: "
        f"{info['size']} bytes, target_bank={target_bank}, "
        f"SHA256: {info['sha256'][:16]}..."

    )

    return jsonify({

        "status": "success",

        "version": version,

        "sha256": info["sha256"],

        "size": info["size"],

        "pages": info["page_count"],

        "target_bank": target_bank

    })


@app.route("/api/firmware/full", methods=["GET"])
def download_full_firmware():

    metadata = load_metadata()

    if metadata["latest_version"] is None:

        return jsonify({

            "error": "No firmware available"

        }), 404

    fw = firmware_path(

        metadata["latest_version"]
    )

    if not os.path.exists(fw):

        return jsonify({

            "error": "Firmware missing"

        }), 404

    with open(fw, "rb") as f:

        firmware = f.read()

    firmware_hash_raw = hashlib.sha256(

        firmware

    ).digest()

    temp = fw + ".combined"

    with open(temp, "wb") as f:

        f.write(firmware)

        f.write(firmware_hash_raw)

    return send_file(

        temp,

        mimetype="application/octet-stream",

        as_attachment=True,

        download_name=

        f"firmware_v{metadata['latest_version']}.bin"

    )
# ==========================================================
# Delta Firmware API
# ==========================================================

@app.route("/api/firmware/delta", methods=["POST"])
def download_delta():

    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing JSON"}), 400

    if "current_version" not in data:
        return jsonify({"error": "current_version required"}), 400

    metadata = load_metadata()

    target_version = data.get(
        "target_version",
        metadata["latest_version"]
    )

    current_version = data["current_version"]

    if current_version == target_version:

        return jsonify({

            "message": "Already up to date",

            "version": current_version

        })

    old_fw = firmware_path(current_version)

    new_fw = firmware_path(target_version)

    if not os.path.exists(old_fw):

        return jsonify({

            "error": f"Firmware {current_version} not found"

        }), 404

    if not os.path.exists(new_fw):

        return jsonify({

            "error": f"Firmware {target_version} not found"

        }), 404

    patch, stats = generate_delta_patch(

        old_fw,

        new_fw

    )

    filename = f"patch_{current_version}_to_{target_version}.bin"

    patch_path = os.path.join(

        PATCHES_DIR,

        filename

    )

    with open(patch_path, "wb") as f:

        f.write(patch)

    print(

        f"[OTA] Delta Patch Created "

        f"{current_version}->{target_version}"

    )

    print(stats)

    return send_file(

        patch_path,

        mimetype="application/octet-stream",

        as_attachment=True,

        download_name=filename

    )


# ==========================================================
# Delta Information
# ==========================================================

@app.route("/api/firmware/delta/info", methods=["POST"])
def delta_information():

    data = request.get_json()

    if not data:

        return jsonify({

            "error": "Missing JSON"

        }), 400

    if "current_version" not in data:

        return jsonify({

            "error": "current_version required"

        }), 400

    metadata = load_metadata()

    target = data.get(

        "target_version",

        metadata["latest_version"]

    )

    old_fw = firmware_path(

        data["current_version"]

    )

    new_fw = firmware_path(

        target

    )

    if not os.path.exists(old_fw):

        return jsonify({

            "error": "Current firmware missing"

        }), 404

    if not os.path.exists(new_fw):

        return jsonify({

            "error": "Target firmware missing"

        }), 404

    _, stats = generate_delta_patch(

        old_fw,

        new_fw

    )

    stats["current_version"] = data["current_version"]

    stats["target_version"] = target

    return jsonify(stats)


# ==========================================================
# Device Status API
# ==========================================================

@app.route("/api/device/status", methods=["POST"])
def post_device_status():

    data = request.get_json()

    if not data:

        return jsonify({

            "error": "Missing JSON"

        }), 400

    device_id = data.get(

        "device_id",

        DEFAULT_DEVICE_ID

    )

    data["ip_address"] = request.remote_addr

    data["last_seen"] = datetime.utcnow().isoformat()

    update_device_status(

        device_id,

        data

    )

    return jsonify({

        "status": "success",

        "device_id": device_id,

        "message": "Device status updated"

    })


@app.route("/api/device/status", methods=["GET"])
def get_device():

    device_id = request.args.get(

        "device_id",

        DEFAULT_DEVICE_ID

    )

    status = get_device_status(

        device_id

    )

    if status is None:

        return jsonify({

            "error": "Device not found"

        }), 404

    metadata = load_metadata()

    latest = metadata["latest_version"]

    if latest:

        status["latest_server_version"] = latest

        status["update_available"] = (

            latest != status.get(

                "device_version",

                ""

            )

        )

        active = status.get(

            "active_bank",

            "A"

        )

        status["inactive_bank"] = (

            "B"

            if active == "A"

            else "A"

        )

        status["recommended_build"] = (

            "BankB"

            if active == "A"

            else "BankA"

        )

    return jsonify(status)


@app.route("/api/device/list", methods=["GET"])
def device_list():

    database = list_devices()

    return jsonify({

        "device_count": len(database),

        "devices": database

    })


# ==========================================================
# Main
# ==========================================================

if __name__ == "__main__":

    print("=" * 60)

    print(" Secure OTA Firmware Update Server")

    print(" STM32F411RE Dual Bank OTA")

    print(" ESP32 WiFi Bridge")

    print("=" * 60)

    print(f"Firmware Folder : {FIRMWARE_DIR}")

    print(f"Patch Folder    : {PATCHES_DIR}")

    print(f"Device Database : {DEVICE_STATUS_FILE}")

    print(f"Page Size       : {PAGE_SIZE}")

    print("Listening on http://0.0.0.0:5000")

    print("=" * 60)

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True

    )