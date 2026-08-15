"""
Secure OTA Firmware Update Server
=================================
Flask-based server for managing firmware versions, generating delta patches,
and serving updates to ESP32/STM32 devices.

CDAC ACTS PG-Diploma in DESD Capstone Project

Endpoints:
    GET  /api/version          - Get latest firmware version info
    GET  /api/firmware/full     - Download full firmware binary
    POST /api/firmware/delta    - Generate and download delta patch
    POST /api/firmware/upload   - Upload new firmware version
    GET  /api/health            - Server health check

FIX APPLIED (see download_full_firmware): the STM32-side ota_receiver.c
expects the LAST 32 BYTES of a full-firmware transfer to be the raw
SHA-256 hash of everything before it - exactly like generate_delta_patch()
already appends new_fw_hash for delta patches. The original version of
this endpoint sent the raw .bin with nothing appended, which would fail
verification on the device every time. Now it appends the same way.

TEST HOOK: download_full_firmware() currently corrupts one byte of the
firmware AFTER computing the hash, so the hash sent to the device is for
the GOOD data but the bytes actually sent are BAD - this is used to
exercise the STM32's SHA-256 rejection / rollback-adjacent path. Remove
or comment out the "TEST ONLY" block before doing any real OTA update,
or every update will fail.
"""

import os
import hashlib
import json
import struct
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

app = Flask(__name__)

FIRMWARE_DIR = os.path.join(os.path.dirname(__file__), 'firmware')
PATCHES_DIR = os.path.join(FIRMWARE_DIR, 'patches')
METADATA_FILE = os.path.join(FIRMWARE_DIR, 'metadata.json')
PAGE_SIZE = 1024  # 1KB page size for delta comparison

# Ensure directories exist
os.makedirs(FIRMWARE_DIR, exist_ok=True)
os.makedirs(PATCHES_DIR, exist_ok=True)


# ─────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────

def compute_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            block = f.read(4096)
            if not block:
                break
            sha256.update(block)
    return sha256.hexdigest()


def compute_sha256_bytes(data):
    """Compute SHA-256 hash of bytes data."""
    return hashlib.sha256(data).hexdigest()


def load_metadata():
    """Load firmware metadata from JSON file."""
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r') as f:
            return json.load(f)
    return {
        'versions': [],
        'latest_version': None,
        'latest_file': None
    }


def save_metadata(metadata):
    """Save firmware metadata to JSON file."""
    with open(METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=2)


def get_firmware_path(version):
    """Get full path to a firmware binary by version."""
    return os.path.join(FIRMWARE_DIR, f'firmware_v{version}.bin')


def pad_firmware(data, page_size=PAGE_SIZE):
    """Pad firmware to align with page boundaries."""
    remainder = len(data) % page_size
    if remainder != 0:
        data += b'\xFF' * (page_size - remainder)  # 0xFF = erased flash state
    return data


# ─────────────────────────────────────────────
# Delta Patch Generation (Page-Based)
# ─────────────────────────────────────────────

def generate_delta_patch(old_fw_path, new_fw_path):
    """
    Generate a page-based delta patch between old and new firmware.

    Patch Format:
    ┌──────────────────────────────────────────┐
    │ Header (16 bytes)                        │
    │   Magic: 0x4F544150 ("OTAP")             │
    │   Version: uint16                        │
    │   Num Changed Pages: uint16              │
    │   New FW Size: uint32                    │
    │   Total Pages: uint16                    │
    │   Page Size: uint16                      │
    ├──────────────────────────────────────────┤
    │ Page Entry 0                             │
    │   Page Index: uint16                     │
    │   Page Data: PAGE_SIZE bytes             │
    ├──────────────────────────────────────────┤
    │ Page Entry 1                             │
    │   ...                                    │
    ├──────────────────────────────────────────┤
    │ SHA-256 Hash of NEW firmware (32 bytes)  │
    └──────────────────────────────────────────┘
    """

    # Read firmware files
    with open(old_fw_path, 'rb') as f:
        old_data = f.read()
    with open(new_fw_path, 'rb') as f:
        new_data = f.read()

    # Pad to page boundaries
    old_data = pad_firmware(old_data, PAGE_SIZE)
    new_data = pad_firmware(new_data, PAGE_SIZE)

    old_pages = len(old_data) // PAGE_SIZE
    new_pages = len(new_data) // PAGE_SIZE
    total_pages = new_pages

    # Find changed pages
    changed_pages = []
    for i in range(total_pages):
        old_page = old_data[i * PAGE_SIZE:(i + 1) * PAGE_SIZE] if i < old_pages else b'\xFF' * PAGE_SIZE
        new_page = new_data[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]

        if old_page != new_page:
            changed_pages.append((i, new_page))

    # Build patch binary
    patch = bytearray()

    # Header (16 bytes)
    patch += struct.pack('<I', 0x4F544150)          # Magic "OTAP"
    patch += struct.pack('<H', 1)                    # Patch format version
    patch += struct.pack('<H', len(changed_pages))   # Number of changed pages
    patch += struct.pack('<I', len(new_data))         # New firmware size (padded)
    patch += struct.pack('<H', total_pages)           # Total pages in new firmware
    patch += struct.pack('<H', PAGE_SIZE)             # Page size

    # Changed page entries
    for page_idx, page_data in changed_pages:
        patch += struct.pack('<H', page_idx)         # Page index (2 bytes)
        patch += page_data                           # Page data (PAGE_SIZE bytes)

    # Append SHA-256 of complete new firmware
    new_fw_hash = hashlib.sha256(new_data).digest()  # 32 bytes raw hash
    patch += new_fw_hash

    # Statistics
    full_size = len(new_data)
    patch_size = len(patch)
    savings = ((full_size - patch_size) / full_size) * 100 if full_size > 0 else 0

    stats = {
        'old_firmware_size': len(old_data),
        'new_firmware_size': len(new_data),
        'total_pages': total_pages,
        'changed_pages': len(changed_pages),
        'unchanged_pages': total_pages - len(changed_pages),
        'patch_size': patch_size,
        'compression_ratio': f'{savings:.1f}%',
        'new_firmware_sha256': new_fw_hash.hex()
    }

    return bytes(patch), stats


# ─────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health_check():
    """Server health check endpoint."""
    return jsonify({
        'status': 'ok',
        'server': 'OTA Firmware Update Server',
        'timestamp': datetime.utcnow().isoformat(),
        'project': 'CDAC ACTS DESD Capstone'
    })


@app.route('/api/version', methods=['GET'])
def get_version():
    """Get latest firmware version information."""
    metadata = load_metadata()

    if not metadata['latest_version']:
        return jsonify({'error': 'No firmware uploaded yet'}), 404

    fw_path = get_firmware_path(metadata['latest_version'])
    fw_hash = compute_sha256(fw_path) if os.path.exists(fw_path) else None
    fw_size = os.path.getsize(fw_path) if os.path.exists(fw_path) else 0

    return jsonify({
        'version': metadata['latest_version'],
        'sha256': fw_hash,
        'size': fw_size,
        'filename': metadata['latest_file'],
        'available_versions': metadata['versions'],
        'page_size': PAGE_SIZE
    })


@app.route('/api/firmware/upload', methods=['POST'])
def upload_firmware():
    """
    Upload new firmware binary.

    Form Data:
        file: firmware .bin file
        version: version string (e.g., "1.0.0")
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    version = request.form.get('version', None)

    if not version:
        return jsonify({'error': 'Version string required'}), 400

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Save firmware
    filename = f'firmware_v{version}.bin'
    filepath = os.path.join(FIRMWARE_DIR, filename)
    file.save(filepath)

    # Compute hash
    fw_hash = compute_sha256(filepath)
    fw_size = os.path.getsize(filepath)

    # Update metadata
    metadata = load_metadata()
    version_info = {
        'version': version,
        'filename': filename,
        'sha256': fw_hash,
        'size': fw_size,
        'uploaded_at': datetime.utcnow().isoformat(),
        'page_count': (fw_size + PAGE_SIZE - 1) // PAGE_SIZE
    }

    # Remove existing same version if re-uploading
    metadata['versions'] = [v for v in metadata['versions'] if v['version'] != version]
    metadata['versions'].append(version_info)
    metadata['latest_version'] = version
    metadata['latest_file'] = filename

    save_metadata(metadata)

    print(f"[OTA] Firmware v{version} uploaded: {fw_size} bytes, SHA256: {fw_hash[:16]}...")

    return jsonify({
        'message': f'Firmware v{version} uploaded successfully',
        'version': version,
        'sha256': fw_hash,
        'size': fw_size,
        'pages': version_info['page_count']
    })


@app.route('/api/firmware/full', methods=['GET'])
def download_full_firmware():
    """
    Download the latest full firmware binary, with a trailing 32-byte
    RAW SHA-256 hash appended.

    ota_receiver.c on the STM32 reads the last 32 bytes of whatever it
    received as the expected hash (fwSize = receivedSize - 32), the same
    way generate_delta_patch() above already appends new_fw_hash to
    patches. Without this, the device-side verification would always
    fail on a full-firmware update.
    """
    metadata = load_metadata()

    if not metadata['latest_version']:
        return jsonify({'error': 'No firmware available'}), 404

    fw_path = get_firmware_path(metadata['latest_version'])

    if not os.path.exists(fw_path):
        return jsonify({'error': 'Firmware file not found'}), 404

    with open(fw_path, 'rb') as f:
        fw_data = f.read()

    # Hash computed on the ORIGINAL, uncorrupted bytes - this is what gets
    # appended and is what the device will compare against after it
    # receives (and, below, corrupts) the data.
    fw_hash = hashlib.sha256(fw_data).digest()  # raw 32 bytes, NOT hex

    # ----- TEST ONLY: Corrupt one byte after computing SHA -----
    # Simulates transit/flash corruption: the hash sent to the device is
    # still the hash of the GOOD data, but the bytes actually sent (and
    # written to flash) are bad - so OTA_VerifyFirmware() on the STM32
    # should reject it. Comment this block out / remove it for normal,
    # real-world OTA operation.
    fw_data = bytearray(fw_data)
    fw_data[100] ^= 0xFF        # Flip one byte (any valid index works)
    fw_data = bytes(fw_data)
    print(f"[OTA][TEST] Corrupted byte 100 of v{metadata['latest_version']} before sending")
    # ----- END TEST ONLY -----

    combined_path = fw_path + '.combined'
    with open(combined_path, 'wb') as f:
        f.write(fw_data)
        f.write(fw_hash)

    return send_file(
        combined_path,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'firmware_v{metadata["latest_version"]}.bin'
    )


@app.route('/api/firmware/delta', methods=['POST'])
def get_delta_patch():
    """
    Generate and download delta patch.

    JSON Body:
        current_version: device's current firmware version
        target_version: (optional) target version, defaults to latest

    Returns: Binary delta patch file
    """
    data = request.get_json()

    if not data or 'current_version' not in data:
        return jsonify({'error': 'current_version required'}), 400

    current_version = data['current_version']
    metadata = load_metadata()
    target_version = data.get('target_version', metadata['latest_version'])

    if not target_version:
        return jsonify({'error': 'No target firmware available'}), 404

    if current_version == target_version:
        return jsonify({'message': 'Already up to date', 'version': current_version})

    old_fw_path = get_firmware_path(current_version)
    new_fw_path = get_firmware_path(target_version)

    if not os.path.exists(old_fw_path):
        return jsonify({'error': f'Current firmware v{current_version} not found on server'}), 404

    if not os.path.exists(new_fw_path):
        return jsonify({'error': f'Target firmware v{target_version} not found'}), 404

    # Generate delta patch
    print(f"[OTA] Generating delta patch: v{current_version} -> v{target_version}")
    patch_data, stats = generate_delta_patch(old_fw_path, new_fw_path)

    # Save patch to file
    patch_filename = f'patch_{current_version}_to_{target_version}.bin'
    patch_path = os.path.join(PATCHES_DIR, patch_filename)
    with open(patch_path, 'wb') as f:
        f.write(patch_data)

    print(f"[OTA] Delta patch generated: {stats}")

    # Return patch info + file
    return send_file(
        patch_path,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=patch_filename
    )


@app.route('/api/firmware/delta/info', methods=['POST'])
def get_delta_info():
    """
    Get delta patch info without downloading.
    Returns statistics about what would change.
    """
    data = request.get_json()

    if not data or 'current_version' not in data:
        return jsonify({'error': 'current_version required'}), 400

    current_version = data['current_version']
    metadata = load_metadata()
    target_version = data.get('target_version', metadata['latest_version'])

    old_fw_path = get_firmware_path(current_version)
    new_fw_path = get_firmware_path(target_version)

    if not os.path.exists(old_fw_path) or not os.path.exists(new_fw_path):
        return jsonify({'error': 'Firmware files not found'}), 404

    _, stats = generate_delta_patch(old_fw_path, new_fw_path)
    stats['current_version'] = current_version
    stats['target_version'] = target_version

    return jsonify(stats)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  Secure OTA Firmware Update Server")
    print("  CDAC ACTS PG-Diploma in DESD")
    print("=" * 60)
    print(f"  Firmware directory: {FIRMWARE_DIR}")
    print(f"  Page size: {PAGE_SIZE} bytes")
    print(f"  Server starting on http://0.0.0.0:5000")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=True)