/*
 * esp32_ota_bridge.ino - ESP32 OTA WiFi Bridge
 *
 * CDAC ACTS PG-Diploma in DESD
 * Secure OTA Firmware Update System
 *
 * ─────────────────────────────────────────────
 * NACK reason reporting
 * ─────────────────────────────────────────────
 * The STM32 sends a one-byte reason code immediately after CMD_NACK
 * (see OTA_NackReason_t in the STM32's ota_receiver.h). waitForACK() reads
 * that byte and nackReasonToString() converts it to a readable message
 * printed on the serial monitor - e.g. a SHA-256 verification failure on
 * the STM32 now shows up here as:
 *
 *   [UART] NACK received for END_OTA - reason: SHA-256 mismatch (image
 *   corrupted or verification failed) (0x05)
 *
 * instead of a bare "NACK received", which gave no indication of why.
 *
 * ─────────────────────────────────────────────
 * NEW IN THIS VERSION: wait-for-reboot + bank status upload to server
 * ─────────────────────────────────────────────
 * 1) waitForSTM32Ready() - after an OTA install triggers a reboot on the
 *    STM32, the old code did a blind delay(5000) before querying the
 *    active bank. That's fragile: too short and the query hits the MCU
 *    mid-boot (UART not yet reinitialized -> silence or garbage), too
 *    long and every single update wastes seconds doing nothing. This is
 *    replaced with an active poll: probe with a lightweight
 *    CMD_VERSION_REQ every ~300ms (cheaper round-trip than the 44-byte
 *    bank response) until the STM32 answers or a timeout elapses, THEN
 *    do the real bank query.
 *
 * 2) postDeviceStatusToServer() - server.py's same-bank upload rejection
 *    (get_active_bank_for_device()) reads active_bank straight out of
 *    device_status.json on the server. Nothing in the previous version of
 *    this file ever POSTed there, so that check was silently a no-op
 *    (always saw "unknown", never blocked anything). querySTM32Bank() now
 *    POSTs the parsed bank info to /api/device/status right after a
 *    successful query, so the server always has a fresh, accurate
 *    active_bank on file before the next upload happens.
 */

#include <WiFi.h>
#include <HTTPClient.h>
#include "config.h"

// ─────────────────────────────────────────────
// NACK Reason Codes - MUST match ota_receiver.h's OTA_NackReason_t
// ─────────────────────────────────────────────
#define NACK_REASON_NONE                0x00
#define NACK_REASON_CHECKSUM_MISMATCH   0x01
#define NACK_REASON_SEQUENCE_ERROR      0x02
#define NACK_REASON_FLASH_ERASE_FAILED  0x03
#define NACK_REASON_FLASH_WRITE_FAILED  0x04
#define NACK_REASON_SHA256_MISMATCH     0x05
#define NACK_REASON_BAD_ADDRESS         0x06
#define NACK_REASON_BAD_PATCH_MAGIC     0x07
#define NACK_REASON_RECONSTRUCT_FAILED  0x08
#define NACK_REASON_INVALID_STACK_PTR   0x09


#define CMD_BANK_QUERY    0xD0
#define CMD_BANK_RESPONSE 0xD1

/* Must match server.py's DEFAULT_DEVICE_ID / the device_id
   post_device_status() falls back to when none is given, so the bank
   status we post here lands on the same device record the upload
   endpoint's get_active_bank_for_device() reads back. */
#define DEVICE_ID "STM32_F411RE_001"

/* Server endpoint for posting device status. OTA_SERVER_HOST/PORT come
   from config.h (same host:port used for version/delta/full-firmware
   requests elsewhere in this file). */
#define OTA_DEVICE_STATUS_URL "/api/device/status"

const char* nackReasonToString(uint8_t reason) {
    switch (reason) {
        case NACK_REASON_CHECKSUM_MISMATCH:  return "Checksum mismatch (packet corrupted in transit)";
        case NACK_REASON_SEQUENCE_ERROR:     return "Chunk sequence error (out-of-order or dropped chunk)";
        case NACK_REASON_FLASH_ERASE_FAILED: return "Flash erase failed on STM32";
        case NACK_REASON_FLASH_WRITE_FAILED: return "Flash write failed on STM32";
        case NACK_REASON_SHA256_MISMATCH:    return "SHA-256 mismatch (image corrupted or verification failed)";
        case NACK_REASON_BAD_ADDRESS:        return "Firmware built for wrong bank address (linker origin mismatch)";
        case NACK_REASON_BAD_PATCH_MAGIC:    return "Delta patch header invalid (bad magic)";
        case NACK_REASON_RECONSTRUCT_FAILED: return "Delta reconstruction failed";
        case NACK_REASON_INVALID_STACK_PTR:  return "Invalid stack pointer in received image";
        case NACK_REASON_NONE:               return "No reason given";
        default:                             return "Unknown reason code";
    }
}

// ─────────────────────────────────────────────
// Global Variables
// ─────────────────────────────────────────────

HardwareSerial STM32Serial(2);  // UART2 for STM32 communication

String currentDeviceVersion = "1.0.0";
String currentActiveBank = "UNKNOWN";
bool otaInProgress = false;
unsigned long lastCheckTime = 0;

uint32_t totalBytesSent = 0;
uint32_t totalChunks = 0;
uint32_t failedChunks = 0;


// ─────────────────────────────────────────────
// Setup
// ─────────────────────────────────────────────

void querySTM32Bank();
bool waitForSTM32Ready(unsigned long timeoutMs);
void postDeviceStatusToServer(const char* activeBankShort, const char* versionA,
                               const char* versionB, uint32_t sizeA, uint32_t sizeB);

void setup() {
    DEBUG_SERIAL.begin(DEBUG_BAUD);
    delay(1000);

    DBG_PRINTLN("\n========================================");
    DBG_PRINTLN("  ESP32 OTA WiFi Bridge");
    DBG_PRINTLN("  CDAC ACTS DESD Project");
    DBG_PRINTLN("========================================\n");

    pinMode(LED_WIFI, OUTPUT);
    pinMode(LED_OTA_ACTIVE, OUTPUT);
    digitalWrite(LED_WIFI, LOW);
    digitalWrite(LED_OTA_ACTIVE, LOW);

    STM32Serial.begin(STM32_UART_BAUD, SERIAL_8N1, STM32_UART_RX, STM32_UART_TX);
    DBG_PRINTF("[UART] Initialized: %d baud, TX=GPIO%d, RX=GPIO%d\n",
               STM32_UART_BAUD, STM32_UART_TX, STM32_UART_RX);

    connectWiFi();
    querySTM32Version();
    querySTM32Bank();

    DBG_PRINTLN("[INIT] Setup complete. Entering main loop.\n");
}


// ─────────────────────────────────────────────
// Main Loop
// ─────────────────────────────────────────────

void loop() {
    if (WiFi.status() != WL_CONNECTED) {
        DBG_PRINTLN("[WIFI] Connection lost! Reconnecting...");
        digitalWrite(LED_WIFI, LOW);
        connectWiFi();
    }

    if (!otaInProgress && (millis() - lastCheckTime > OTA_CHECK_INTERVAL)) {
        lastCheckTime = millis();
        checkForUpdates();
    }

    handleSTM32Messages();

    delay(100);
}


// ─────────────────────────────────────────────
// WiFi Management
// ─────────────────────────────────────────────

void connectWiFi() {
    DBG_PRINTF("[WIFI] Connecting to: %s", WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long startTime = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - startTime > WIFI_CONNECT_TIMEOUT) {
            DBG_PRINTLN("\n[WIFI] Connection timeout! Retrying...");
            WiFi.disconnect();
            delay(1000);
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            startTime = millis();
        }
        DBG_PRINT(".");
        digitalWrite(LED_WIFI, !digitalRead(LED_WIFI));
        delay(500);
    }

    digitalWrite(LED_WIFI, HIGH);
    DBG_PRINTLN();
    DBG_PRINTF("[WIFI] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
    DBG_PRINTF("[WIFI] Signal strength: %d dBm\n", WiFi.RSSI());
}


// ─────────────────────────────────────────────
// Server Communication
// ─────────────────────────────────────────────

void checkForUpdates() {
    DBG_PRINTLN("[OTA] Checking server for updates...");

    HTTPClient http;
    String url = String("http://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + OTA_VERSION_URL + "?bank=" + currentActiveBank;

    http.begin(url);
    int httpCode = http.GET();

    if (httpCode == HTTP_CODE_OK) {
        String payload = http.getString();
        DBG_PRINTF("[OTA] Server response: %s\n", payload.c_str());

        /* Skip past the available_versions array before searching, so we
           land on the top-level version/sha256/size fields rather than
           the first (possibly older) entry inside the array. */
        int searchFrom = 0;
        int arrayKeyIdx = payload.indexOf("\"available_versions\"");
        if (arrayKeyIdx != -1) {
            int arrayEndIdx = payload.indexOf(']', arrayKeyIdx);
            if (arrayEndIdx != -1) {
                searchFrom = arrayEndIdx + 1;
            }
        }
        String topLevelPayload = payload.substring(searchFrom);

        String serverVersion = parseJsonString(topLevelPayload, "version");
        String serverHash = parseJsonString(topLevelPayload, "sha256");
        int serverSize = parseJsonInt(topLevelPayload, "size");

        DBG_PRINTF("[OTA] Server version: %s, Device version: %s\n",
                   serverVersion.c_str(), currentDeviceVersion.c_str());

        if (serverVersion.length() > 0 && serverVersion != currentDeviceVersion) {
            DBG_PRINTLN("[OTA] *** New firmware available! Starting update... ***");
            startOTAUpdate(serverVersion, serverHash, serverSize);
        } else {
            DBG_PRINTLN("[OTA] Firmware is up to date.");
        }
    } else {
        DBG_PRINTF("[OTA] Server check failed, HTTP code: %d\n", httpCode);
    }

    http.end();
}


void startOTAUpdate(String newVersion, String expectedHash, int fwSize) {
    otaInProgress = true;
    digitalWrite(LED_OTA_ACTIVE, HIGH);
    totalBytesSent = 0;
    totalChunks = 0;
    failedChunks = 0;

    DBG_PRINTF("\n[OTA] === Update available: v%s ===\n", newVersion.c_str());
    DBG_PRINTF("[OTA] Current version: v%s\n", currentDeviceVersion.c_str());
    DBG_PRINTLN("[OTA] Downloading update...");

    bool success = downloadAndSendDelta(newVersion);

    if (!success) {
        DBG_PRINTLN("[OTA] Delta unavailable, downloading full update instead...");
        success = downloadAndSendFull(newVersion);
    }

    if (success) {
        DBG_PRINTLN("[OTA] Installing update...");
        DBG_PRINTLN("[OTA] Update installed successfully. Device is restarting...");
        DBG_PRINTF("[OTA] (%u bytes transferred in %u chunks, %u retried)\n",
                   totalBytesSent, totalChunks, failedChunks);
        currentDeviceVersion = newVersion;

        /* Give the STM32 a moment to actually begin its reset before we
           start probing - the flash write + reboot sequence doesn't
           happen instantaneously right after the END_OTA ACK is sent. */
        delay(500);

        if (waitForSTM32Ready(10000)) {
            /* Reboot confirmed complete - safe to query the bank now.
               querySTM32Bank() also posts the result to the server, so
               the server's record of the active bank is refreshed
               immediately after every successful update. */
            querySTM32Bank();
        } else {
            DBG_PRINTLN("[OTA] STM32 never came back after update - active bank unknown");
            currentActiveBank = "UNKNOWN";
        }
    } else {
        DBG_PRINTLN("[OTA] Update failed - keeping current version.");
        sendCommandToSTM32(CMD_ABORT);
    }

    otaInProgress = false;
    digitalWrite(LED_OTA_ACTIVE, LOW);
}


bool downloadAndSendDelta(String targetVersion) {
    DBG_PRINTLN("[OTA] Requesting delta patch from server...");

    HTTPClient http;
    String url = String("http://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + OTA_DELTA_URL;

    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    String body = "{\"current_version\":\"" + currentDeviceVersion +
                  "\",\"target_version\":\"" + targetVersion + "\"}";

    int httpCode = http.POST(body);

    if (httpCode == HTTP_CODE_OK) {
        int contentLength = http.getSize();
        DBG_PRINTF("[OTA] Delta patch size: %d bytes\n", contentLength);

        if (!sendStartOTA(contentLength, true)) {
            http.end();
            return false;
        }

        WiFiClient* stream = http.getStreamPtr();
        bool success = streamToSTM32(stream, contentLength);

        http.end();

        if (success) {
            return sendEndOTA();
        }
    } else {
        DBG_PRINTF("[OTA] Delta request failed: %d\n", httpCode);
    }

    http.end();
    return false;
}


bool downloadAndSendFull(String targetVersion) {
    DBG_PRINTLN("[OTA] Downloading full firmware...");

    HTTPClient http;
    String url = String("http://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + OTA_FULL_FW_URL;

    http.begin(url);
    int httpCode = http.GET();

    if (httpCode == HTTP_CODE_OK) {
        int contentLength = http.getSize();
        DBG_PRINTF("[OTA] Full firmware size: %d bytes\n", contentLength);

        if (!sendStartOTA(contentLength, false)) {
            http.end();
            return false;
        }

        WiFiClient* stream = http.getStreamPtr();
        bool success = streamToSTM32(stream, contentLength);

        http.end();

        if (success) {
            return sendEndOTA();
        }
    } else {
        DBG_PRINTF("[OTA] Full download failed: %d\n", httpCode);
    }

    http.end();
    return false;
}


// ─────────────────────────────────────────────
// UART Transfer Protocol
// ─────────────────────────────────────────────

bool sendStartOTA(uint32_t totalSize, bool isDelta) {
    uint8_t packet[7];
    packet[0] = CMD_START_OTA;
    packet[1] = isDelta ? 0x01 : 0x00;
    packet[2] = (totalSize >> 0)  & 0xFF;
    packet[3] = (totalSize >> 8)  & 0xFF;
    packet[4] = (totalSize >> 16) & 0xFF;
    packet[5] = (totalSize >> 24) & 0xFF;
    packet[6] = computeChecksum(packet, 6);

    DBG_PRINTF("[UART] Sending START_OTA: size=%u, delta=%d\n", totalSize, isDelta);
    STM32Serial.write(packet, 7);
    STM32Serial.flush();

    return waitForACK("START_OTA");
}


void printProgressBar(uint32_t sent, uint32_t total) {
    const int barWidth = 20;
    int percent = (total > 0) ? (int)((sent * 100) / total) : 0;
    int filled = (percent * barWidth) / 100;

    DBG_PRINT("\r[OTA] [");
    for (int i = 0; i < barWidth; i++) {
        DBG_PRINT(i < filled ? "#" : "-");
    }
    DBG_PRINTF("] %3d%% (%u/%u bytes)\n  ", percent, sent, total);
}


bool streamToSTM32(WiFiClient* stream, int totalSize) {
    uint8_t buffer[CHUNK_SIZE];
    int remaining = totalSize;
    int chunkIndex = 0;

    /* Keep reading as long as data is expected AND either the socket is
       still connected OR there's buffered data waiting - connected()
       can flip false slightly before the last bytes are actually
       drained, which used to silently drop the final chunk. */
    while (remaining > 0 && (stream->connected() || stream->available())) {
        int toRead = min(remaining, (int)CHUNK_SIZE);
        int bytesRead = 0;

        unsigned long readStart = millis();
        while (bytesRead < toRead && (millis() - readStart < 10000)) {
            if (stream->available()) {
                int r = stream->read(buffer + bytesRead, toRead - bytesRead);
                if (r > 0) bytesRead += r;
            }
            delay(1);
        }

        if (bytesRead == 0) {
            DBG_PRINTLN("\n[OTA] Stream read timeout!");
            return false;
        }

        bool chunkSent = false;
        for (int retry = 0; retry < MAX_RETRIES; retry++) {
            if (sendChunkToSTM32(buffer, bytesRead, chunkIndex)) {
                chunkSent = true;
                break;
            }
            DBG_PRINTF("[UART] Chunk %d retry %d/%d\n", chunkIndex, retry + 1, MAX_RETRIES);
            failedChunks++;
        }

        if (!chunkSent) {
            DBG_PRINTF("[UART] Chunk %d failed after %d retries!\n", chunkIndex, MAX_RETRIES);
            return false;
        }

        remaining -= bytesRead;
        totalBytesSent += bytesRead;
        totalChunks++;
        chunkIndex++;

        printProgressBar(totalSize - remaining, totalSize);

        delay(INTER_CHUNK_DELAY);
    }

    DBG_PRINTLN();
    return remaining == 0;
}


bool sendChunkToSTM32(uint8_t* data, int length, int chunkIndex) {
    STM32Serial.write(CMD_CHUNK_DATA);
    STM32Serial.write((uint8_t)(chunkIndex & 0xFF));
    STM32Serial.write((uint8_t)((chunkIndex >> 8) & 0xFF));
    STM32Serial.write((uint8_t)(length & 0xFF));
    STM32Serial.write((uint8_t)((length >> 8) & 0xFF));

    STM32Serial.write(data, length);

    uint8_t checksum = CMD_CHUNK_DATA;
    checksum ^= (chunkIndex & 0xFF);
    checksum ^= ((chunkIndex >> 8) & 0xFF);
    checksum ^= (length & 0xFF);
    checksum ^= ((length >> 8) & 0xFF);
    for (int i = 0; i < length; i++) {
        checksum ^= data[i];
    }
    STM32Serial.write(checksum);
    STM32Serial.flush();

    return waitForACK("CHUNK");
}


bool sendEndOTA() {
    uint8_t packet[2];
    packet[0] = CMD_END_OTA;
    packet[1] = CMD_END_OTA;

    DBG_PRINTLN("[UART] Sending END_OTA");
    STM32Serial.write(packet, 2);
    STM32Serial.flush();

    return waitForACK("END_OTA");
}


void sendCommandToSTM32(uint8_t cmd) {
    STM32Serial.write(cmd);
    STM32Serial.flush();
}


/* NACK now carries a reason byte immediately after it. When a NACK is
   seen, this reads that second byte (waiting briefly if it hasn't
   arrived yet) and prints a human-readable reason - this is what makes
   a SHA-256 mismatch (or any other failure) visible on the serial
   monitor instead of a bare "NACK received". */
bool waitForACK(const char* context) {
    unsigned long startTime = millis();

    while (millis() - startTime < ACK_TIMEOUT) {
        if (STM32Serial.available()) {
            uint8_t response = STM32Serial.read();

            if (response == CMD_ACK) {
                return true;

            } else if (response == CMD_NACK) {
                /* Reason byte should arrive right behind CMD_NACK - give
                   it a short window in case it's still in flight. */
                unsigned long reasonWaitStart = millis();
                uint8_t reason = NACK_REASON_NONE;
                bool gotReason = false;

                while (millis() - reasonWaitStart < 200) {
                    if (STM32Serial.available()) {
                        reason = STM32Serial.read();
                        gotReason = true;
                        break;
                    }
                    delay(1);
                }

                if (gotReason) {
                    DBG_PRINTF("[UART] NACK received for %s - reason: %s (0x%02X)\n",
                               context, nackReasonToString(reason), reason);
                } else {
                    DBG_PRINTF("[UART] NACK received for %s - no reason byte arrived\n", context);
                }
                return false;
            }
        }
        delay(1);
    }

    DBG_PRINTF("[UART] ACK timeout for %s\n", context);
    return false;
}


uint8_t computeChecksum(uint8_t* data, int length) {
    uint8_t checksum = 0;
    for (int i = 0; i < length; i++) {
        checksum ^= data[i];
    }
    return checksum;
}


// ─────────────────────────────────────────────
// STM32 Communication
// ─────────────────────────────────────────────

void querySTM32Version() {
    DBG_PRINTLN("[UART] Querying STM32 firmware version...");

    sendCommandToSTM32(CMD_VERSION_REQ);

    unsigned long startTime = millis();
    String version = "";

    while (millis() - startTime < 3000) {
        if (STM32Serial.available()) {
            uint8_t b = STM32Serial.read();
            if (b == CMD_VERSION_RESP) {
                while (millis() - startTime < 3000) {
                    if (STM32Serial.available()) {
                        char c = STM32Serial.read();
                        if (c == '\0') break;
                        version += c;
                    }
                }
                break;
            }
        }
        delay(10);
    }

    if (version.length() > 0) {
        currentDeviceVersion = version;
        DBG_PRINTF("[UART] STM32 firmware version: %s\n", currentDeviceVersion.c_str());
    } else {
        DBG_PRINTLN("[UART] No version response from STM32, using default");
    }
}


/* Blocks until the STM32 responds to a lightweight probe (version
   request) or timeoutMs elapses - used after triggering a reboot (OTA
   install, or any other STM32-side reset) so we don't query the bank
   while the MCU is still mid-boot and its UART peripheral isn't
   initialized/listening yet.

   Uses CMD_VERSION_REQ as the probe rather than CMD_BANK_QUERY itself:
   it's a much shorter round-trip (the bank query's success response is
   44 bytes; version's is just a few), so polling with it wastes less
   time per attempt while a boot is still in progress. Once a probe gets
   ANY reply within its own short window, the STM32 is considered booted
   and ready for the real bank query.

   Returns true if the STM32 responded before timeoutMs elapsed, false
   if it never did (caller should treat the bank as UNKNOWN, same as any
   other bank-query failure). */
bool waitForSTM32Ready(unsigned long timeoutMs) {
    DBG_PRINTLN("[UART] Waiting for STM32 to finish rebooting...");

    unsigned long start = millis();
    const unsigned long PROBE_INTERVAL_MS = 300;
    const unsigned long PROBE_RESPONSE_WINDOW_MS = 250;

    while (millis() - start < timeoutMs) {
        /* Flush anything stale sitting in the RX buffer before each
           probe, so a leftover byte from before the reboot can't be
           mistaken for a fresh response. */
        while (STM32Serial.available()) STM32Serial.read();

        STM32Serial.write(CMD_VERSION_REQ);
        STM32Serial.flush();

        unsigned long probeStart = millis();
        while (millis() - probeStart < PROBE_RESPONSE_WINDOW_MS) {
            if (STM32Serial.available()) {
                /* Got SOMETHING back - the UART peripheral is alive and
                   the app/bootloader is running its main loop. Drain the
                   rest of this response so it doesn't pollute the real
                   bank query that follows. */
                delay(20);  /* let the rest of the response land */
                while (STM32Serial.available()) STM32Serial.read();

                unsigned long elapsed = millis() - start;
                DBG_PRINTF("[UART] STM32 responded after %lums - ready\n", elapsed);
                return true;
            }
            delay(5);
        }

        delay(PROBE_INTERVAL_MS);
    }

    DBG_PRINTF("[UART] STM32 did not respond within %lums - giving up\n", timeoutMs);
    return false;
}


void querySTM32Bank()
{
    DBG_PRINTLN("[UART] Querying STM32 active bank...");

    while(STM32Serial.available())
        STM32Serial.read();

    STM32Serial.write(CMD_BANK_QUERY);
    STM32Serial.flush();

    const uint8_t BANK_RESPONSE_SIZE = 44;

    uint8_t resp[BANK_RESPONSE_SIZE];

    unsigned long start = millis();
    int index = 0;

    while(index < BANK_RESPONSE_SIZE && millis() - start < 3000)
    {
        if(STM32Serial.available())
        {
            resp[index++] = STM32Serial.read();
        }
    }

    if(index != BANK_RESPONSE_SIZE)
    {
        DBG_PRINTLN("[UART] Bank query timeout");
        currentActiveBank = "UNKNOWN";
        return;
    }

    if(resp[0] != CMD_BANK_RESPONSE)
    {
        DBG_PRINTF("[UART] Invalid response 0x%02X\n", resp[0]);
        currentActiveBank = "UNKNOWN";
        return;
    }

    uint8_t active = resp[1];

    if(active==0)
        currentActiveBank="BANK_A";
    else if(active==1)
        currentActiveBank="BANK_B";
    else
        currentActiveBank="UNKNOWN";

    char versionA[17];
    char versionB[17];

    memcpy(versionA,&resp[2],16);
    memcpy(versionB,&resp[18],16);

    versionA[16]=0;
    versionB[16]=0;

    uint32_t sizeA;
    uint32_t sizeB;

    memcpy(&sizeA,&resp[34],4);
    memcpy(&sizeB,&resp[38],4);

    uint8_t flags=resp[42];
    uint8_t valid=resp[43];

    DBG_PRINTF("[UART] Active Bank: %s\n",currentActiveBank.c_str());

    /* Push this to the server so get_active_bank_for_device() on the
       upload endpoint has an up-to-date record to check new uploads
       against. Server expects "A"/"B" (short form) for active_bank -
       NOT the "BANK_A"/"BANK_B" strings used for local logging above -
       since that's what it compares directly against target_bank
       (also "A"/"B") from validate_firmware_bytes(). Skip the POST
       entirely if the bank came back UNKNOWN - posting an unknown bank
       would let a same-bank upload slip through undetected, which is
       worse than just leaving the server's last-known value in place. */
    if (active == 0 || active == 1) {
        const char* activeBankShort = (active == 0) ? "A" : "B";
        postDeviceStatusToServer(activeBankShort, versionA, versionB, sizeA, sizeB);
    } else {
        DBG_PRINTLN("[UART] Active bank unknown - skipping server status update");
    }
}


/* POSTs the device's current bank status to /api/device/status so the
   server's device_status.json stays in sync with reality. This is what
   server.py's get_active_bank_for_device() reads back inside
   upload_firmware() to reject a same-bank upload - without this POST
   ever happening, that check always sees "no status reported yet" and
   silently allows any upload through regardless of which bank it
   targets. */
void postDeviceStatusToServer(const char* activeBankShort, const char* versionA,
                               const char* versionB, uint32_t sizeA, uint32_t sizeB) {
    if (WiFi.status() != WL_CONNECTED) {
        DBG_PRINTLN("[HTTP] Skipping device status POST - WiFi not connected");
        return;
    }

    HTTPClient http;
    String url = String("http://") + OTA_SERVER_HOST + ":" + OTA_SERVER_PORT + OTA_DEVICE_STATUS_URL;

    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    String body = String("{") +
        "\"device_id\":\"" + DEVICE_ID + "\"," +
        "\"active_bank\":\"" + activeBankShort + "\"," +
        "\"device_version\":\"" + currentDeviceVersion + "\"," +
        "\"bank_a_version\":\"" + versionA + "\"," +
        "\"bank_b_version\":\"" + versionB + "\"," +
        "\"bank_a_size\":" + String(sizeA) + "," +
        "\"bank_b_size\":" + String(sizeB) +
        "}";

    int httpCode = http.POST(body);

    if (httpCode == HTTP_CODE_OK) {
        DBG_PRINTF("[HTTP] Device status posted - active_bank=%s\n", activeBankShort);
    } else {
        DBG_PRINTF("[HTTP] Device status POST failed, HTTP code: %d\n", httpCode);
    }

    http.end();
}


void handleSTM32Messages() {
    while (STM32Serial.available()) {
        uint8_t byte = STM32Serial.read();
        DBG_PRINTF("[UART] Received from STM32 (unsolicited): 0x%02X\n", byte);
    }
}


// ─────────────────────────────────────────────
// JSON Parsing Helpers (lightweight, no library)
// ─────────────────────────────────────────────

String parseJsonString(String json, String key) {
    String searchKey = "\"" + key + "\":\"";
    int startIdx = json.indexOf(searchKey);
    if (startIdx == -1) {
        searchKey = "\"" + key + "\": \"";
        startIdx = json.indexOf(searchKey);
    }
    if (startIdx == -1) return "";

    startIdx += searchKey.length();
    int endIdx = json.indexOf("\"", startIdx);
    if (endIdx == -1) return "";

    return json.substring(startIdx, endIdx);
}


int parseJsonInt(String json, String key) {
    String searchKey = "\"" + key + "\":";
    int startIdx = json.indexOf(searchKey);
    if (startIdx == -1) {
        searchKey = "\"" + key + "\": ";
        startIdx = json.indexOf(searchKey);
    }
    if (startIdx == -1) return 0;

    startIdx += searchKey.length();
    while (startIdx < (int)json.length() && json.charAt(startIdx) == ' ') startIdx++;

    String numStr = "";
    while (startIdx < (int)json.length() && json.charAt(startIdx) >= '0' && json.charAt(startIdx) <= '9') {
        numStr += json.charAt(startIdx);
        startIdx++;
    }

    return numStr.toInt();
}
