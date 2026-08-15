#include "ota_receiver.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>

/* ─────────────────────────────────────────────
 * OTA capability marker (NEW)
 * ─────────────────────────────────────────────
 * The Flask server's validate_firmware_bytes() scans uploaded firmware
 * bytes for this exact string after vector-table checks pass, as a
 * (non-airtight) proxy for "this build actually compiled in the OTA
 * receiver code." It only needs to exist as a compiled string constant
 * somewhere in the final .bin - nothing else in this file references it.
 * Keep the string identical to OTA_CAPABILITY_MARKER in server.py.
 * ───────────────────────────────────────────── */
const char OTA_CAPABLE_TAG[] __attribute__((section(".ota_marker"), used)) = "OTA_CAPABLE_V1";

/* ─────────────────────────────────────────────
 * Private Variables
 * ───────────────────────────────────────────── */

static UART_HandleTypeDef *otaUart;
static OTA_Context_t otaCtx;

/* Receive buffer (circular) */
static uint8_t rxBuffer[OTA_RX_BUFFER_SIZE];
static volatile uint16_t rxHead = 0;
static volatile uint16_t rxTail = 0;

/* Temporary storage for incoming data */
static uint8_t chunkBuffer[PAGE_SIZE + 64];  /* Chunk data + header overhead */
static uint32_t chunkBufferLen = 0;

/* Full firmware buffer for delta reconstruction */
static uint8_t pageBuffer[PAGE_SIZE];


/* ─────────────────────────────────────────────
 * OTA Initialization
 * ───────────────────────────────────────────── */

void OTA_Init(UART_HandleTypeDef *huart) {
    otaUart = huart;

    memset(&otaCtx, 0, sizeof(OTA_Context_t));
    otaCtx.state = OTA_STATE_IDLE;

    FirmwareMetadata_t meta;
    memcpy(&meta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));

    if (meta.magic == METADATA_MAGIC) {
        otaCtx.inactiveBankAddr = (meta.active_bank == BANK_A) ? APP_BANK_B_START : APP_BANK_A_START;
    } else {
        otaCtx.inactiveBankAddr = APP_BANK_B_START;
    }

    HAL_UART_Receive_IT(otaUart, &rxBuffer[rxHead], 1);
}


/* ─────────────────────────────────────────────
 * Main OTA Processing Loop
 * ───────────────────────────────────────────── */

void OTA_Process(void) {
    while (rxTail != rxHead) {
        uint8_t byte = rxBuffer[rxTail];
        rxTail = (rxTail + 1) % OTA_RX_BUFFER_SIZE;

        switch (otaCtx.state) {
            case OTA_STATE_IDLE:
                if (byte == CMD_START_OTA) {
                    chunkBuffer[0] = byte;
                    chunkBufferLen = 1;
                    otaCtx.state = OTA_STATE_RECEIVING;
                }
                else if (byte == CMD_VERSION_REQ) {
                    OTA_SendVersion();
                }
                else if (byte == CMD_BANK_QUERY) {
                    /* NEW: host asked which bank is active - answer
                       straight from flash metadata, no OTA session
                       needed. Only handled from IDLE on purpose: a bank
                       query mid-transfer would be ambiguous (is the
                       host asking about the bank we're currently
                       writing into, or the one that's still bootable?)
                       so it's simplest to just not answer until any
                       in-progress transfer finishes or is aborted. */
                    OTA_HandleBankQuery();
                }
                break;

            case OTA_STATE_RECEIVING:
                chunkBuffer[chunkBufferLen++] = byte;

                if (chunkBuffer[0] == CMD_START_OTA && chunkBufferLen == 7) {
                    OTA_HandleStartCommand(chunkBuffer, chunkBufferLen);
                    chunkBufferLen = 0;
                }
                else if (chunkBuffer[0] == CMD_CHUNK_DATA && chunkBufferLen >= 5) {
                    uint16_t dataLen = chunkBuffer[3] | (chunkBuffer[4] << 8);
                    uint16_t totalPacketLen = 5 + dataLen + 1;

                    if (chunkBufferLen == totalPacketLen) {
                        OTA_HandleChunkData(chunkBuffer, chunkBufferLen);
                        chunkBufferLen = 0;
                    }
                }
                else if (byte == CMD_END_OTA && chunkBufferLen <= 2) {
                    OTA_HandleEndCommand();
                    chunkBufferLen = 0;
                }
                else if (byte == CMD_ABORT) {
                    otaCtx.state = OTA_STATE_IDLE;
                    chunkBufferLen = 0;
                    LED_BlinkError(2);  /* short blink = OTA aborted */
                }

                if (chunkBufferLen >= sizeof(chunkBuffer)) {
                    chunkBufferLen = 0;
                }
                break;

            case OTA_STATE_ERROR:
                /* Dead code now that every failure branch below resets
                   straight to OTA_STATE_IDLE instead of parking here -
                   kept only so the enum/switch stays exhaustive. */
                if (byte == CMD_START_OTA) {
                    chunkBuffer[0] = byte;
                    chunkBufferLen = 1;
                    otaCtx.state = OTA_STATE_RECEIVING;
                }
                break;

            default:
                break;
        }
    }
}


OTA_State_t OTA_GetState(void) {
    return otaCtx.state;
}


/* ─────────────────────────────────────────────
 * Protocol Command Handlers
 * ───────────────────────────────────────────── */

void OTA_HandleStartCommand(uint8_t *data, uint16_t len) {
    uint8_t checksum = 0;
    for (int i = 0; i < len - 1; i++) {
        checksum ^= data[i];
    }
    if (checksum != data[len - 1]) {
        OTA_SendNACK(NACK_REASON_CHECKSUM_MISMATCH);
        return;
    }

    otaCtx.isDelta = data[1];
    otaCtx.totalSize = data[2] | (data[3] << 8) | (data[4] << 16) | (data[5] << 24);
    otaCtx.receivedSize = 0;
    otaCtx.expectedChunk = 0;
    otaCtx.writeAddress = otaCtx.inactiveBankAddr;

    if (OTA_EraseInactiveBank() != HAL_OK) {
        otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
        OTA_SendNACK(NACK_REASON_FLASH_ERASE_FAILED);
        return;
    }

    otaCtx.state = OTA_STATE_RECEIVING;
    OTA_SendACK();

    /* FIX: was HAL_GPIO_WritePin(LED_PORT, LED_ORANGE, GPIO_PIN_SET) -
       LED_ORANGE no longer exists. Single LED: solid on = "transfer in
       progress". */
    LED_SetStatus(LED_PIN, 1);
}


void OTA_HandleChunkData(uint8_t *data, uint16_t len) {
    uint8_t checksum = 0;
    for (int i = 0; i < len - 1; i++) {
        checksum ^= data[i];
    }
    if (checksum != data[len - 1]) {
        OTA_SendNACK(NACK_REASON_CHECKSUM_MISMATCH);
        return;
    }

    uint16_t chunkIndex = data[1] | (data[2] << 8);
    uint16_t dataLen = data[3] | (data[4] << 8);
    uint8_t *chunkData = &data[5];

    if (chunkIndex != otaCtx.expectedChunk) {
        OTA_SendNACK(NACK_REASON_SEQUENCE_ERROR);
        return;
    }

    if (OTA_WriteToFlash(otaCtx.writeAddress, chunkData, dataLen) != HAL_OK) {
        otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
        OTA_SendNACK(NACK_REASON_FLASH_WRITE_FAILED);
        return;
    }

    otaCtx.writeAddress += dataLen;
    otaCtx.receivedSize += dataLen;
    otaCtx.expectedChunk++;

    /* FIX: was HAL_GPIO_TogglePin(LED_PORT, LED_BLUE) - LED_BLUE no
       longer exists. Toggle the single LED as a per-chunk heartbeat. */
    HAL_GPIO_TogglePin(LED_PORT, LED_PIN);

    OTA_SendACK();
}


void OTA_HandleEndCommand(void) {
    otaCtx.state = OTA_STATE_VERIFYING;

    /* FIX: was HAL_GPIO_WritePin(LED_PORT, LED_ORANGE, GPIO_PIN_RESET) -
       clear the "transfer in progress" indicator on the single LED. */
    LED_SetStatus(LED_PIN, 0);

    if (otaCtx.isDelta) {
        /* Delta mode: reconstruct full firmware from patch */
        PatchHeader_t patchHdr;
        memcpy(&patchHdr, (void *)otaCtx.inactiveBankAddr, sizeof(PatchHeader_t));

        if (patchHdr.magic != PATCH_MAGIC) {
            otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
            LED_BlinkError(5);
            OTA_SendNACK(NACK_REASON_BAD_PATCH_MAGIC);
            return;
        }

        uint8_t expectedHash[32];
        uint32_t hashOffset = otaCtx.inactiveBankAddr + otaCtx.receivedSize - 32;
        memcpy(expectedHash, (void *)hashOffset, 32);

        /*
         * NOTE: full delta reconstruction is not implemented in this
         * demo - see the original file header for what a real
         * implementation would do. We fall straight through to marking
         * the bootloader-side hash pending, same as before.
         */

        /* NEW: reject if the image's own vector table doesn't belong to
           the bank we just wrote it into - catches a wrong-linker-origin
           build before it's ever marked bootable. */
        if (!OTA_ValidateFirmwareAddress(otaCtx.inactiveBankAddr, APP_BANK_SIZE_BYTES)) {
            otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
            LED_BlinkError(4);  /* 4 blinks = address validation failed (distinct from 5 = SHA mismatch) */
            OTA_SendNACK(NACK_REASON_BAD_ADDRESS);
            return;
        }

        OTA_SetUpdatePending(expectedHash, patchHdr.newFirmwareSize, "");

        /* NEW: verify metadata was written correctly before rebooting */
        FirmwareMetadata_t verifyMeta;
        memcpy(&verifyMeta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));
        uint32_t storedCRC = verifyMeta.crc32;
        verifyMeta.crc32 = 0;
        uint32_t computedCRC = OTA_ComputeMetadataCRC32(&verifyMeta);

        if (computedCRC != storedCRC) {
            /* metadata write failed - don't reboot into broken state */
            otaCtx.state = OTA_STATE_IDLE;
            LED_BlinkError(7);  /* 7 blinks = metadata write failed */
            OTA_SendNACK(NACK_REASON_FLASH_WRITE_FAILED);
            return;
        }

        OTA_SendACK();

        otaCtx.state = OTA_STATE_COMPLETE;

        /* FIX: was HAL_GPIO_WritePin(LED_PORT, LED_GREEN, GPIO_PIN_SET) -
           single LED, solid on = "update accepted, about to reboot". */
        LED_SetStatus(LED_PIN, 1);

        HAL_Delay(2000);  /* increased from 1000 - give flash write more time to settle */
        OTA_TriggerReboot();

    } else {
        /* Full firmware mode: verify what we wrote */
        uint32_t fwSize = otaCtx.receivedSize - 32;
        uint8_t expectedHash[32];
        memcpy(expectedHash,
               (void *)(otaCtx.inactiveBankAddr + fwSize),
               32);

        if (OTA_VerifyFirmware(otaCtx.inactiveBankAddr, fwSize, expectedHash)) {
            /* SHA-256 PASSED - now check the address before trusting it */
            if (!OTA_ValidateFirmwareAddress(otaCtx.inactiveBankAddr, APP_BANK_SIZE_BYTES)) {
                otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
                LED_BlinkError(4);  /* 4 blinks = address validation failed */
                OTA_SendNACK(NACK_REASON_BAD_ADDRESS);
                return;
            }

            OTA_SetUpdatePending(expectedHash, fwSize, "");

            /* NEW: verify metadata was written correctly before rebooting */
            FirmwareMetadata_t verifyMeta;
            memcpy(&verifyMeta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));
            uint32_t storedCRC = verifyMeta.crc32;
            verifyMeta.crc32 = 0;
            uint32_t computedCRC = OTA_ComputeMetadataCRC32(&verifyMeta);

            if (computedCRC != storedCRC) {
                /* metadata write failed - don't reboot into broken state */
                otaCtx.state = OTA_STATE_IDLE;
                LED_BlinkError(7);  /* 7 blinks = metadata write failed */
                OTA_SendNACK(NACK_REASON_FLASH_WRITE_FAILED);
                return;
            }

            OTA_SendACK();

            otaCtx.state = OTA_STATE_COMPLETE;

            /* FIX: was HAL_GPIO_WritePin(LED_PORT, LED_GREEN, GPIO_PIN_SET) */
            LED_SetStatus(LED_PIN, 1);

            HAL_Delay(2000);  /* increased from 1000 - give flash write more time to settle */
            OTA_TriggerReboot();
        } else {
            /* SHA-256 FAILED - this is the case you asked to see appear
               on the serial monitor. NACK_REASON_SHA256_MISMATCH gets
               sent here; the ESP32 prints it as "SHA-256 mismatch". */
            otaCtx.state = OTA_STATE_IDLE;   /* was OTA_STATE_ERROR */
            LED_BlinkError(5);  /* 5 blinks = SHA-256 verification failed */
            OTA_SendNACK(NACK_REASON_SHA256_MISMATCH);
        }
    }
}


void OTA_HandleVersionRequest(void) {
    OTA_SendVersion();
}


/* ─────────────────────────────────────────────
 * NEW: Bank Status Query
 * ─────────────────────────────────────────────
 * Answers CMD_BANK_QUERY (sent with no payload) with a fixed-length
 * packet, so a host can parse it without needing a length prefix:
 *
 *   Offset  Size  Field
 *   ------  ----  -----------------------------------------
 *   0       1     CMD_BANK_RESP (0xD1)
 *   1       1     active_bank        (0 = BANK_A, 1 = BANK_B)
 *   2       16    fw_version_a       (ASCII, NUL-padded)
 *   18      16    fw_version_b       (ASCII, NUL-padded)
 *   34      4     fw_size_a          (uint32, little-endian)
 *   38      4     fw_size_b          (uint32, little-endian)
 *   42      1     update_flags       (UpdateFlag_t bitmask, see bootloader.h)
 *   43      1     metadata_valid     (1 = magic+CRC OK, 0 = fell back to defaults)
 *   ------
 *   Total: 44 bytes
 *
 * Reads metadata fresh from flash every time rather than relying on
 * otaCtx (which only caches inactiveBankAddr at OTA_Init time) - this way
 * the answer is always current even if the bootloader updated metadata
 * on the last boot.
 * ───────────────────────────────────────────── */

void OTA_HandleBankQuery(void) {
    FirmwareMetadata_t meta;
    uint8_t metadataValid = 1;

    memcpy(&meta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));

    uint32_t storedCRC = meta.crc32;
    meta.crc32 = 0;
    uint32_t computedCRC = OTA_ComputeMetadataCRC32(&meta);
    meta.crc32 = storedCRC;

    if (meta.magic != METADATA_MAGIC || computedCRC != storedCRC) {
        /* Same fallback bootloader.c's Metadata_Init_Default() would
           produce, so a host reading this before first-ever boot still
           gets a sensible answer instead of garbage. */
        metadataValid = 0;
        memset(&meta, 0, sizeof(meta));
        meta.active_bank = BANK_A;
    }

    uint8_t resp[1 + 1 + FIRMWARE_VERSION_LEN + FIRMWARE_VERSION_LEN + 4 + 4 + 1 + 1];
    uint32_t idx = 0;

    resp[idx++] = CMD_BANK_RESP;
    resp[idx++] = (uint8_t)meta.active_bank;

    memcpy(&resp[idx], meta.fw_version_a, FIRMWARE_VERSION_LEN);
    idx += FIRMWARE_VERSION_LEN;

    memcpy(&resp[idx], meta.fw_version_b, FIRMWARE_VERSION_LEN);
    idx += FIRMWARE_VERSION_LEN;

    memcpy(&resp[idx], &meta.fw_size_a, sizeof(uint32_t));
    idx += sizeof(uint32_t);

    memcpy(&resp[idx], &meta.fw_size_b, sizeof(uint32_t));
    idx += sizeof(uint32_t);

    resp[idx++] = meta.update_flags;
    resp[idx++] = metadataValid;

    HAL_UART_Transmit(otaUart, resp, sizeof(resp), 100);
}


/* ─────────────────────────────────────────────
 * Address Validation
 * ───────────────────────────────────────────── */

uint8_t OTA_ValidateFirmwareAddress(uint32_t bankAddr, uint32_t bankSize) {
    uint32_t candidateSP = *(__IO uint32_t *)(bankAddr);
    uint32_t candidateResetHandler = *(__IO uint32_t *)(bankAddr + 4);

    if (candidateSP < SRAM_START_ADDR || candidateSP > SRAM_END_ADDR) {
        return 0;
    }

    if ((candidateResetHandler & 0x1U) == 0U) {
        return 0;
    }

    uint32_t resetAddrNoThumb = candidateResetHandler & ~0x1U;
    uint32_t bankEnd = bankAddr + bankSize;

    if (resetAddrNoThumb < bankAddr || resetAddrNoThumb >= bankEnd) {
        return 0;
    }

    return 1;
}


/* ─────────────────────────────────────────────
 * Flash Operations
 * ───────────────────────────────────────────── */

HAL_StatusTypeDef OTA_EraseInactiveBank(void) {
    HAL_StatusTypeDef status;
    FLASH_EraseInitTypeDef eraseInit;
    uint32_t sectorError = 0;

    HAL_FLASH_Unlock();

    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR |
                            FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR |
                            FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    if (otaCtx.inactiveBankAddr == APP_BANK_B_START) {
        eraseInit.Sector    = BANK_B_SECTOR_START;
        eraseInit.NbSectors = 1;
    } else {
        eraseInit.Sector    = BANK_A_SECTOR_START;
        eraseInit.NbSectors = 1;
    }

    eraseInit.TypeErase    = FLASH_TYPEERASE_SECTORS;
    eraseInit.VoltageRange = FLASH_VOLTAGE_RANGE_3;

    status = HAL_FLASHEx_Erase(&eraseInit, &sectorError);

    HAL_FLASH_Lock();

    return status;
}


HAL_StatusTypeDef OTA_WriteToFlash(uint32_t address, uint8_t *data, uint32_t size) {
    HAL_StatusTypeDef status = HAL_OK;

    HAL_FLASH_Unlock();

    for (uint32_t i = 0; i < size; i += 4) {
        uint32_t word;
        if (i + 4 <= size) {
            word = *(uint32_t *)(data + i);
        } else {
            word = 0xFFFFFFFF;
            memcpy(&word, data + i, size - i);
        }

        status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + i, word);
        if (status != HAL_OK) break;
    }

    HAL_FLASH_Lock();

    return status;
}


HAL_StatusTypeDef OTA_CopyPage(uint32_t srcAddr, uint32_t destAddr, uint32_t size) {
    memcpy(pageBuffer, (void *)srcAddr, size);
    return OTA_WriteToFlash(destAddr, pageBuffer, size);
}


/* ─────────────────────────────────────────────
 * Verification
 * ───────────────────────────────────────────── */

uint8_t OTA_VerifyFirmware(uint32_t startAddr, uint32_t size, uint8_t *expectedHash) {
    SHA256_CTX ctx;
    uint8_t computedHash[32];
    uint8_t buffer[256];

    sha256_init(&ctx);

    uint32_t remaining = size;
    uint32_t addr = startAddr;

    while (remaining > 0) {
        uint32_t chunkSize = (remaining > 256) ? 256 : remaining;
        memcpy(buffer, (void *)addr, chunkSize);
        sha256_update(&ctx, buffer, chunkSize);
        addr += chunkSize;
        remaining -= chunkSize;
    }

    sha256_final(&ctx, computedHash);

    return (memcmp(computedHash, expectedHash, 32) == 0) ? 1 : 0;
}


uint32_t OTA_ComputeMetadataCRC32(FirmwareMetadata_t *meta) {
    uint32_t crc = 0xFFFFFFFF;
    uint8_t *data = (uint8_t *)meta;
    uint32_t len = sizeof(FirmwareMetadata_t) - sizeof(uint32_t);

    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    return crc ^ 0xFFFFFFFF;
}


void OTA_SetUpdatePending(uint8_t *sha256Hash, uint32_t fwSize, const char *version) {
    (void)version;

    FirmwareMetadata_t meta;
    memcpy(&meta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));

    if (meta.magic != METADATA_MAGIC) {
        return;
    }

    meta.update_flags = FLAG_UPDATE_PENDING;

    if (meta.active_bank == BANK_A) {
        memcpy(meta.sha256_b, sha256Hash, SHA256_HASH_LEN);
        meta.fw_size_b = fwSize;
    } else {
        memcpy(meta.sha256_a, sha256Hash, SHA256_HASH_LEN);
        meta.fw_size_a = fwSize;
    }

    meta.crc32 = 0;
    meta.crc32 = OTA_ComputeMetadataCRC32(&meta);

    FLASH_EraseInitTypeDef eraseInit;
    uint32_t sectorError;

    HAL_FLASH_Unlock();

    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR |
                            FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR |
                            FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    eraseInit.TypeErase    = FLASH_TYPEERASE_SECTORS;
    eraseInit.VoltageRange = FLASH_VOLTAGE_RANGE_3;
    eraseInit.Sector       = METADATA_SECTOR;
    eraseInit.NbSectors    = 1;

    HAL_FLASHEx_Erase(&eraseInit, &sectorError);

    uint8_t *metaBytes = (uint8_t *)&meta;
    for (uint32_t i = 0; i < sizeof(FirmwareMetadata_t); i += 4) {
        uint32_t word;
        if (i + 4 <= sizeof(FirmwareMetadata_t)) {
            word = *(uint32_t *)(metaBytes + i);
        } else {
            word = 0xFFFFFFFF;
            memcpy(&word, metaBytes + i, sizeof(FirmwareMetadata_t) - i);
        }
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, METADATA_ADDR + i, word);
    }

    HAL_FLASH_Lock();
}


void OTA_TriggerReboot(void) {
    HAL_NVIC_SystemReset();
}


/* ─────────────────────────────────────────────
 * UART Communication
 * ───────────────────────────────────────────── */

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
    if (huart == otaUart) {
        OTA_UART_RxCallback();
    }
}

void OTA_UART_RxCallback(void) {
    rxHead = (rxHead + 1) % OTA_RX_BUFFER_SIZE;
    HAL_UART_Receive_IT(otaUart, &rxBuffer[rxHead], 1);
}


void OTA_SendACK(void) {
    uint8_t ack = CMD_ACK;
    HAL_UART_Transmit(otaUart, &ack, 1, 100);
}


void OTA_SendNACK(OTA_NackReason_t reason) {
    uint8_t packet[2];
    packet[0] = CMD_NACK;
    packet[1] = (uint8_t)reason;
    HAL_UART_Transmit(otaUart, packet, 2, 100);
}


void OTA_SendVersion(void) {
    uint8_t resp = CMD_VERSION_RESP;
    HAL_UART_Transmit(otaUart, &resp, 1, 100);

    const char *version = FIRMWARE_VERSION;
    HAL_UART_Transmit(otaUart, (uint8_t *)version, strlen(version) + 1, 100);
}
