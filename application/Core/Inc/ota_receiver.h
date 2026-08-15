/*
 * ota_receiver.h - STM32F411RE OTA Firmware Receiver
 *
 * CDAC ACTS PG-Diploma in DESD
 * Secure OTA Firmware Update System
 *
 * ─────────────────────────────────────────────
 * NEW IN THIS VERSION: NACK reason codes + bank-address validation
 * ─────────────────────────────────────────────
 * 1) NACK now carries a one-byte reason code after it, so the ESP32 can
 *    print WHY a transfer failed instead of just "NACK received" with no
 *    context. See OTA_NackReason_t below.
 * 2) OTA_ValidateFirmwareAddress() reads the freshly-received image's own
 *    vector table (initial SP + Reset_Handler, at offset 0 and 4 of the
 *    image) and checks that the Reset_Handler address actually falls
 *    inside the bank it was just written to. This is exactly the class
 *    of bug that caused a silent boot failure earlier in this project:
 *    a .bin built with FLASH ORIGIN = 0x08020000 (Bank A) that gets
 *    written into Bank B (0x08040000) - the SHA-256 still matches (the
 *    bytes are exactly what was uploaded), so hash verification alone
 *    can't catch it. This check runs AFTER SHA-256 passes and BEFORE
 *    OTA_SetUpdatePending() ever marks the image as bootable, so a
 *    wrong-bank image is rejected right here instead of bricking the
 *    device on the next boot.
 *
 * ─────────────────────────────────────────────
 * NEW: CMD_BANK_QUERY / CMD_BANK_RESP - direct UART bank status query
 * ─────────────────────────────────────────────
 * Previously the only way to find out which bank was currently active
 * was to ask the Flask server (which itself only knows what the device
 * last reported over the OTA link via the ESP32 bridge). This adds a
 * lightweight request/response pair that lets a host (e.g. a PC running
 * check_active_bank.py over the ST-Link Virtual COM Port, which is wired
 * to USART2 on the Nucleo-F411RE - the same UART this OTA protocol uses)
 * ask the DEVICE directly, with no ESP32/Flask hop required. See
 * OTA_HandleBankQuery() in ota_receiver.c for the wire format.
 *
 * ─────────────────────────────────────────────
 * FIX (this revision): LED macro mismatch with bootloader.h
 * ─────────────────────────────────────────────
 * bootloader.h now only defines a single physical LED (LED_GPIO_PORT /
 * LED_PIN, PA5 - the Nucleo-F411RE's only user LED, LD2). This file used
 * to redefine LED_GREEN/LED_ORANGE/LED_RED/LED_BLUE in terms of
 * LED_GREEN_PIN etc., which no longer exist anywhere and would fail to
 * compile. Replaced with a single LED_PORT/LED_PIN pair that maps onto
 * bootloader.h's macros, and event signaling now goes through
 * LED_SetStatus()/LED_BlinkPattern()/LED_BlinkError() (steady state +
 * distinct blink counts) instead of pretending there are 4 colors.
 */

#ifndef OTA_RECEIVER_H
#define OTA_RECEIVER_H

#include "stm32f4xx_hal.h"
#include "bootloader.h"     /* shares FirmwareMetadata_t + memory map with the bootloader project */
#include <stdint.h>

/* ─────────────────────────────────────────────
 * Memory Map (reused from bootloader.h - do not redefine here)
 * ───────────────────────────────────────────── */

#define BOOTLOADER_START        BOOTLOADER_START_ADDR
#define APP_BANK_A_START        APP_BANK_A_START_ADDR
#define APP_BANK_B_START        APP_BANK_B_START_ADDR
#define APP_BANK_SIZE_BYTES     APP_BANK_SIZE            /* 128KB per bank on F411 */
#define METADATA_ADDR           METADATA_START_ADDR
#define PAGE_SIZE               1024U                    /* Must match server PAGE_SIZE */

/* SRAM range used to sanity-check a candidate initial stack pointer -
   same bounds bootloader.c's IsValidStackPointer() uses. Duplicated here
   (rather than shared) since this file doesn't currently include a
   common header for it; keep both in sync if the RAM size ever changes. */
#define SRAM_START_ADDR          0x20000000U
#define SRAM_END_ADDR            0x20020000U

/* ─────────────────────────────────────────────
 * Protocol Commands (must match ESP32 config.h)
 * ───────────────────────────────────────────── */

#define CMD_START_OTA           0xAA
#define CMD_CHUNK_DATA          0xBB
#define CMD_END_OTA              0xCC
#define CMD_ACK                  0x06
#define CMD_NACK                 0x15
#define CMD_VERSION_REQ          0xDD
#define CMD_VERSION_RESP         0xEE
#define CMD_ABORT                0xFF

/* NEW: bank status query, answered directly by the device - see
   OTA_HandleBankQuery() for the fixed-length response layout. Chosen to
   not collide with any existing command byte above. */
#define CMD_BANK_QUERY            0xD0
#define CMD_BANK_RESP             0xD1

/* ─────────────────────────────────────────────
 * NACK Reason Codes (NEW)
 * ─────────────────────────────────────────────
 * Sent as a single byte immediately after CMD_NACK. The ESP32 reads this
 * byte and prints a human-readable reason to the serial monitor instead
 * of a bare "NACK received". Keep in sync with esp32_ota_bridge.ino's
 * nackReasonToString().
 * ───────────────────────────────────────────── */

typedef enum {
    NACK_REASON_NONE                = 0x00, /* unused / not applicable */
    NACK_REASON_CHECKSUM_MISMATCH   = 0x01, /* packet XOR checksum didn't match */
    NACK_REASON_SEQUENCE_ERROR      = 0x02, /* chunk index != expectedChunk */
    NACK_REASON_FLASH_ERASE_FAILED  = 0x03, /* HAL_FLASHEx_Erase failed */
    NACK_REASON_FLASH_WRITE_FAILED  = 0x04, /* HAL_FLASH_Program failed */
    NACK_REASON_SHA256_MISMATCH     = 0x05, /* computed hash != expected hash */
    NACK_REASON_BAD_ADDRESS         = 0x06, /* image's own vector table doesn't
                                                belong to the bank it was written to -
                                                the "wrong linker origin" bug */
    NACK_REASON_BAD_PATCH_MAGIC     = 0x07, /* delta patch header magic invalid */
    NACK_REASON_RECONSTRUCT_FAILED  = 0x08, /* delta reconstruction failed */
    NACK_REASON_INVALID_STACK_PTR   = 0x09, /* candidate SP outside valid SRAM range */
} OTA_NackReason_t;

/* ─────────────────────────────────────────────
 * OTA Transfer State Machine
 * ───────────────────────────────────────────── */

typedef enum {
    OTA_STATE_IDLE = 0,
    OTA_STATE_RECEIVING,
    OTA_STATE_VERIFYING,
    OTA_STATE_COMPLETE,
    OTA_STATE_ERROR
} OTA_State_t;

typedef struct {
    OTA_State_t  state;
    uint8_t      isDelta;           /* 1=delta patch, 0=full firmware */
    uint32_t     totalSize;         /* Total bytes expected */
    uint32_t     receivedSize;      /* Bytes received so far */
    uint16_t     expectedChunk;     /* Next expected chunk index */
    uint32_t     writeAddress;      /* Current flash write address */
    uint32_t     inactiveBankAddr;  /* Start of inactive bank */
} OTA_Context_t;

/* ─────────────────────────────────────────────
 * Delta Patch Header (must match server format)
 * ───────────────────────────────────────────── */

#define PATCH_MAGIC              0x4F544150U     /* "OTAP" */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t numChangedPages;
    uint32_t newFirmwareSize;
    uint16_t totalPages;
    uint16_t pageSize;
} PatchHeader_t;

/* ─────────────────────────────────────────────
 * Firmware Version
 * ───────────────────────────────────────────── */

#define FIRMWARE_VERSION         "1.0.0"
#define FIRMWARE_VERSION_MAJOR   1
#define FIRMWARE_VERSION_MINOR   0
#define FIRMWARE_VERSION_PATCH   0

/* ─────────────────────────────────────────────
 * UART Configuration
 * ───────────────────────────────────────────── */

#define OTA_UART_INSTANCE        USART1
#define OTA_UART_BAUDRATE        115200
#define OTA_RX_BUFFER_SIZE       2048            /* Circular buffer size */
#define OTA_CHUNK_TIMEOUT        5000            /* ms */

/* ─────────────────────────────────────────────
 * LED Pin - reused from bootloader.h
 * ─────────────────────────────────────────────
 * FIX: Nucleo-F411RE has only ONE user LED (LD2, PA5). There is no
 * separate green/orange/red/blue physical pin - bootloader.h exposes it
 * as LED_GPIO_PORT/LED_PIN. Event signaling here uses that single pin,
 * either steady on/off (LED_SetStatus) or distinct blink counts
 * (LED_BlinkPattern / LED_BlinkError), same convention bootloader.c uses.
 * ───────────────────────────────────────────── */

#define LED_PORT                 LED_GPIO_PORT   /* from bootloader.h */
/* LED_PIN is inherited directly from bootloader.h - do not redefine it here */

/* ─────────────────────────────────────────────
 * Function Prototypes
 * ───────────────────────────────────────────── */

/* OTA Receiver Core */
void        OTA_Init(UART_HandleTypeDef *huart);
void        OTA_Process(void);
OTA_State_t OTA_GetState(void);

/* UART Protocol Handling
 * OTA_UART_RxCallback takes no argument: HAL writes the received byte
 * directly into rxBuffer[rxHead] (that's the target kept armed via
 * HAL_UART_Receive_IT in OTA_Init), so there's nothing to pass in - this
 * just notifies the OTA layer that a new byte is ready. ota_receiver.c
 * defines HAL_UART_RxCpltCallback() itself, so main.c does NOT need to
 * define it - doing so in both places causes a linker "multiple
 * definition" error. */
void        OTA_UART_RxCallback(void);
void        OTA_HandleStartCommand(uint8_t *data, uint16_t len);
void        OTA_HandleChunkData(uint8_t *data, uint16_t len);
void        OTA_HandleEndCommand(void);
void        OTA_HandleVersionRequest(void);

/* NEW: answers CMD_BANK_QUERY with a fixed-length status packet - see
   ota_receiver.c for the exact byte layout. Lets a host PC ask the
   device directly (over the same UART used for OTA transfers) which
   bank is active, without going through the ESP32/Flask server. */
void        OTA_HandleBankQuery(void);

/* Flash Operations */
HAL_StatusTypeDef OTA_EraseInactiveBank(void);
HAL_StatusTypeDef OTA_WriteToFlash(uint32_t address, uint8_t *data, uint32_t size);
HAL_StatusTypeDef OTA_CopyPage(uint32_t srcAddr, uint32_t destAddr, uint32_t size);

/* Verification */
uint8_t     OTA_VerifyFirmware(uint32_t startAddr, uint32_t size, uint8_t *expectedHash);

/* NEW: rejects an image whose own vector table (SP + Reset_Handler) doesn't
   actually belong to the bank it was just written to. Returns 1 if valid,
   0 if not - catches a wrong linker-origin build before it's ever marked
   bootable. */
uint8_t     OTA_ValidateFirmwareAddress(uint32_t bankAddr, uint32_t bankSize);

void        OTA_SetUpdatePending(uint8_t *sha256Hash, uint32_t fwSize, const char *version);
void        OTA_TriggerReboot(void);

/* Metadata helpers shared with the app's main.c (both link this .c, not the
   bootloader's - each binary owns its own copy of these) */
uint32_t    OTA_ComputeMetadataCRC32(FirmwareMetadata_t *meta);

/* Utility - OTA_SendNACK now takes a reason code, sent as the byte right
   after CMD_NACK. */
void        OTA_SendACK(void);
void        OTA_SendNACK(OTA_NackReason_t reason);
void        OTA_SendVersion(void);

/* Defined in the app's main.c - simple blink helper used to distinguish
   OTA success/failure on a board with only one physical LED */
extern void LED_BlinkError(uint8_t count);

/* Also defined in the app's main.c (shared convention with bootloader.c):
   steady on/off status indicator on the single LED. ota_receiver.c calls
   this instead of touching GPIO registers directly so main.c stays the
   single owner of LED state. */
extern void LED_SetStatus(uint16_t pin, uint8_t state);

#endif /* OTA_RECEIVER_H */
