/*
 * bootloader.h - STM32F411RE OTA Bootloader Definitions
 *
 * CDAC ACTS PG-Diploma in DESD
 * Secure OTA Firmware Update System
 *
 * Target: STM32F411RE - 512KB Flash, 128KB SRAM, NO CCMRAM
 *
 * Memory Layout (512KB total flash):
 *   0x08000000 - 0x0800FFFF : Bootloader        (64KB,  Sectors 0-3)
 *   0x08010000 - 0x0801FFFF : Metadata/Flags    (64KB,  Sector 4)
 *   0x08020000 - 0x0803FFFF : Application Bank A (128KB, Sector 5)
 *   0x08040000 - 0x0805FFFF : Application Bank B (128KB, Sector 6)
 *   0x08060000 - 0x0807FFFF : Reserved / spare  (128KB, Sector 7)
 *
 * NOTE: Unlike the STM32F407 (1MB flash), the F411RE only has 512KB.
 * Bank A and Bank B MUST be equal size since firmware alternates between
 * them, so the maximum application image size on this board is 128KB
 * (limited by the smallest sector used for a bank). Sector 7 is left
 * reserved/unused here; it could be merged into one bank if you are
 * willing to accept asymmetric banks (not recommended for ping-pong OTA).
 */

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include "stm32f4xx_hal.h"
#include <stdint.h>

/* ─────────────────────────────────────────────
 * Flash Memory Map
 * ───────────────────────────────────────────── */

#define BOOTLOADER_START_ADDR       0x08000000U
#define BOOTLOADER_SIZE             0x00010000U     /* 64KB */

#define METADATA_START_ADDR         0x08010000U     /* Metadata sector start */
#define METADATA_SIZE                0x00010000U    /* 64KB (Sector 4) */

#define APP_BANK_A_START_ADDR       0x08020000U     /* Application Bank A start */
#define APP_BANK_B_START_ADDR       0x08040000U     /* Application Bank B start */
#define APP_BANK_SIZE                0x00020000U    /* 128KB per bank */

#define RESERVED_START_ADDR         0x08060000U     /* Spare / future use */
#define RESERVED_SIZE                0x00020000U    /* 128KB (Sector 7) */

/* ─────────────────────────────────────────────
 * Flash Sectors (STM32F411RE, 512KB density, 8 sectors)
 * ───────────────────────────────────────────── */

/* Bootloader: Sectors 0-3 (4 x 16KB = 64KB) */
#define BOOTLOADER_SECTOR_START     FLASH_SECTOR_0
#define BOOTLOADER_SECTOR_END       FLASH_SECTOR_3

/* Metadata: Sector 4 (64KB) */
#define METADATA_SECTOR              FLASH_SECTOR_4

/* Bank A: Sector 5 (128KB) */
#define BANK_A_SECTOR_START         FLASH_SECTOR_5
#define BANK_A_SECTOR_END           FLASH_SECTOR_5

/* Bank B: Sector 6 (128KB) */
#define BANK_B_SECTOR_START         FLASH_SECTOR_6
#define BANK_B_SECTOR_END           FLASH_SECTOR_6

/* Reserved: Sector 7 (128KB) - not currently used */
#define RESERVED_SECTOR              FLASH_SECTOR_7

/* ─────────────────────────────────────────────
 * Firmware Metadata Structure
 * ───────────────────────────────────────────── */

#define METADATA_MAGIC              0xDEADBEEFU
#define FIRMWARE_VERSION_LEN        16
#define SHA256_HASH_LEN             32

typedef enum {
    BANK_A = 0,
    BANK_B = 1
} ActiveBank_t;

typedef enum {
    FLAG_NONE           = 0x00,
    FLAG_UPDATE_PENDING = 0x01,     /* New firmware written, needs verification */
    FLAG_UPDATE_SUCCESS = 0x02,     /* Update verified and running */
    FLAG_ROLLBACK       = 0x04,     /* Rollback requested */
    FLAG_BOOT_FAILED    = 0x08      /* Boot attempt failed */
} UpdateFlag_t;

/* Stored at METADATA_START_ADDR in flash */
typedef struct __attribute__((packed)) {
    uint32_t    magic;                              /* 0xDEADBEEF = valid metadata */
    ActiveBank_t active_bank;                       /* Currently active bank (A or B) */
    uint8_t     update_flags;                       /* UpdateFlag_t combination */
    uint8_t     boot_fail_count;                    /* Consecutive boot failures */
    uint8_t     reserved;                           /* Alignment padding */
    char        fw_version_a[FIRMWARE_VERSION_LEN]; /* Bank A firmware version */
    char        fw_version_b[FIRMWARE_VERSION_LEN]; /* Bank B firmware version */
    uint8_t     sha256_a[SHA256_HASH_LEN];          /* Bank A firmware SHA-256 */
    uint8_t     sha256_b[SHA256_HASH_LEN];          /* Bank B firmware SHA-256 */
    uint32_t    fw_size_a;                          /* Bank A firmware size */
    uint32_t    fw_size_b;                          /* Bank B firmware size */
    uint32_t    update_timestamp;                   /* Last update timestamp */
    uint32_t    crc32;                              /* CRC of this metadata struct */
} FirmwareMetadata_t;

/* ─────────────────────────────────────────────
 * Boot Configuration
 * ───────────────────────────────────────────── */

#define MAX_BOOT_FAILURES           3               /* Max failures before rollback */
#define WATCHDOG_TIMEOUT_MS         10000            /* 10 second watchdog */

/* ─────────────────────────────────────────────
 * LED Status Indicators
 * ───────────────────────────────────────────── */

/* NOTE: The Nucleo-F411RE does NOT have the 4-LED array (PD12-PD15) that
 * the STM32F407 Discovery board has - it only has one user LED (LD2, PA5).
 * All four role-macros below point at that same physical pin. Because a
 * single LED can't show 4 distinct colors, bootloader.c now signals status
 * via distinct BLINK PATTERNS (see LED_BlinkPattern / LED_BlinkError)
 * rather than steady per-color states. If you later wire external LEDs to
 * spare GPIOs, give each macro its own pin here and bootloader.c can go
 * back to steady on/off per color. */

#define LED_GPIO_PORT   GPIOA
#define LED_PIN         GPIO_PIN_5

/* ─────────────────────────────────────────────
 * Function Prototypes
 * ───────────────────────────────────────────── */

/* Bootloader core */
void        Bootloader_Init(void);
void        Bootloader_Run(void);
void        Bootloader_JumpToApp(uint32_t appAddress);

/* Metadata management */
HAL_StatusTypeDef Metadata_Read(FirmwareMetadata_t *meta);
HAL_StatusTypeDef Metadata_Write(FirmwareMetadata_t *meta);
HAL_StatusTypeDef Metadata_Init_Default(void);

/* Firmware verification */
uint8_t     Verify_Firmware_SHA256(uint32_t startAddr, uint32_t size,
                                    uint8_t *expectedHash);
uint32_t    Compute_CRC32_Metadata(FirmwareMetadata_t *meta);
uint8_t     IsValidStackPointer(uint32_t stackPtr);

/* Flash operations */
HAL_StatusTypeDef Flash_EraseSectors(uint32_t startSector, uint32_t endSector);
HAL_StatusTypeDef Flash_WriteData(uint32_t address, uint8_t *data, uint32_t size);

/* Bank management */
uint32_t    GetActiveAppAddress(FirmwareMetadata_t *meta);
uint32_t    GetInactiveAppAddress(FirmwareMetadata_t *meta);
void        SwitchActiveBank(FirmwareMetadata_t *meta);

/* LED indicators */
void        LED_Init(void);
void        LED_SetStatus(uint16_t pin, uint8_t state);
void        LED_BlinkError(uint8_t count);
void        LED_BlinkPattern(uint8_t count, uint16_t onMs, uint16_t offMs);

#endif /* BOOTLOADER_H */
