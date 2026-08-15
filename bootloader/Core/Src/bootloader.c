/*
 * bootloader.c - STM32F411RE OTA Bootloader Implementation
 *
 * CDAC ACTS PG-Diploma in DESD
 * Secure OTA Firmware Update System
 * Ported from STM32F407 -> STM32F411RE
 *
 * ─────────────────────────────────────────────
 * WHAT CHANGED FROM THE F407 VERSION (read this first)
 * ─────────────────────────────────────────────
 * 1) Clock: F411 max SYSCLK is 100 MHz (F407 could do 168 MHz).
 *    PLL/APB dividers and flash wait-states below are recompiled for 100 MHz.
 * 2) Clock source: this board has no HSE (no crystal, no ST-LINK MCO feed),
 *    so SystemClock_Config() uses the internal 16 MHz HSI oscillator
 *    instead - always present, no external hardware needed. PLLM is 16
 *    (vs. 8 for an 8MHz HSE) to land on the same 1MHz VCO input, so the
 *    end result is still 100MHz SYSCLK.
 * 3) Flash geometry: matches bootloader.h - Bootloader = sectors 0-3 (64KB),
 *    Metadata = sector 4 (64KB), Bank A = sector 5 (128KB), Bank B = sector 6
 *    (128KB), sector 7 reserved/unused. Banks are equal size (128KB each),
 *    so unlike an uneven split, either bank can safely hold the other's
 *    rollback image - max application image size is 128KB either way.
 * 4) LEDs: SIMPLIFIED - this board has exactly ONE onboard LED (LD2, PA5),
 *    so instead of carrying over 4 role-macros (LED_GREEN_PIN,
 *    LED_ORANGE_PIN, LED_RED_PIN, LED_BLUE_PIN) that all aliased the same
 *    physical pin - a leftover from the F407 Discovery board's 4 discrete
 *    LEDs - this version uses a single LED_PIN throughout. Status is
 *    signaled with distinct BLINK PATTERNS on that one LED instead of
 *    steady on/off states (which would have looked visually identical for
 *    "verifying" vs "success" since they'd just leave the same pin lit).
 *    See LED_BlinkPattern() below. If you later wire external LEDs to
 *    spare GPIOs, you can reintroduce separate per-color pins.
 * 5) App validity check strengthened: now checks the RESET HANDLER
 *    address too, not just the initial stack pointer. A stack pointer
 *    can look plausible by coincidence (leftover flash data happening to
 *    fall in the SRAM range) while the reset handler is garbage - this
 *    also confirms the handler address is >= the app's own start address
 *    and has the Thumb bit set (required for any Cortex-M code address).
 *    See IsValidApp() below.
 * 6) Manual rollback added: B1 user button (PC13) held for 5 continuous
 *    seconds at boot forces a bank switch, bypassing the normal
 *    update-pending / boot-fail-count logic entirely. Gives a physical
 *    recovery path with no OTA cycle or serial connection needed - see
 *    CheckManualRollbackButton() below.
 *
 * Boot Decision Logic (unchanged from F407 version, plus new Step 1.5):
 *   1. Read metadata from flash
 *   1.5. If B1 held 5s: force bank switch, skip straight to Step 4
 *   2. If UPDATE_PENDING: verify new firmware SHA-256
 *      - Valid: switch banks, clear flag, boot new firmware
 *      - Invalid: clear flag, boot old firmware (rollback)
 *   3. If BOOT_FAILED count > MAX: rollback to other bank
 *   4. Otherwise: boot active bank
 *
 * ─────────────────────────────────────────────
 * REQUIRED bootloader.h CHANGE FOR THIS VERSION
 * ─────────────────────────────────────────────
 * Replace the old 4-macro LED block:
 *   #define LED_GPIO_PORT   GPIOA
 *   #define LED_GREEN_PIN   GPIO_PIN_5
 *   #define LED_ORANGE_PIN  GPIO_PIN_5
 *   #define LED_RED_PIN     GPIO_PIN_5
 *   #define LED_BLUE_PIN    GPIO_PIN_5
 * with:
 *   #define LED_GPIO_PORT   GPIOA
 *   #define LED_PIN         GPIO_PIN_5
 */

#include "bootloader.h"
#include "sha256.h"
#include <string.h>

/* ─────────────────────────────────────────────
 * Private Variables
 * ───────────────────────────────────────────── */

static FirmwareMetadata_t currentMetadata;


/* ─────────────────────────────────────────────
 * Bootloader Initialization
 * ───────────────────────────────────────────── */

void Bootloader_Init(void) {
    /* Initialize HAL */
    HAL_Init();

    /* Configure system clock (100 MHz on F411) */
    SystemClock_Config();

    /* Initialize LED */
    LED_Init();

    /* LED on = bootloader active */
    LED_SetStatus(LED_PIN, 1);
}


/* ─────────────────────────────────────────────
 * Stack Pointer Validation
 * ───────────────────────────────────────────── */

/* Checks whether a value looks like a plausible initial stack pointer for
 * this chip's SRAM (F411RE: 128KB, 0x20000000-0x2001FFFF).
 *
 * BUG FIX: the original check here was `(stackPtr & 0x2FFE0000) ==
 * 0x20000000`, which only accepts addresses strictly inside
 * 0x20000000-0x2001FFFF. But a linker's initial stack pointer (_estack)
 * conventionally points to 0x20020000 - one byte PAST the end of RAM,
 * since the stack grows downward from an exclusive top boundary. That is
 * a completely normal, correct value - but the old bitmask check rejected
 * it, meaning a genuinely valid, correctly-linked application would always
 * be reported as "invalid" by the bootloader. Using an inclusive range
 * check instead fixes this without weakening the check elsewhere (it
 * still rejects blank flash 0xFFFFFFFF, NULL/0x00000000, or anything
 * outside the chip's actual SRAM window).
 */
uint8_t IsValidStackPointer(uint32_t stackPtr) {
    return (stackPtr >= 0x20000000UL && stackPtr <= 0x20020000UL);
}


/* IMPROVEMENT: checks the RESET HANDLER too, not just the stack pointer.
 * A stack pointer can look valid by pure coincidence (e.g. leftover data
 * from a previous erase happens to fall in the SRAM range) while the
 * reset handler address is garbage - checking both catches that case.
 * Two things must hold for a Cortex-M reset handler address:
 *   1. It must point somewhere inside (or after) the app's own flash
 *      region - a handler address pointing BEFORE the app start is
 *      nonsensical.
 *   2. Bit 0 must be set (the Thumb bit) - ARM Cortex-M cores require
 *      this for any code address; a handler address with bit 0 clear
 *      is guaranteed invalid and would itself fault immediately if
 *      jumped to. */
static uint8_t IsValidApp(uint32_t appAddress) {
    uint32_t stackPtr    = *(__IO uint32_t *)appAddress;
    uint32_t resetHandler = *(__IO uint32_t *)(appAddress + 4);

    return IsValidStackPointer(stackPtr) &&
           (resetHandler >= appAddress) &&
           ((resetHandler & 1U) == 1U);
}


/* ─────────────────────────────────────────────
 * Manual Rollback via B1 Button Hold
 * ───────────────────────────────────────────── */

/* Nucleo-F411RE user button B1 is on PC13, wired active-LOW (reads 1 when
 * released, 0 while held). The Nucleo board already has an external
 * pull-up on this net, but we also configure GPIO_PULLUP in software so
 * the check is still correct even if that board-level pull-up is ever
 * bypassed, removed, or the pin is reused on custom hardware.
 *
 * Polls for a full 5 continuous seconds. If the button is released at
 * any point before 5 seconds elapses, returns 0 immediately and does
 * NOT force a rollback - this is deliberate: a brief accidental press
 * during normal power-up (e.g. board handling, boxed shipping, someone
 * bumping it) must never be able to trigger a bank switch. Only a
 * genuine sustained 5-second hold counts.
 *
 * Returns 1 if held the full 5 seconds, 0 otherwise (including "not
 * pressed at all").
 */
static uint8_t CheckManualRollbackButton(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOC_CLK_ENABLE();

    GPIO_InitStruct.Pin  = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    /* Button not pressed at all right now - nothing to do, don't even
       start the hold-feedback blink */
    if (HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) != GPIO_PIN_RESET) {
        return 0;
    }

    /* Button is currently down - poll in 100ms slices for 5000ms total.
       LED pulses the whole time as feedback that the hold is being
       registered (a continuously-running pulse, distinct from every
       other fixed-count pattern used elsewhere in this file). */
    const uint32_t POLL_INTERVAL_MS = 100;
    const uint32_t HOLD_REQUIRED_MS = 5000;
    uint32_t heldMs = 0;

    while (heldMs < HOLD_REQUIRED_MS) {
        if (HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13) != GPIO_PIN_RESET) {
            /* Released early - abort, no rollback triggered */
            return 0;
        }

        LED_SetStatus(LED_PIN, (heldMs / POLL_INTERVAL_MS) % 2);
        HAL_Delay(POLL_INTERVAL_MS);
        heldMs += POLL_INTERVAL_MS;
    }

    /* Held the full 5 seconds - confirm with a solid-on LED briefly
       before proceeding, so there's clear physical feedback that the
       hold was recognized and the rollback is about to happen. */
    LED_SetStatus(LED_PIN, 1);
    HAL_Delay(500);
    LED_SetStatus(LED_PIN, 0);

    return 1;
}


void Bootloader_Run(void) {
    uint32_t appAddress;

    /* Step 1: Read metadata */
    if (Metadata_Read(&currentMetadata) != HAL_OK ||
        currentMetadata.magic != METADATA_MAGIC) {
        /* No valid metadata - first boot or corrupted */
        /* Initialize default metadata and boot Bank A */
        Metadata_Init_Default();
        Metadata_Read(&currentMetadata);
    }

    /* Step 1.5: Manual rollback override - B1 held 5s forces a switch to
       the other bank, bypassing the normal update-pending/boot-fail
       logic entirely. This gives a physical recovery path with no OTA
       cycle or serial connection needed - covers cases the automatic
       checks can't, like "new firmware boots but is badly broken in a
       way IsValidApp() can't detect" (e.g. a hung peripheral init).
       Automatic rollback only triggers on MAX_BOOT_FAILURES repeated
       HARD boot failures or a failed SHA verify during a pending
       update - neither covers "app boots but is unusable". */
    if (CheckManualRollbackButton()) {
        SwitchActiveBank(&currentMetadata);
        currentMetadata.update_flags = FLAG_ROLLBACK;
        currentMetadata.boot_fail_count = 0;
        Metadata_Write(&currentMetadata);

        /* Distinct 4-blink pattern = "manual rollback performed",
           different from the 6-blink verifying, 3-blink success, and
           LED_BlinkError patterns used elsewhere */
        LED_BlinkPattern(4, 150, 150);
    }

    /* Step 2: Check for pending update */
    if (currentMetadata.update_flags & FLAG_UPDATE_PENDING) {
        /* Verifying update: rapid blink (distinct from the success/error
           patterns below) */
        LED_BlinkPattern(6, 80, 80);

        /* Get the NEW firmware bank address and info */
        uint32_t newBankAddr;
        uint8_t *expectedHash;
        uint32_t fwSize;

        if (currentMetadata.active_bank == BANK_A) {
            /* New firmware is in Bank B */
            newBankAddr = APP_BANK_B_START_ADDR;
            expectedHash = currentMetadata.sha256_b;
            fwSize = currentMetadata.fw_size_b;
        } else {
            /* New firmware is in Bank A */
            newBankAddr = APP_BANK_A_START_ADDR;
            expectedHash = currentMetadata.sha256_a;
            fwSize = currentMetadata.fw_size_a;
        }

        /* Verify SHA-256 of new firmware */
        if (Verify_Firmware_SHA256(newBankAddr, fwSize, expectedHash)) {
            /* Verification PASSED - switch to new firmware */
            SwitchActiveBank(&currentMetadata);
            currentMetadata.update_flags = FLAG_UPDATE_SUCCESS;
            currentMetadata.boot_fail_count = 0;
            Metadata_Write(&currentMetadata);

            /* Update success: 3 slow blinks, distinct from the 6 fast
               "verifying" blinks and from LED_BlinkError's patterns */
            LED_BlinkPattern(3, 300, 300);
        } else {
            /* Verification FAILED - rollback, keep current bank */
            currentMetadata.update_flags = FLAG_ROLLBACK;
            currentMetadata.boot_fail_count = 0;
            Metadata_Write(&currentMetadata);

            LED_BlinkError(5);  /* Verification failed */
        }
    }

    /* Step 3: Check boot failure count */
    if (currentMetadata.boot_fail_count >= MAX_BOOT_FAILURES) {
        /* Too many failures - switch to other bank */
        SwitchActiveBank(&currentMetadata);
        currentMetadata.boot_fail_count = 0;
        currentMetadata.update_flags = FLAG_ROLLBACK;
        Metadata_Write(&currentMetadata);

        LED_BlinkError(3);  /* Rollback */
    }

    /* Step 4: Increment boot count (will be cleared by app on successful boot) */
    currentMetadata.boot_fail_count++;
    Metadata_Write(&currentMetadata);

    /* Step 5: Get active application address and jump */
    appAddress = GetActiveAppAddress(&currentMetadata);

    /* Validate application: stack pointer AND reset handler must both
       look legitimate - see IsValidApp() for why both checks matter */
    if (IsValidApp(appAddress)) {
        /* Valid app - about to hand off to it. Turn the LED off here;
           the application owns this pin from this point on and can
           signal its own running state however it wants. */
        LED_SetStatus(LED_PIN, 0);

        Bootloader_JumpToApp(appAddress);
    } else {
        /* Invalid application - try other bank */
        SwitchActiveBank(&currentMetadata);
        Metadata_Write(&currentMetadata);

        appAddress = GetActiveAppAddress(&currentMetadata);

        if (IsValidApp(appAddress)) {
            Bootloader_JumpToApp(appAddress);
        } else {
            /* BOTH banks invalid - stay in bootloader, blink error */
            while (1) {
                LED_BlinkError(10);
                HAL_Delay(2000);
            }
        }
    }
}


/* ─────────────────────────────────────────────
 * Jump to Application
 * ───────────────────────────────────────────── */

void Bootloader_JumpToApp(uint32_t appAddress) {
    /* Disable all interrupts */
    __disable_irq();

    /* Deinitialize HAL and peripherals */
    HAL_DeInit();

    /* Reset SysTick */
    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL  = 0;

    /* Clear all pending interrupts.
       NOTE: F411 (like F407) is a Cortex-M4 with 8 NVIC ICER/ICPR registers,
       so this loop bound of 8 is still correct - no change needed here. */
    for (uint8_t i = 0; i < 8; i++) {
        NVIC->ICER[i] = 0xFFFFFFFF;  /* Disable all NVIC interrupts */
        NVIC->ICPR[i] = 0xFFFFFFFF;  /* Clear all pending interrupts */
    }

    /* Set Vector Table Offset Register (VTOR) to application's vector table */
    SCB->VTOR = appAddress;

    /* Get application's initial stack pointer and reset handler */
    uint32_t appStackPtr   = *(__IO uint32_t *)(appAddress);        /* First word = SP */
    uint32_t appResetHandler = *(__IO uint32_t *)(appAddress + 4);  /* Second word = Reset_Handler */

    /* Set Main Stack Pointer to application's stack pointer */
    __set_MSP(appStackPtr);

    /* Re-enable interrupts */
    __enable_irq();

    /* Jump to application's Reset_Handler */
    void (*jumpToApp)(void) = (void (*)(void))appResetHandler;
    jumpToApp();

    /* Should never reach here */
    while (1) {}
}


/* ─────────────────────────────────────────────
 * Metadata Management
 * ───────────────────────────────────────────── */

HAL_StatusTypeDef Metadata_Read(FirmwareMetadata_t *meta) {
    /* Read metadata directly from flash (memory-mapped) */
    memcpy(meta, (void *)METADATA_START_ADDR, sizeof(FirmwareMetadata_t));

    /* Verify CRC */
    uint32_t expectedCRC = meta->crc32;
    meta->crc32 = 0;
    uint32_t computedCRC = Compute_CRC32_Metadata(meta);
    meta->crc32 = expectedCRC;

    if (computedCRC != expectedCRC) {
        return HAL_ERROR;  /* Metadata corrupted */
    }

    return HAL_OK;
}


HAL_StatusTypeDef Metadata_Write(FirmwareMetadata_t *meta) {
    HAL_StatusTypeDef status;

    /* Compute CRC before writing */
    meta->crc32 = 0;
    meta->crc32 = Compute_CRC32_Metadata(meta);

    /* Erase metadata sector (Sector 1 on F411, was a different sector on F407) */
    status = Flash_EraseSectors(METADATA_SECTOR, METADATA_SECTOR);
    if (status != HAL_OK) return status;

    /* Write metadata */
    status = Flash_WriteData(METADATA_START_ADDR, (uint8_t *)meta, sizeof(FirmwareMetadata_t));

    return status;
}


HAL_StatusTypeDef Metadata_Init_Default(void) {
    FirmwareMetadata_t defaultMeta;

    memset(&defaultMeta, 0, sizeof(FirmwareMetadata_t));
    defaultMeta.magic = METADATA_MAGIC;
    defaultMeta.active_bank = BANK_A;
    defaultMeta.update_flags = FLAG_NONE;
    defaultMeta.boot_fail_count = 0;
    strncpy(defaultMeta.fw_version_a, "1.0.0", FIRMWARE_VERSION_LEN);
    strncpy(defaultMeta.fw_version_b, "0.0.0", FIRMWARE_VERSION_LEN);
    defaultMeta.fw_size_a = 0;
    defaultMeta.fw_size_b = 0;

    return Metadata_Write(&defaultMeta);
}


/* ─────────────────────────────────────────────
 * Firmware Verification
 * ───────────────────────────────────────────── */

uint8_t Verify_Firmware_SHA256(uint32_t startAddr, uint32_t size, uint8_t *expectedHash) {
    SHA256_CTX ctx;
    uint8_t computedHash[SHA256_HASH_LEN];

    sha256_init(&ctx);

    /* Hash firmware in chunks to save RAM */
    uint32_t remaining = size;
    uint32_t addr = startAddr;
    uint8_t buffer[256];

    while (remaining > 0) {
        uint32_t chunkSize = (remaining > 256) ? 256 : remaining;
        memcpy(buffer, (void *)addr, chunkSize);
        sha256_update(&ctx, buffer, chunkSize);
        addr += chunkSize;
        remaining -= chunkSize;
    }

    sha256_final(&ctx, computedHash);

    /* Compare hashes */
    return (memcmp(computedHash, expectedHash, SHA256_HASH_LEN) == 0) ? 1 : 0;
}


uint32_t Compute_CRC32_Metadata(FirmwareMetadata_t *meta) {
    /* Simple CRC32 for metadata integrity (not security - just corruption check) */
    uint32_t crc = 0xFFFFFFFF;
    uint8_t *data = (uint8_t *)meta;
    uint32_t len = sizeof(FirmwareMetadata_t) - sizeof(uint32_t); /* Exclude CRC field */

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


/* ─────────────────────────────────────────────
 * Flash Operations
 * ───────────────────────────────────────────── */

HAL_StatusTypeDef Flash_EraseSectors(uint32_t startSector, uint32_t endSector) {
    HAL_StatusTypeDef status;
    FLASH_EraseInitTypeDef eraseInit;
    uint32_t sectorError = 0;

    /* Unlock flash */
    HAL_FLASH_Unlock();

    /* Clear pending flags */
    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR |
                            FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR |
                            FLASH_FLAG_PGPERR | FLASH_FLAG_PGSERR);

    eraseInit.TypeErase    = FLASH_TYPEERASE_SECTORS;
    eraseInit.VoltageRange = FLASH_VOLTAGE_RANGE_3;  /* 2.7V - 3.6V (same on F411) */
    eraseInit.Sector       = startSector;
    eraseInit.NbSectors    = endSector - startSector + 1;

    status = HAL_FLASHEx_Erase(&eraseInit, &sectorError);

    HAL_FLASH_Lock();

    return status;
}


HAL_StatusTypeDef Flash_WriteData(uint32_t address, uint8_t *data, uint32_t size) {
    HAL_StatusTypeDef status = HAL_OK;

    HAL_FLASH_Unlock();

    /* Write word by word (32-bit) for efficiency */
    uint32_t i = 0;
    while (i < size) {
        if (size - i >= 4) {
            /* Write 32-bit word */
            uint32_t word = *(uint32_t *)(data + i);
            status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, address + i, word);
            i += 4;
        } else {
            /* Write remaining bytes one at a time */
            status = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address + i, data[i]);
            i += 1;
        }

        if (status != HAL_OK) break;
    }

    HAL_FLASH_Lock();

    return status;
}


/* ─────────────────────────────────────────────
 * Bank Management
 * ───────────────────────────────────────────── */

uint32_t GetActiveAppAddress(FirmwareMetadata_t *meta) {
    return (meta->active_bank == BANK_A) ? APP_BANK_A_START_ADDR : APP_BANK_B_START_ADDR;
}


uint32_t GetInactiveAppAddress(FirmwareMetadata_t *meta) {
    return (meta->active_bank == BANK_A) ? APP_BANK_B_START_ADDR : APP_BANK_A_START_ADDR;
}


void SwitchActiveBank(FirmwareMetadata_t *meta) {
    meta->active_bank = (meta->active_bank == BANK_A) ? BANK_B : BANK_A;
}


/* ─────────────────────────────────────────────
 * LED Indicator
 *
 * NOTE: simplified to a single LED (LD2, PA5) - the only physical LED on
 * Nucleo-F411RE. All status signaling uses BLINK PATTERNS on this one
 * pin instead of separate colors (see LED_BlinkPattern()). If you later
 * wire external LEDs to spare GPIOs, this can be split back into
 * per-color pins/macros.
 * ───────────────────────────────────────────── */

void LED_Init(void) {
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin   = LED_PIN;
    GPIO_InitStruct.Mode  = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull  = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;

    HAL_GPIO_Init(LED_GPIO_PORT, &GPIO_InitStruct);

    /* LED off */
    HAL_GPIO_WritePin(LED_GPIO_PORT, LED_PIN, GPIO_PIN_RESET);
}


void LED_SetStatus(uint16_t pin, uint8_t state) {
    HAL_GPIO_WritePin(LED_GPIO_PORT, pin, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
}


void LED_BlinkError(uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        LED_SetStatus(LED_PIN, 1);
        HAL_Delay(200);
        LED_SetStatus(LED_PIN, 0);
        HAL_Delay(200);
    }
}


/* General-purpose blink pattern, used to give non-error states (verifying,
   update success, etc.) a shape distinct from LED_BlinkError's patterns. */
void LED_BlinkPattern(uint8_t count, uint16_t onMs, uint16_t offMs) {
    for (uint8_t i = 0; i < count; i++) {
        LED_SetStatus(LED_PIN, 1);
        HAL_Delay(onMs);
        LED_SetStatus(LED_PIN, 0);
        HAL_Delay(offMs);
    }
}


/* ─────────────────────────────────────────────
 * System Clock Configuration (100 MHz - F411 max)
 * ───────────────────────────────────────────── */

void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    /* Configure power supply - Scale 1 needed to reach 100 MHz */
    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

    /* HSI -> PLL -> 100MHz
     *
     * No HSE available on this board, so we use the internal 16 MHz HSI
     * oscillator instead - always present, no external hardware needed.
     * PLLM is doubled vs. the HSE version (16 instead of 8) since HSI is
     * 16 MHz vs HSE's 8 MHz - both still land on a 1 MHz VCO input, so
     * PLLN/PLLP are unchanged and SYSCLK is still 100 MHz.
     */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState       = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState   = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource  = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLM       = 16;   /* 16MHz / 16 = 1MHz VCO input */
    RCC_OscInitStruct.PLL.PLLN       = 200;  /* 1MHz * 200 = 200MHz VCO   */
    RCC_OscInitStruct.PLL.PLLP       = RCC_PLLP_DIV2; /* 200MHz / 2 = 100MHz SYSCLK */
    RCC_OscInitStruct.PLL.PLLQ       = 4;    /* not critical here (no USB) */
    HAL_RCC_OscConfig(&RCC_OscInitStruct);

    /* F411 bus limits: APB1 max 50MHz, APB2 max 100MHz (F407 was 42/84) */
    RCC_ClkInitStruct.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                                       RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;   /* HCLK = 100MHz */
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;     /* APB1 = 50MHz  */
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;     /* APB2 = 100MHz */

    /* Flash latency: at 100MHz / Scale 1 / 2.7-3.6V, F411 needs 3 wait states
       (F407 at 168MHz needed 5 - this is lower because SYSCLK is lower) */
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3);
}
