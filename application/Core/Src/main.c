/*
 * main.c - STM32F411RE Application Firmware
 *
 * CDAC ACTS PG-Diploma in DESD
 * Secure OTA Firmware Update System
 *
 * This is the main application firmware running from Bank A or Bank B.
 * It performs normal application tasks while also handling OTA updates
 * received from ESP32 via UART.
 *
 * Vector Table: Relocated by bootloader via VTOR register.
 * Start Address: 0x08020000 (Bank A) or 0x08040000 (Bank B)
 *
 * ─────────────────────────────────────────────
 * WHAT CHANGED FROM THE F407 VERSION
 * ─────────────────────────────────────────────
 * - SystemClock_Config(): 100MHz PLL settings for F411 (see bootloader.c's
 *   port for the same change - kept identical here since both binaries
 *   must run at a clock speed the F411 actually supports). Uses the
 *   internal HSI oscillator (16MHz) rather than HSE, since no external
 *   crystal/MCO reference is available on this board.
 * - ClearBootFailCount(): rewritten to use the FirmwareMetadata_t struct by
 *   field name instead of hardcoded byte offsets (metaBuffer[5], [6]), for
 *   the same reason described in ota_receiver.c - and now recomputes crc32
 *   before writing, which the F407 version never did. Without that, the
 *   very act of "I booted OK, clear the fail count" would leave metadata
 *   with a stale CRC, and the bootloader would reject it as corrupted on
 *   the next boot.
 * - Metadata sector erase now targets METADATA_SECTOR (sector 4) instead
 *   of FLASH_SECTOR_11.
 * - GPIO: LEDs collapsed to the single PA5 LED (Nucleo LD2) via
 *   bootloader.h's macros; GPIOD clock enable removed since it's unused.
 * - User button moved from PA0 (F407 Discovery convention) to PC13, which
 *   is where the User button (B1) actually is on Nucleo-F411RE. Remove/
 *   adjust this if you're on different hardware.
 * - Interrupt handlers (NMI_Handler, HardFault_Handler, SysTick_Handler,
 *   USART1_IRQHandler, etc.) are deliberately NOT defined in this file.
 *   If you generated this project's scaffolding via STM32CubeMX/CubeIDE's
 *   wizard, those already exist in the auto-generated stm32f4xx_it.c -
 *   defining them again here causes linker "multiple definition" errors.
 * - BUG FIX: removed the standalone uartRxByte buffer and main()'s own
 *   HAL_UART_Receive_IT() call. Both this file and ota_receiver.c were
 *   separately calling HAL_UART_Receive_IT() after every byte, targeting
 *   two DIFFERENT buffers - whichever call ran second silently failed
 *   (HAL_UART_Receive_IT no-ops if the UART isn't READY), so real
 *   incoming bytes ended up landing directly in ota_receiver.c's buffer
 *   while this file kept re-feeding a stale, frozen byte value back into
 *   the protocol logic. Net effect: reception desynced/corrupted from the
 *   second byte received onward - which explains inconsistent or missing
 *   responses to STM32-side UART commands like the version query. Fixed
 *   by having exactly one buffer (ota_receiver.c's rxBuffer) and exactly
 *   one place arming reception into it.
 * - FIX (this revision): LED macro mismatch with bootloader.h /
 *   ota_receiver.h. This file previously referenced LED_GREEN/LED_ORANGE/
 *   LED_RED/LED_BLUE, none of which exist anymore - bootloader.h exposes
 *   only a single physical LED as LED_GPIO_PORT/LED_PIN (Nucleo-F411RE's
 *   one user LED, LD2 on PA5). Every call site below now uses LED_PIN
 *   directly. Also added LED_SetStatus() - ota_receiver.h declares it
 *   extern and ota_receiver.c now calls it directly (see that file's
 *   OTA_HandleStartCommand/OTA_HandleEndCommand); each flash image (app
 *   vs bootloader) needs its own copy since they don't link together,
 *   same reasoning already applied to LED_BlinkError() below.
 */

#include "stm32f4xx_hal.h"
#include "ota_receiver.h"
#include <string.h>

/* ─────────────────────────────────────────────
 * Private Variables
 * ───────────────────────────────────────────── */

UART_HandleTypeDef huart1;      /* USART1 for ESP32 communication (PA9/PA10 - moved off PA2/PA3 since those are shared with the Nucleo's ST-Link VCP) */

/* ─────────────────────────────────────────────
 * Function Prototypes
 * ───────────────────────────────────────────── */

void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART1_UART_Init(void);
void Application_Run(void);
void ClearBootFailCount(void);

/* ─────────────────────────────────────────────
 * Main Entry Point
 * ───────────────────────────────────────────── */

int main(void) {
    /* HAL Initialization */
    HAL_Init();

    /* Configure system clock to 100MHz (F411 max) */
    SystemClock_Config();

    /* Initialize peripherals */
    MX_GPIO_Init();
    MX_USART1_UART_Init();

    /* Signal successful boot: LED ON
       FIX: was HAL_GPIO_WritePin(LED_PORT, LED_GREEN, GPIO_PIN_SET) -
       LED_GREEN no longer exists, single LED uses LED_PIN. */
    HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);

    /* Clear boot failure count in metadata (we booted successfully) -
       this is what tells the bootloader NOT to roll back next time */
    ClearBootFailCount();

    /* Initialize OTA receiver - this also arms the first byte reception
       directly into ota_receiver.c's own buffer (see OTA_Init) */
    OTA_Init(&huart1);

    /* Main application loop */
    while (1) {
        /* Process OTA commands if any */
        OTA_Process();

        /* Normal application tasks */
        Application_Run();

        HAL_Delay(10);
    }
}


/* ─────────────────────────────────────────────
 * Application Logic
 * ───────────────────────────────────────────── */

void Application_Run(void) {
    /*
     * Main application behavior.
     * This is where you put your actual application code.
     *
     * For demonstration: Heartbeat LED blink pattern indicates
     * that the application is running normally. Only runs while idle
     * so it never fights with OTA's use of the same physical LED.
     */

    static uint32_t lastBlink = 0;
    static uint8_t blinkState = 0;

    /* Heartbeat: LED blinks every 1 second when idle */
    if (OTA_GetState() == OTA_STATE_IDLE) {
        if (HAL_GetTick() - lastBlink >= 500) {
            lastBlink = HAL_GetTick();
            blinkState = !blinkState;
            /* FIX: was HAL_GPIO_WritePin(LED_PORT, LED_GREEN, ...) */
            HAL_GPIO_WritePin(LED_PORT, LED_PIN,
                            blinkState ? GPIO_PIN_SET : GPIO_PIN_RESET);
        }
    }

    /*
     * Add your application-specific code here:
     * - Sensor readings
     * - Data processing
     * - Communication tasks
     * - Control logic
     * etc.
     */
}


void ClearBootFailCount(void) {
    /*
     * Clear boot failure counter in metadata to indicate successful boot.
     * The bootloader increments this on each boot attempt (bootloader.c,
     * Bootloader_Run Step 4). If it reaches MAX_BOOT_FAILURES, bootloader.c
     * Step 3 rolls back to the other bank on the NEXT boot. Clearing it
     * here is what prevents that rollback from ever triggering when the
     * app is actually healthy: "I made it this far, I'm fine."
     */

    FirmwareMetadata_t meta;
    memcpy(&meta, (void *)METADATA_ADDR, sizeof(FirmwareMetadata_t));

    if (meta.magic != METADATA_MAGIC) {
        return;  /* nothing valid to update */
    }

    if (meta.boot_fail_count > 0 || meta.update_flags == FLAG_UPDATE_PENDING) {
        meta.boot_fail_count = 0;
        meta.update_flags = FLAG_UPDATE_SUCCESS;  /* mark as stable */

        /* Recompute CRC before writing - same requirement as
           ota_receiver.c's OTA_SetUpdatePending(), see file header note */
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
        eraseInit.Sector       = METADATA_SECTOR;   /* FLASH_SECTOR_4 on F411 */
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
}


/* ─────────────────────────────────────────────
 * Peripheral Initialization
 * ───────────────────────────────────────────── */

static void MX_GPIO_Init(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    /* Enable GPIO clocks - GPIOA only needed now (LED on PA5, USART1 on
       PA9/PA10); GPIOD isn't used on this board so its clock is dropped */
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();

    /* Configure LED pin (PA5 - single onboard LED, see LED_PORT/LED_PIN
       in bootloader.h).
       FIX: was Pin = LED_GREEN | LED_ORANGE | LED_RED | LED_BLUE
       ("all alias PA5") - those macros don't exist; there's just one
       pin now, so this is simply LED_PIN. */
    GPIO_InitStruct.Pin   = LED_PIN;
    GPIO_InitStruct.Mode  = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull  = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(LED_PORT, &GPIO_InitStruct);

    /* LED off initially
       FIX: was WritePin(LED_PORT, LED_GREEN | LED_ORANGE | LED_RED | LED_BLUE, ...) */
    HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_RESET);

    /* Configure User Button - Nucleo-F411RE's B1 button is on PC13, not
       PA0 (that was the F407 Discovery board's pin) */
    GPIO_InitStruct.Pin  = GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);
}


static void MX_USART1_UART_Init(void) {
    /* USART1: PA9 (TX), PA10 (RX) - Connected to ESP32.
       Moved from USART2/PA2-PA3 because those pins are shared with the
       Nucleo board's onboard ST-Link Virtual COM Port, which can contend
       with an external UART device wired to the same pins. */

    __HAL_RCC_USART1_CLK_ENABLE();

    /* Configure USART1 GPIO pins */
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    GPIO_InitStruct.Pin       = GPIO_PIN_9 | GPIO_PIN_10;   /* PA9=TX, PA10=RX */
    GPIO_InitStruct.Mode      = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull      = GPIO_PULLUP;
    GPIO_InitStruct.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART1;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    /* USART1 configuration */
    huart1.Instance          = USART1;
    huart1.Init.BaudRate     = OTA_UART_BAUDRATE;
    huart1.Init.WordLength   = UART_WORDLENGTH_8B;
    huart1.Init.StopBits     = UART_STOPBITS_1;
    huart1.Init.Parity       = UART_PARITY_NONE;
    huart1.Init.Mode         = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl    = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart1);

    /* Enable USART1 interrupt */
    HAL_NVIC_SetPriority(USART1_IRQn, 1, 0);
    HAL_NVIC_EnableIRQ(USART1_IRQn);
}


void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

    /* Same 100MHz PLL configuration as bootloader.c - both binaries must
       agree on clock speed. No HSE available on this board, so both use
       the internal 16 MHz HSI oscillator (PLLM=16 instead of 8). */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState       = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState   = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource  = RCC_PLLSOURCE_HSI;
    RCC_OscInitStruct.PLL.PLLM       = 16;
    RCC_OscInitStruct.PLL.PLLN       = 200;
    RCC_OscInitStruct.PLL.PLLP       = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLQ       = 4;
    HAL_RCC_OscConfig(&RCC_OscInitStruct);

    RCC_ClkInitStruct.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                                       RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;   /* APB1 = 50MHz */
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;   /* APB2 = 100MHz */
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3);
}


/* ─────────────────────────────────────────────
 * Interrupt Handlers
 *
 * NOTE: NMI_Handler, HardFault_Handler, MemManage_Handler, BusFault_Handler,
 * UsageFault_Handler, SVC_Handler, PendSV_Handler, SysTick_Handler, and
 * USART1_IRQHandler are NOT defined here - they already exist in CubeMX's
 * generated stm32f4xx_it.c. Defining them here too causes "multiple
 * definition" linker errors. If USART1_IRQHandler in stm32f4xx_it.c
 * doesn't already call HAL_UART_IRQHandler(&huart1), add that one line
 * inside its USER CODE block instead of redefining the whole function.
 * ───────────────────────────────────────────── */

/* Helper for error LED (this binary's own copy - separate from the
   bootloader's LED_BlinkError, since app and bootloader are separate
   flash images and don't link together).
   FIX: was HAL_GPIO_WritePin(LED_PORT, LED_RED, ...) - single LED now,
   uses LED_PIN. Blink COUNT still distinguishes error types (see the
   4/5/7-blink codes ota_receiver.c passes in), just no longer a
   dedicated "red" pin. */
void LED_BlinkError(uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_SET);
        HAL_Delay(200);
        HAL_GPIO_WritePin(LED_PORT, LED_PIN, GPIO_PIN_RESET);
        HAL_Delay(200);
    }
}


/* NEW: required by ota_receiver.h (declared extern there) - ota_receiver.c
   calls this directly in OTA_HandleStartCommand()/OTA_HandleEndCommand()
   to set the single LED to a steady on/off state (distinct from the
   blink-count error signaling in LED_BlinkError above). Simple pass-
   through to HAL since this board has only one LED and no separate
   "status" vs "error" hardware - state=1 means solid on, state=0 means
   off. The `pin` parameter is accepted for API symmetry with a possible
   future multi-LED board, but this build only ever has LED_PIN wired up. */
void LED_SetStatus(uint16_t pin, uint8_t state) {
    HAL_GPIO_WritePin(LED_PORT, pin, state ? GPIO_PIN_SET : GPIO_PIN_RESET);
}
