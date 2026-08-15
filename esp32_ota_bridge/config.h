#ifndef CONFIG_H
#define CONFIG_H  

// ─────────────────────────────────────────────
// WiFi Configuration
// ─────────────────────────────────────────────
#define WIFI_SSID           "Harshit’s iphone"
#define WIFI_PASSWORD       "harshit1234"
#define WIFI_CONNECT_TIMEOUT 20000   // ms

// ─────────────────────────────────────────────
// OTA Server Configuration
// ─────────────────────────────────────────────
#define OTA_SERVER_HOST     "172.20.10.2"  // Your server IP - MUST be on the
                                              // same network as this ESP32 (see note below)
#define OTA_SERVER_PORT     5000
#define OTA_VERSION_URL     "/api/version"
#define OTA_DELTA_URL       "/api/firmware/delta"
#define OTA_FULL_FW_URL     "/api/firmware/full"
#define OTA_CHECK_INTERVAL  30000    // Check for updates every 30 seconds (ms)

// ─────────────────────────────────────────────
// UART Configuration (ESP32 <-> STM32)
// ─────────────────────────────────────────────
// NOTE: ESP32 GPIO numbers are unchanged. Only the STM32-side pins changed,
// from USART2/PA2-PA3 to USART1/PA9-PA10, since PA2/PA3 are shared with the
// Nucleo board's onboard ST-Link Virtual COM Port and can conflict with an
// external UART device wired to the same pins.
#define STM32_UART_BAUD     115200
#define STM32_UART_TX       17       // GPIO17 -> STM32 PA10 (USART1_RX)
#define STM32_UART_RX       16       // GPIO16 <- STM32 PA9  (USART1_TX)

// ─────────────────────────────────────────────
// Transfer Protocol Configuration
// ─────────────────────────────────────────────
#define CHUNK_SIZE          512      // Bytes per UART chunk
#define ACK_TIMEOUT         5000     // Wait for ACK timeout (ms)
#define MAX_RETRIES         3        // Retries per chunk before abort
#define INTER_CHUNK_DELAY   10       // Delay between chunks (ms)

// ─────────────────────────────────────────────
// Protocol Commands (ESP32 <-> STM32)
// ─────────────────────────────────────────────
#define CMD_START_OTA       0xAA     // OTA transfer starting
#define CMD_CHUNK_DATA      0xBB     // Data chunk follows
#define CMD_END_OTA         0xCC     // Transfer complete
#define CMD_ACK             0x06     // Acknowledged
#define CMD_NACK            0x15     // Not acknowledged / error
#define CMD_VERSION_REQ     0xDD     // Request current version
#define CMD_VERSION_RESP    0xEE     // Version response
#define CMD_ABORT           0xFF     // Abort transfer

// ─────────────────────────────────────────────
// LED Indicators (ESP32 DevKit)
// ─────────────────────────────────────────────
#define LED_WIFI            2        // Built-in LED: WiFi status
#define LED_OTA_ACTIVE      4        // External LED: OTA in progress

// ─────────────────────────────────────────────
// Debug Configuration
// ─────────────────────────────────────────────
#define DEBUG_SERIAL        Serial   // USB Serial for debug output
#define DEBUG_BAUD          115200
#define DEBUG_ENABLED       1        // Set to 0 to disable debug prints

#if DEBUG_ENABLED
  #define DBG_PRINT(...)    DEBUG_SERIAL.print(__VA_ARGS__)
  #define DBG_PRINTLN(...)  DEBUG_SERIAL.println(__VA_ARGS__)
  #define DBG_PRINTF(...)   DEBUG_SERIAL.printf(__VA_ARGS__)
#else
  #define DBG_PRINT(...)
  #define DBG_PRINTLN(...)
  #define DBG_PRINTF(...)
#endif

#endif // CONFIG_H
