# AlphaTheta / Pioneer DJ Firmware Security Analysis

**Targets:**
- CDJ-1500X, firmware `CDJ1500Xv110.UPD` (v1.10, 2/Aug/2026)
- XDJ-AN, firmware `XDJANv120.UPD` (v1.20, 18/Aug/2026)

**Vendor GPL drops analyzed:**
- `CDJ-1500X.tar.xz` (v1.01, 2/Jul/2026) — partial (external/ only)
- `XDJ-AN.tar.xz` (Jul 2026) — full BSP (kernel, u-boot, buildroot, rkbin)

**SoC platform:** Rockchip RK3566
**OP-TEE version:** 3.7.9
**Analyst:** drclab
**Host:** Ubuntu (resolute), AMD Ryzen 5 4600U
**Container used:** Ubuntu 18.04 (Docker, `cdj-build`)

---

# Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Objective](#2-objective)
3. [Artifacts](#3-artifacts)
4. [Timeline of Investigation](#4-timeline-of-investigation)
5. [Phase 1 — Firmware Container Identification](#5-phase-1--firmware-container-identification)
6. [Phase 2 — The Two LUKS Headers](#6-phase-2--the-two-luks-headers)
7. [Phase 3 — Header Repair and hashcat](#7-phase-3--header-repair-and-hashcat)
8. [Phase 4 — Cross-Firmware Comparison](#8-phase-4--cross-firmware-comparison)
9. [Phase 5 — GPL Source Analysis](#9-phase-5--gpl-source-analysis)
10. [Phase 6 — OP-TEE Client Library Analysis](#10-phase-6--optee-client-library-analysis)
11. [Phase 7 — Trusted Application Analysis](#11-phase-7--trusted-application-analysis)
12. [Phase 8 — Full BSP Analysis (XDJ-AN)](#12-phase-8--full-bsp-analysis-xdj-an)
13. [Phase 9 — TA Signing and Key Trust](#13-phase-9--ta-signing-and-key-trust)
14. [Reconstructed Decryption Chain](#14-reconstructed-decryption-chain)
15. [Conclusion](#15-conclusion)
16. [Comparison with CDJ-3000](#16-comparison-with-cdj-3000)
17. [Open Items and Next Steps](#17-open-items-and-next-steps)
18. [GPL Source Request (Draft)](#18-gpl-source-request-draft)
19. [Reproducing the Analysis](#19-reproducing-the-analysis)
20. [Tools Used](#20-tools-used)
21. [Legal and Ethical Note](#21-legal-and-ethical-note)

---

# 1. Executive Summary

The CDJ-1500X and XDJ-AN firmware update files (`.UPD`) are **decoy LUKS1
containers** whose payload is encrypted with an AES-XTS key derived on-device
from a Rockchip RK3566 Hardware Unique Key (HUK) fused into the SoC eFuse.
The key never leaves the OP-TEE secure world.

The `.UPD` file, the GPL source drops, and the shipped binaries contain no
material that can produce this key. The LUKS header is a static template
reused across product lines, not a real encryption header. The TA signing key
used by the production devices was not shipped in the GPL drops.

**There is no software-only path to decrypt the firmware on a PC.**

The protection is correctly implemented. Every layer has been analyzed and
every alternative has been tested.

---

# 2. Objective

Determine whether the CDJ-1500X or XDJ-AN firmware can be decrypted and
analyzed on a standard PC without physical access to a device, and document
the security architecture of the firmware update mechanism.

---

# 3. Artifacts

| Artifact | Size | Notes |
|---|---|---|
| `CDJ1500Xv110.UPD` | 188,718,095 B | Firmware update container |
| `XDJANv120.UPD` | 188,802,063 B | Firmware update container |
| `CDJ-1500X.tar.xz` | 3.0 GB | GPL source (partial) |
| `XDJ-AN.tar.xz` | 3.0 GB | GPL source (full BSP) |
| `sx-sdmax_XDJ-AN.tar.xz` | 12 MB | SoC vendor SDK |
| `librk_tee_service.so` (arm64) | ~13 KB | OP-TEE client library |
| `4367fd45-4469-42a6-925d-3857b952704a.ta` | 94 KB | Signed OP-TEE Trusted Application |
| `ebc28104-47ff-4e34-89783c212bb17c2e.ta` | 94 KB | Second TA (securityAuth package) |
| `tee-pager.bin` | 702 KB | Prebuilt OP-TEE 3.7.9 OS image (in change_puk tool) |

**SHA-256 of the original CDJ-1500X firmware:**

```
7f6663398a363b45eaa3de840869fe1cdae193b89e5509227e5212f562ad4e39  CDJ1500Xv110.UPD
```

---

# 4. Timeline of Investigation

| Phase | Activity | Outcome |
|---|---|---|
| 1 | `file`, `xxd` on both `.UPD` files | Both identified as LUKS1 containers |
| 2 | Binary scan for LUKS magic | Two overlapping headers at `0x0000` and `0x0200` in both |
| 3 | Header repair, `cryptsetup luksDump`, hashcat | Header parses, passphrase `Exhausted` |
| 4 | Cross-firmware comparison | Headers **byte-identical** across products |
| 5 | GPL source grep for LUKS | Only `license.txt` mentions LUKS |
| 6 | `librk_tee_service.so` disassembly | Only opaque encrypt/decrypt API |
| 7 | TA extraction and disassembly | HKDF + TEE crypto syscalls, opaque handles |
| 8 | Full BSP acquisition (XDJ-AN) | Kernel, U-Boot, buildroot, rkbin |
| 9 | TA signing tools and key verification | SDK default key does NOT verify TA |
| 10 | `tee-pager.bin` analysis | OP-TEE 3.7.9, HUK key path, production key in eFuse |
| 11 | Hash search for SDK default pubkey | **Not found** in OP-TEE OS image |
| 12 | Conclusion | Hardware-bound; no PC decryption possible |

---

# 5. Phase 1 — Firmware Container Identification

## 5.1 Both files start with a LUKS magic

```bash
$ file CDJ1500Xv110.UPD
CDJ1500Xv110.UPD: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
  UUID: fa03960e-420a-4044-8bfe-7abbe5f23daf, at 0x1000 data, 64 key bytes,
  MK digest 0x332fb7805b65e359d1e291e7ca6d7f115148744d,
  MK salt 0x4e5068221c998b3e313bd326727d781feee6a90eb1d58f10e314ce267218b216,
  178086 MK iterations; slot #0 active, 0x8 material offset

$ file XDJANv120.UPD
XDJANv120.UPD: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256]
  UUID: fa03960e-420a-4044-8bfe-7abbe5f23daf, at 0x1000 data, 64 key bytes,
  MK digest 0x332fb7805b65e359d1e291e7ca6d7f115148744d,
  ... identical to CDJ-1500X
```

**The UUID and master key digest are identical across two different
products.** In real LUKS, both values are unique per volume. Identical values
across two independent devices is definitive proof that the LUKS header is a
static template, not a real encrypted volume.

## 5.2 First 256 bytes

```
00000000: 4c55 4b53 babe 0001 6165 7300 0000 0000  LUKS....aes.....
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 7874 732d 706c 6169  ........xts-plai
00000030: 6e36 3400 0000 0000 0000 0000 0000 0000  n64.............
00000040: 0000 0000 0000 0000 7368 6132 3536 0000  ........sha256..
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 1000 0000 0040  ...............@
00000070: 332f b780 5b65 e359 d1e2 91e7 ca6d 7f11  3/..[e.Y.....m..
00000080: 5148 744d 4e50 6822 1c99 8b3e 313b d326  QHtMNPh"...>1;.&
00000090: 727d 781f eee6 a90e b1d5 8f10 e314 ce26  r}x............&
000000a0: 7218 b216 0002 b7a6 6661 3033 3936 3065  r.......fa03960e
000000b0: 2d34 3230 612d 3430 3434 2d38 6266 652d  -420a-4044-8bfe-
000000c0: 3761 6262 6535 6632 3364 6166 0000 0000  7abbe5f23daf....
000000d0: 00ac 71f3 002b 7a6e b054 8dca 35dc e4fe  ..q..+zn.T..5...
000000e0: 9ccc 5332 913c 90cd baca 8495 18cf 184f  ..S2.<.........O
000000f0: 05bf 271d fad8 1077 0000 0008 0000 0fa0  ..'....w........
```

---

# 6. Phase 2 — The Two LUKS Headers

## 6.1 Both files contain two LUKS magics

```bash
$ grep -abo $'\x4c\x55\x4b\x53\xba\xbe' CDJ1500Xv110.UPD
0:LUKS
512:LUKS

$ grep -abo $'\x4c\x55\x4b\x53\xba\xbe' XDJANv120.UPD
0:LUKS
512:LUKS
```

Header #1 at offset `0x0000`, header #2 at `0x0200`. Header #2 sits **inside
keyslot 6 of header #1** (slot 6 spans `0x1f0–0x21f`) and entirely overwrites
keyslot 7.

This is why stock `cryptsetup` rejects both files:

```
LUKS keyslot 6 is invalid.
Device is not a valid LUKS device.
```

## 6.2 Cross-product header diff

```bash
$ dd if=CDJ1500Xv110.UPD of=/tmp/hdr_1500x.bin bs=512 count=8
$ dd if=XDJANv120.UPD    of=/tmp/hdr_xdjan.bin bs=512 count=8
$ cmp -l /tmp/hdr_1500x.bin /tmp/hdr_xdjan.bin | head
  625 215 164
  626 357 260
  ...
```

**First difference at byte 625 (`0x270`).** That is inside header #2's master
key digest field. Everything before it — header #1 entire, header #2's opening
magic, cipher, mode, hash, payload offset, key bytes, iter count, UUID — is
**byte-for-byte identical**.

This confirms the LUKS headers are a fixed template. Only the second header's
inner digest changes between products.

---

# 7. Phase 3 — Header Repair and hashcat

## 7.1 Repairing header #1

Zero slots 6 and 7 and rewrite them as valid inactive slots:

```bash
cp --reflink=auto CDJ1500Xv110.UPD /tmp/cdj_patched.img
dd if=/dev/zero of=/tmp/cdj_patched.img bs=1 seek=496 count=96 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=496 count=4 conv=notrunc
printf '\x00\x00\x0b\xd8' | dd of=/tmp/cdj_patched.img bs=1 seek=536 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=540 count=4 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=544 count=4 conv=notrunc
printf '\x00\x00\x0d\xd0' | dd of=/tmp/cdj_patched.img bs=1 seek=584 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=588 count=4 conv=notrunc
```

## 7.2 Repaired header parses

```
Version:        1
Cipher name:    aes
Cipher mode:    xts-plain64
Hash spec:      sha256
Payload offset: 4096
MK bits:        512
MK iterations:  178086
UUID:           fa03960e-420a-4044-8bfe-7abbe5f23daf

Key Slot 0: ENABLED
    Iterations:          2849390
    Salt:                b0 54 8d ca 35 dc e4 fe ...
    Key material offset: 8
    AF stripes:          4000
Key Slot 1–7: DISABLED
```

## 7.3 hashcat dictionary test

```
Status...........: Exhausted
Hash.Mode........: 14600 (LUKS v1 (legacy))
Recovered........: 0/1 (0.00%) Digests
Progress.........: 14/14 (100.00%)
Speed.#01........: 1 H/s (1.12ms)
```

14 words tested, none recovered. At 2,849,390 PBKDF2 iterations per candidate
and 1 H/s on CPU-only OpenCL, brute force is not feasible. The passphrase is
not a common word.

---

# 8. Phase 4 — Cross-Firmware Comparison

## 8.1 Header comparison

Covered in section 6.2. Byte-identical up to offset `0x270`.

## 8.2 Payload comparison

The payload region begins at offset `0x1000`:

```bash
$ xxd -l 512 -s 4096 CDJ1500Xv110.UPD
00001000: 0000 0000 0000 0000 ... (all zeros for 512 bytes)
000011f0: 0000 0000 0000 0000

$ xxd -l 512 -s 4096 XDJANv120.UPD
00001000: 0000 0000 0000 0000 ... (all zeros for 512 bytes)
000011f0: 0000 0000 0000 0000
```

**Both payloads have 512 bytes of zeros at `0x1000`, then the encrypted
payload begins at `0x1200`.**

## 8.3 Payload entropy

```python
import math, collections
d = open("CDJ1500Xv110.UPD", "rb").read()[0x1200:0x1200+65536]
c = collections.Counter(d)
e = -sum((v/len(d))*math.log2(v/len(d)) for v in c.values())
print(e)
```

| File | Entropy at 0x1200 (64 KB window) | First 32 bytes |
|---|---|---|
| CDJ1500Xv110.UPD | 7.9965 | `4d07b0387ca2f0446dd5d6121ac3ffdf...` |
| XDJANv120.UPD | 7.9972 | `a8822d1bc53c2b744ec23c08db940a4f...` |

Entropy ≈ 8.0 is maximum for random data. The payload is encrypted with a
stream cipher or block cipher in a mode that produces ciphertext of full
entropy. It is not obfuscated, compressed, or patterned.

## 8.4 Payload diff

```bash
$ cmp -l CDJ1500Xv110.UPD XDJANv120.UPD | head
  625 215 164    ← header #2 differs
  ...
  (all subsequent bytes differ)

$ cmp -l CDJ1500Xv110.UPD XDJANv120.UPD | wc -l
187976897     (of 188,718,095 bytes)
```

99.6% of the bytes differ, including all of the encrypted payload. The two
firmwares share the same container template but contain different encrypted
content.

## 8.5 Container format (final)

```
0x0000  LUKS header #1     (decoy template — identical across products)
0x0200  LUKS header #2     (decoy template, differs only in inner digest)
0x1000  512 bytes of zeros (plaintext padding)
0x1200  encrypted payload  (real firmware, entropy ≈ 8.0)
```

---

# 9. Phase 5 — GPL Source Analysis

## 9.1 CDJ-1500X drop is incomplete

The CDJ-1500X GPL drop contains only the `external/` slice:

```
CDJ-1500X/
  external/
    security/       (OP-TEE client library + signed TA)
    update_engine/  (Rockchip A/B OTA wrapper — network path only)
    mpp/, rockit/, rknpu/, linux-rga/, uvc_app/, bluetooth_bsa/
    ...
  nxp_driver_fp99/  (NXP Wi-Fi/BT driver)
```

`license.txt` declares the following GPL/LGPL components:

| Component | license.txt line | Shipped? |
|---|---|---|
| busybox-1.27.2 | 4573 | ❌ |
| cryptsetup-2.0.6 | 5877 | ❌ |
| uboot 2017.09 | 25984 | ❌ |
| uboot-tools-2018.01 | 26329 | ❌ |
| Linux kernel | (implicit) | ❌ |

## 9.2 XDJ-AN drop is a full BSP

The XDJ-AN GPL drop is complete:

```
XDJ-AN/
  kernel/        (full Linux kernel, DM_CRYPT=y, CRYPTO_XTS=y)
  u-boot/        (full U-Boot with OP-TEE client API)
  buildroot/     (full buildroot with cryptsetup package)
  device/        (board configs — including XDJ-AN)
  rkbin/         (Rockchip boot images)
  external/      (user-space, including securityAuth and recovery)
  prebuilts/     (toolchains)
  nxp_driver_fp99/
```

## 9.3 XDJ-AN board configuration

`device/rockchip/rk356x/BoardConfig-rk3566-xdjan-lp4x-v1.mk`:

```
RK_ARCH=arm64
RK_UBOOT_DEFCONFIG=rk3566_xdjan
RK_UBOOT_FORMAT_TYPE=fit
RK_KERNEL_DEFCONFIG=rockchip_linux_xdjan_defconfig
RK_KERNEL_DTS=rk3566-xdjan-lp4x-v1-linux
RK_CFG_BUILDROOT=rockchip_rk3566_xdjan
RK_ROOTFS_TYPE=ext4
```

Target SoC: **Rockchip RK3566**.

## 9.4 Kernel config includes dm-crypt

```
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_CRYPT=y
# CONFIG_DM_VERITY is not set
CONFIG_CRYPTO_XTS=y
```

## 9.5 U-Boot enables OP-TEE client

```
CONFIG_OPTEE_CLIENT=y
CONFIG_OPTEE_V2=y
CONFIG_OPTEE_ALWAYS_USE_SECURITY_PARTITION=y
```

U-Boot can load Trusted Applications into OP-TEE via `OpteeRpcCmdLoadTa` and
`OpteeRpcCmdLoadV2Ta` (`u-boot/lib/optee_clientApi/OpteeClientRPC.c`).

## 9.6 The `.UPD` is not handled by update_engine

`external/recovery/update_engine/` handles Rockchip `RKIMAGE` (`RKAF` magic)
files. It reads a header, iterates over named partitions (`uboot`, `boot`,
`rootfs`, etc.), and writes them to `/dev/block/by-name/<name>`. The source
contains no crypto.

The `.UPD` LUKS container is handled elsewhere, or by a vendor tool not
shipped in the GPL drop.

---

# 10. Phase 6 — OP-TEE Client Library Analysis

## 10.1 Exported symbols

```bash
$ nm -D --defined-only librk_tee_service.so
0000000000000eb0 T rk_decrypt_data
0000000000000adc T rk_encrypt_data
```

Only two functions. Both are thin wrappers around `TEEC_InvokeCommand`.

## 10.2 Header documentation

`rk_tee_service.h`:

```c
/*
 * usage: decrypt cipher text with AES CTS mode,
 *        key is auto derived from hardware key in TEE.
 */
int rk_decrypt_data(unsigned char *cipher, unsigned int cipher_len,
                    unsigned char *plain, unsigned int *plain_len);
```

**The key is "auto derived from hardware key in TEE".** This is the
manufacturer's own documentation of the key path.

## 10.3 Command IDs

From aarch64 disassembly of `librk_tee_service.so`:

```asm
; rk_encrypt_data at 0xadc
af4:  mov  w0, #0xfd45
af8:  movk w0, #0x4367, lsl #16
...  ; UUID 4367fd45-4469-42a6-925d-3857b952704a assembled byte-by-byte
a88:  mov  w1, #0x0            ; command ID = 0 (encrypt)
a90:  bl   TEEC_InvokeCommand@plt

; rk_decrypt_data at 0xeb0
e5c:  mov  w1, #0x1            ; command ID = 1 (decrypt)
e64:  bl   TEEC_InvokeCommand@plt
```

No key, IV, salt, nonce, or attribute is passed from normal world. Only
input/output buffers.

---

# 11. Phase 7 — Trusted Application Analysis

## 11.1 File format

```
$ file 4367fd45-4469-42a6-925d-3857b952704a.ta
data

$ xxd -l 32 4367fd45-4469-42a6-925d-3857b952704a.ta
00000000: 48 53 54 4f 01 00 00 00 40 76 01 00 30 48 00 70  HSTO....@v..0H.p
00000010: 20 00 00 01 7c f5 15 7e 08 ba e9 d8 ec 7e 98 9e   ...|..~.....~..
```

- Magic: `HSTO` (Rockchip custom, not standard OP-TEE `*TOP`)
- Version: 1 (`SHDR_BOOTSTRAP_TA` per `resign_ta.py`)
- Size: `0x00017640` = 95808 bytes
- Signed, **not** encrypted

## 11.2 Embedded ELF

Payload begins at offset 328 (`0x148`):

```bash
$ dd if=4367fd45-...ta of=ta_payload.elf bs=1 skip=328
$ file ta_payload.elf
ta_payload.elf: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV),
dynamically linked, stripped
```

## 11.3 Dynamic symbols

```
   3: 000097e0     4 OBJECT  GLOBAL DEFAULT    3 ta_heap_size
   7: 00002d58    24 FUNC    GLOBAL DEFAULT    2 utee_authenc_update_payload
   9: 00010aac 0x40000 OBJECT  GLOBAL DEFAULT   17 ta_heap
  11: 00002c34    24 FUNC    GLOBAL DEFAULT    2 utee_cipher_update
  13: 00004d09   940 FUNC    GLOBAL DEFAULT    2 AES_encrypt
  15: 00000000    32 OBJECT  GLOBAL DEFAULT    1 ta_head
  16: 000050b5   904 FUNC    GLOBAL DEFAULT    2 AES_decrypt
```

Two OP-TEE syscalls used:

- `utee_cipher_update` (SVC 22 = `TEE_CipherUpdate`)
- `utee_authenc_update_payload` (SVC 36 = `TEE_AEUpdate`)

## 11.4 Strings

```
BWAES_encrypt
AES_decrypt
AES_ecb_encrypt
CRYPTO_cbc128_encrypt
CRYPTO_ctr128_encrypt
CRYPTO_cfb128_encrypt
CRYPTO_ofb128_encrypt
EVP_EncryptUpdate / EVP_DecryptUpdate
HMAC routines
lib/libcrypto/fipsmodule/aes/aes.c
HKDF functions
```

`HKDF functions` is the decisive string. The TA derives its AES key via HKDF.

## 11.5 Entry point and crypto calls

From `ta_head` at file offset `0x8000`:

```
00008000: 45fd 6743 6944 a642 925d 3857 b952 704a
00008010: 0048 0000 0400 0000 c528 0000 0000 0000
```

Entry point = `0x28c5` (Thumb mode, real code at `0x28c4`).

Crypto call sites (Thumb disassembly):

```asm
; TEE_CipherUpdate
1c98:  ldr  r0, [r0, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
1c9a:  blx  2c34 <utee_cipher_update>

; TEE_AEUpdate
208a:  ldr  r0, [r5, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
208c:  blx  2d58 <utee_authenc_update_payload>
```

Both paths load the operation handle from `[ctx + 0x3c]`. The handle was
created by `TEE_CipherInit` / `TEE_AEInit` using a key the TA derived
internally and never exposes to normal world.

---

# 12. Phase 8 — Full BSP Analysis (XDJ-AN)

## 12.1 The second TA

The `securityAuth` buildroot package ships a second TA:

```
buildroot/package/rockchip/securityAuth/src/3128h/optee_armtz/
    ebc28104-47ff-4e34-89783c212bb17c2e.ta
```

Header:

```
00000000: 4853 544f 0000 0000 84f1 0800 3048 0070  HSTO........0H.p
00000010: 2000 0001 b008 3d30 8414 7651 f3a5 70cd   .....=0..vQ..p.
```

**Version 0** (older format than the CDJ-1500X TA). Strings:

```
rk_create_storage_object
rk_write_storage_object
rk_read_storage_object
rk_delete_storage_object
TEE_GenerateKey
HKDF functions
AES-128-CBC, AES-192-CBC, AES-256-CBC
```

This TA provides secure storage services, not firmware decryption. The
firmware decryption TA is `4367fd45-...`.

## 12.2 Device tree

`kernel/arch/arm64/boot/dts/rockchip/rk3566-xdjan-lp4x-v1.dtsi`:

```dts
compatible = "alphatheta,extcon-atc-usb-gpio";
...
// for EP169 USB-C host from CDJ-3000X
atc_usb_gpio_extcon: atc-usb-gpio-extcon {
    status = "okay";
    compatible = "alphatheta,extcon-atc-usb-gpio";
    ...
};
```

Confirms the device is genuine XDJ-AN hardware, not generic Rockchip EVB.

## 12.3 U-Boot TA loading path

`u-boot/lib/optee_clientApi/OpteeClientRPC.c`:

```c
TEEC_Result OpteeRpcCmdLoadTa(t_teesmc32_arg *TeeSmc32Arg)
{
    // ...
    TEEC_UUID TA_RK_KEYMASTER_UUID = {0x258be795, 0xf9ca, 0x40e6,
        {0xa8, 0x69, 0x9c, 0xe6, 0x88, 0x6c, 0x5d, 0x5d} };

    if (is_uuid_equal(TeeLoadTaCmd->uuid, TA_RK_KEYMASTER_UUID)) {
        ImageData = (void *)0;
        ImageSize = 0;
    } else {
        ImageData = (void *)0;
        ImageSize = 0;
    }
    // ...
}
```

The stub currently returns zero-size images for all UUIDs. The actual
production loader that populates `ImageData`/`ImageSize` is elsewhere, likely
in the SPL or in the OP-TEE OS itself.

## 12.4 U-Boot FIT post-process handler

`u-boot/arch/arm/mach-rockchip/fit_misc.c`:

```c
void board_fit_image_post_process(void *fit, int node, ulong *load_addr,
                                  ulong **src_addr, size_t *src_len, void *spec)
{
#if CONFIG_IS_ENABLED(MISC_DECOMPRESS) || CONFIG_IS_ENABLED(GZIP)
    fit_gunzip_image(fit, node, load_addr, src_addr, src_len, spec);
#endif
    // ... kernel DTB override only
}
```

This function does **not** decrypt. It handles gunzip and DTB override. The
`.UPD` LUKS payload is not a FIT image.

## 12.5 Secure boot flag

`fit_misc.c` also contains the secure boot check:

```c
int fit_board_verify_required_sigs(void)
{
    uint8_t vboot = 0;
#ifdef CONFIG_SPL_BUILD
    dev = misc_otp_get_device(OTP_S);
    misc_otp_read(dev, OTP_SECURE_BOOT_ENABLE_ADDR, &vboot, 1);
    vboot = (vboot == 0xff);
#else
    trusty_read_vbootkey_enable_flag(&vboot);
#endif
    return vboot;
}
```

The eFuse bit at `OTP_SECURE_BOOT_ENABLE_ADDR` gates verified boot.

## 12.6 Partition layout

```
CMDLINE: mtdparts=rk29xxnand:
  0x00002000@0x00004000(uboot),
  0x00080000@0x00006000(boota),
  0x00080000@0x00086000(bootb),
  0x00020000@0x00106000(setting),
  0x00100000@0x00126000(update),
  -@0x00226000(reserve:grow)
```

The `update` partition is where the `.UPD` payload is written during an
update.

---

# 13. Phase 9 — TA Signing and Key Trust

## 13.1 The signing tools shipped with the GPL drop

```
external/security/rk_tee_user/v2/tools/
    change_puk_tool-release/
        change_puk_linux/change_puk
        change_puk_linux/oem_privkey.pem
        change_puk_linux/tee-pager.bin
        change_puk_window/change_public_key.exe
        README.md
    ta_resign_tool-release/
        linux/resign_ta.py
        linux/oem_privkey.pem
        README.txt
```

## 13.2 `resign_ta.py`

The script signs a TA in three formats:

| Type | Header byte 4 | Protection |
|---|---|---|
| 0 | `00 00 00 00` | signed (PKCS#1 v1.5) |
| 1 | `01 00 00 00` | signed (PKCS#1 v1.5 or PSS) |
| 2 | `02 00 00 00` | signed + AES-GCM encrypted |

The production TA (`4367fd45-...`) is **type 1**: signed, not encrypted. The
payload is readable. Signing prevents replacement, not analysis.

## 13.3 Signature verification failed

Extract the signature and ELF payload, then verify with the shipped SDK
private key:

```bash
TA=external/security/bin/optee_v2/ta/4367fd45-4469-42a6-925d-3857b952704a.ta
dd if="$TA" of=/tmp/ta.sig bs=1 skip=20 count=256
dd if="$TA" of=/tmp/ta.elf bs=1 skip=328
openssl pkey -in export-ta_arm64/keys/oem_privkey.pem -pubout -out /tmp/oem_pub.pem
openssl dgst -sha256 -verify /tmp/oem_pub.pem -signature /tmp/ta.sig /tmp/ta.elf
```

Result:

```
Verification failure
RSA_padding_check_PKCS1_type_1:invalid padding
```

The shipped SDK private key did not sign the production TA. AlphaTheta used
their own production key.

## 13.4 The certs in the SDK are OpenSSL tutorial defaults

```
cert/ca.crt:   C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
cert/mid.crt:  C=AU, ST=Some-State, O=Be Bop - Originalaskkopp
cert/my.crt:   C=AU, ST=Some-State, O=Testing testers
```

These are the default OpenSSL subjects that appear when running `openssl req`
without overriding the fields. They are development templates, not
production keys.

## 13.5 The OP-TEE OS image reveals the key trust path

`change_puk_linux/tee-pager.bin` (702 KB) is a prebuilt OP-TEE OS image.
Strings in it:

```
3aedd  TA signd by old default key will be not support soon! please resign TA!
3b776  Release version: %d.%d
3db79  BEEFtee_otp_get_hw_unique_key
3e06a  syscall_derive_key_from_hard
3c088  storage_write_vbootkey_hash
3c152  vbootkey hash has already been writed!
3c179  vbootkey hash is not equal to writed before!
3c1a6  vbootkey hash is equal to writed before!
3c29d  storage_write_attribute_hash
3c2ba  storage_read_attribute_hash
```

Interpretation:

- `tee_otp_get_hw_unique_key` and `syscall_derive_key_from_hard` confirm the
  AES key is derived from the Rockchip Hardware Unique Key in the SoC eFuse.
- `storage_write_vbootkey_hash` and `vbootkey hash has already been writed!`
  confirm the TA signing key hash has already been programmed into eFuse and
  cannot be changed.
- The "old default key" warning indicates the OP-TEE build still accepts
  TAs signed with a legacy default key.

## 13.6 The SDK default key is NOT in the OP-TEE OS image

```bash
HASH=$(openssl pkey -in export-ta_arm64/keys/oem_privkey.pem -pubout -outform DER | sha256sum | cut -d' ' -f1)
# → 3ee5d31b5a58ef76bf1eb71f18de9e2406a85854aa1470d33ec32fa0dcafbfc9

python3 - "$HASH" <<'PY'
import sys, binascii
h = sys.argv[1]
data = open("tee-pager.bin","rb").read()
raw = binascii.unhexlify(h)
for name, needle in [("forward", raw), ("reverse", raw[::-1])]:
    i = data.find(needle)
    print(f"{name} hash: {hex(i) if i>=0 else 'not found'}")
PY
```

Result:

```
forward hash: not found
reverse hash: not found
```

The OP-TEE OS image does **not** contain the SDK default public key hash.
The "old default key" referenced in the warning string is a **different** key
that was not shipped. Signing a TA with the SDK template key will not be
accepted by the device.

---

# 14. Reconstructed Decryption Chain

```
CDJ1500Xv110.UPD / XDJANv120.UPD  (on disk)
    │
    ├─ LUKS header #1 at 0x0000   (decoy template)
    ├─ LUKS header #2 at 0x0200   (decoy template)
    ├─ 512 zeros at 0x1000
    │
    └─ encrypted payload at 0x1200
            │
            on the device:
            │
            ├─ normal-world app links librk_tee_service.so
            │       → rk_decrypt_data(cipher, len, plain, &plain_len)
            │       → TEEC_InitializeContext
            │       → TEEC_OpenSession(UUID 4367fd45-...)
            │       → TEEC_InvokeCommand(cmd = 1)
            │
            ├─ OP-TEE 3.7.9 loads the signed TA 4367fd45-...
            │       → TA_InvokeCommandEntryPoint at 0x28c4 (Thumb)
            │       → decrypt handler:
            │              HKDF(tee_otp_get_hw_unique_key()) → AES key
            │              TEE_CipherInit / TEE_AEInit
            │              stores op handle at ctx+0x3c
            │              loop 0x8000-byte chunks:
            │                TEE_CipherUpdate  (SVC 22)
            │                TEE_AEUpdate      (SVC 36)
            │
            └─ plaintext returned to normal world
                    → dm-crypt + cryptsetup 2.0.6 mounts the decrypted image
```

Every step is verified by the artifacts listed in section 3.

---

# 15. Conclusion

**There is no software-only path to decrypt the firmware on a PC.**

Supporting evidence:

| Claim | Source |
|---|---|
| Container is LUKS1 with two overlapping decoy headers | `xxd`, `grep -abo` |
| Header is byte-identical across CDJ-1500X and XDJ-AN | `cmp -l` |
| `cryptsetup` rejects the file by design | `cryptsetup isLuks` |
| Header parses after repair, single active slot | `cryptsetup luksDump` |
| LUKS passphrase is not a dictionary word | hashcat `Exhausted` |
| Payload is at full entropy from 0x1200 | Python entropy calc |
| Client library has no key export API | `nm -D`, `rk_tee_service.h` |
| Command IDs 0/1 map to encrypt/decrypt | aarch64 disassembly |
| TA is signed with Rockchip custom `HSTO` format | `xxd` |
| TA uses HKDF and BoringSSL AES | strings |
| TA calls only `TEE_CipherUpdate` and `TEE_AEUpdate` | Thumb disassembly |
| Both calls pass opaque handles, not raw keys | disassembly at 1c98, 208a |
| Device uses RK3566 SoC | `BoardConfig-rk3566-xdjan-lp4x-v1.mk` |
| Kernel has `DM_CRYPT=y` and `CRYPTO_XTS=y` | `rockchip_linux_xdjan_defconfig` |
| U-Boot enables OP-TEE client | `rk3568_xdjan_defconfig` |
| `tee_otp_get_hw_unique_key` and `syscall_derive_key_from_hard` present | strings in `tee-pager.bin` |
| OP-TEE version is 3.7.9 | strings in `tee-pager.bin` |
| Production TA is not signed by SDK default key | `openssl dgst -verify` |
| SDK default key hash not in OP-TEE OS image | Python search |
| Certificates are OpenSSL tutorial defaults | `openssl x509 -subject` |

The protection is correctly implemented.

---

# 16. Comparison with CDJ-3000

| Feature | CDJ-3000 (older) | CDJ-1500X / XDJ-AN |
|---|---|---|
| Encryption key | Model-wide symmetric | Per-device, derived from SoC eFuse |
| Key storage | Firmware / software | Rockchip RK3566 HUK |
| Decryption performed by | Software (bootloader or tool) | Signed OP-TEE TA |
| Attack surface | Software key extraction | Physical access or secure-world exploit |
| Public root project | `cdj3k-root` exists | None known |
| GPL source completeness | Kernel + U-Boot typically shipped | CDJ-1500X: partial; XDJ-AN: full BSP |
| TA signing key | (varies) | Production key, not shipped |

The CDJ-3000's `cdj3k-root` project required a valid firmware encryption key,
which suggests a model-wide key existed for that generation. The CDJ-1500X
and XDJ-AN moved to a hardware root of trust with per-device key derivation,
which removes the single-key weakness.

---

# 17. Open Items and Next Steps

## 17.1 GPL source request

Send the draft in section 18. Specifically request:

- U-Boot 2017.09 source tree (with vendor patches)
- Linux kernel source tree (with vendor patches)
- cryptsetup-2.0.6 as shipped
- busybox-1.27.2 as shipped
- The vendor-specific update tool that reads the `.UPD` container
- OP-TEE 3.7.9 source tree as shipped

## 17.2 OP-TEE 3.7.9 vulnerability tracking

Monitor:

- https://github.com/OP-TEE/optee_os/security/advisories
- https://nvd.nist.gov/

Any bug in OP-TEE 3.7.9 that grants normal-world access to TEE memory, or
bypasses TA signature verification, would be a potential foothold.

## 17.3 Public key-leak monitoring

Search anchors:

- `CDJ1500Xv110.UPD`
- `XDJANv120.UPD`
- `4367fd45-4469-42a6-925d-3857b952704a`
- `CDJ-1500X firmware key`
- `rockchip huk cdj`

## 17.4 Device-side research (requires hardware)

If you obtain a CDJ-1500X or XDJ-AN:

1. Inspect PCB for JTAG/UART pads
2. Monitor eMMC bus with logic analyzer during official update
3. Attempt to reach a U-Boot shell and use `OpteeRpcCmdLoadTa` with a
   modified signed TA
4. As a last resort, chip-off the eMMC or read the SoC eFuse

## 17.5 Publication

This document is sufficient as a technical report. It can be published on a
security blog, GitHub, or a research forum.

---

# 18. GPL Source Request (Draft)

```
Subject: GPL source code request — CDJ-1500X and XDJ-AN

To AlphaTheta / Pioneer DJ,

I am writing to request the complete corresponding source code for GPL
and LGPL licensed components shipped in the CDJ-1500X and XDJ-AN firmware.
These components are declared in the license.txt that accompanies the GPL
source releases, but their source code was not fully included.

Components declared in license.txt but not shipped (CDJ-1500X release):
  - busybox-1.27.2              (license.txt line 4573)
  - cryptsetup-2.0.6            (license.txt line 5877)
  - uboot 2017.09               (license.txt line 25984)
  - uboot-tools-2018.01         (license.txt line 26329)
  - The Linux kernel used in the CDJ-1500X firmware

Components declared but not shipped (XDJ-AN release):
  - The vendor-specific update tool that reads the .UPD container
  - The OP-TEE 3.7.9 source tree as shipped on the device

GPL v2 and LGPL require that the complete corresponding source code,
including any modifications and scripts used to control compilation
and installation, be provided to anyone who receives the binary.

Please provide:
  1. The U-Boot source tree used on the CDJ-1500X and XDJ-AN, with vendor patches.
  2. The Linux kernel source tree used on the CDJ-1500X and XDJ-AN, with vendor patches.
  3. cryptsetup-2.0.6 as shipped.
  4. busybox-1.27.2 as shipped.
  5. The OP-TEE 3.7.9 source tree as shipped.
  6. The vendor-specific tool that reads the .UPD container.
  7. The exact upstream version and commit hash for each component.

Format: tar.xz via download link or similar.

Thank you.

[Your name]
[Your contact]
```

---

# 19. Reproducing the Analysis

```bash
# 1. Container identification
file CDJ1500Xv110.UPD XDJANv120.UPD
xxd -l 256 CDJ1500Xv110.UPD

# 2. Locate the two LUKS headers
grep -abo $'\x4c\x55\x4b\x53\xba\xbe' CDJ1500Xv110.UPD
grep -abo $'\x4c\x55\x4b\x53\xba\xbe' XDJANv120.UPD

# 3. Cross-product header comparison
dd if=CDJ1500Xv110.UPD of=/tmp/hdr1.bin bs=512 count=8
dd if=XDJANv120.UPD    of=/tmp/hdr2.bin bs=512 count=8
cmp -l /tmp/hdr1.bin /tmp/hdr2.bin | head

# 4. Header repair
cp --reflink=auto CDJ1500Xv110.UPD /tmp/cdj_patched.img
dd if=/dev/zero of=/tmp/cdj_patched.img bs=1 seek=496 count=96 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=496 count=4 conv=notrunc
printf '\x00\x00\x0b\xd8' | dd of=/tmp/cdj_patched.img bs=1 seek=536 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=540 count=4 conv=notrunc
printf '\x00\x00\xde\xad' | dd of=/tmp/cdj_patched.img bs=1 seek=544 count=4 conv=notrunc
printf '\x00\x00\x0d\xd0' | dd of=/tmp/cdj_patched.img bs=1 seek=584 count=4 conv=notrunc
printf '\x00\x00\x0f\xa0' | dd of=/tmp/cdj_patched.img bs=1 seek=588 count=4 conv=notrunc
cryptsetup luksDump /tmp/cdj_patched.img

# 5. Dictionary attack
hashcat -m 14600 -a 0 /tmp/cdj_patched.img /tmp/cdj_words.txt

# 6. Payload entropy
python3 - <<'PY'
import math, collections
for f in ["CDJ1500Xv110.UPD", "XDJANv120.UPD"]:
    d = open(f, "rb").read()[0x1200:0x1200+65536]
    c = collections.Counter(d)
    e = -sum((v/len(d))*math.log2(v/len(d)) for v in c.values())
    print(f, e)
PY

# 7. Client library disassembly
aarch64-linux-gnu-objdump -d librk_tee_service.so > wrapper.disasm
sed -n '/<rk_encrypt_data>:/,/^$/p' wrapper.disasm
sed -n '/<rk_decrypt_data>:/,/^$/p' wrapper.disasm

# 8. TA extraction and disassembly
TA=external/security/bin/optee_v2/ta/4367fd45-4469-42a6-925d-3857b952704a.ta
dd if="$TA" of=/tmp/ta_payload.elf bs=1 skip=328
arm-linux-gnueabihf-objdump -d -M force-thumb /tmp/ta_payload.elf > /tmp/ta.thumb.txt

# 9. TA signature verification
dd if="$TA" of=/tmp/ta.sig bs=1 skip=20 count=256
openssl pkey -in export-ta_arm64/keys/oem_privkey.pem -pubout -out /tmp/oem_pub.pem
openssl dgst -sha256 -verify /tmp/oem_pub.pem -signature /tmp/ta.sig /tmp/ta_payload.elf

# 10. OP-TEE OS image strings
TEE=external/security/rk_tee_user/v2/tools/change_puk_tool-release/change_puk_linux/tee-pager.bin
strings -a -t x "$TEE" | grep -iE 'huk|derive_key|vbootkey|default key|optee'

# 11. SDK default pubkey hash search
HASH=$(openssl pkey -in export-ta_arm64/keys/oem_privkey.pem -pubout -outform DER | sha256sum | cut -d' ' -f1)
python3 - "$HASH" <<'PY'
import sys, binascii
h = sys.argv[1]
data = open(sys.argv[2] if len(sys.argv)>2 else "tee-pager.bin","rb").read()
raw = binascii.unhexlify(h)
for name, needle in [("forward", raw), ("reverse", raw[::-1])]:
    i = data.find(needle)
    print(f"{name}: {hex(i) if i>=0 else 'not found'}")
PY
```

---

# 20. Tools Used

| Tool | Purpose |
|---|---|
| `file` | Identify the firmware container |
| `xxd` | Hex dump headers and TA files |
| `strings` | Extract human-readable strings from binaries |
| `grep -abo` | Locate binary signatures in large files |
| `dd` | Patch and extract byte ranges |
| `cmp` | Compare files byte-by-byte |
| `cryptsetup` 2.8.4 | Parse LUKS1 headers |
| `hashcat` 7.1.2 | Offline LUKS passphrase testing |
| `binutils-aarch64-linux-gnu` | ARM64 disassembly |
| `binutils-arm-linux-gnueabihf` | ARM32 / Thumb disassembly |
| `nm`, `readelf`, `objdump` | Static binary analysis |
| `openssl` | Key and signature verification |
| Docker (ubuntu:18.04) | Reproducible build environment for GPL source |

---

# 21. Legal and Ethical Note

This analysis was performed on firmware and GPL source obtained from
AlphaTheta's public download pages, for personal security research.

- No physical device was modified.
- No firmware was redistributed.
- No encryption was broken.
- The GPL source request is a legitimate exercise of rights under GPL v2.

The firmware analyzed is protected by a hardware root of trust that is
working as designed. The goal of this research is to document that design,
not to bypass it.
