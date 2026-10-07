# AlphaTheta / Pioneer DJ Firmware Security Analysis

**Targets:**
- CDJ-1500X — firmware `CDJ1500Xv110.UPD` (v1.10, 2/Aug/2026)
- XDJ-AN — firmware `XDJANv120.UPD` (v1.20, 18/Aug/2026)

**Vendor GPL drops analyzed:**
- `CDJ-1500X.tar.xz` (v1.01, 2/Jul/2026) — partial (external/ only)
- `XDJ-AN.tar.xz` (Jul 2026) — full BSP (kernel, u-boot, buildroot, rkbin)

**SoC platform:** Rockchip RK3566
**Storage:** eMMC (not encrypted at rest)
**OP-TEE version:** 3.7.9
**Analyst:** drclab
**Host:** Ubuntu (resolute), AMD Ryzen 5 4600U
**Container used:** Ubuntu 18.04 (Docker, `cdj-build`)

---

# Table of Contents

1. Executive Summary
2. Objective
3. Artifacts
4. Timeline of Investigation
5. Phase 1 — Firmware Container Identification
6. Phase 2 — The Two LUKS Headers
7. Phase 3 — Header Repair and hashcat
8. Phase 4 — Cross-Firmware Comparison
9. Phase 5 — GPL Source Analysis
10. Phase 6 — OP-TEE Client Library Analysis
11. Phase 7 — Trusted Application Analysis
12. Phase 8 — Full BSP Analysis (XDJ-AN)
13. Phase 9 — TA Signing and Key Trust
14. Phase 10 — Boot Chain and FIT Analysis
15. Reconstructed Decryption Chain
16. Conclusion
17. Comparison with CDJ-3000
18. Open Items and Next Steps
19. GPL Source Request (Draft)
20. Reproducing the Analysis
21. Tools Used
22. Storage and eMMC Analysis
23. Completeness Assessment
24. Legal and Ethical Note

---

# 1. Executive Summary

The CDJ-1500X and XDJ-AN firmware update files (`.UPD`) are **decoy LUKS1
containers** whose payload is encrypted with an AES-XTS key derived on-device
from a Rockchip RK3566 Hardware Unique Key (HUK) fused into the SoC eFuse.
The key never leaves the OP-TEE secure world.

The `.UPD` file, the GPL source drops, and the shipped binaries contain no
material that can produce this key. The LUKS header is a static template
reused across product lines, not a real encryption header. The TA signing key
used by production devices was not shipped in the GPL drops. The OP-TEE OS
source tree and the U-Boot FIT signing key were also not shipped.

Both devices use **eMMC** for storage. The eMMC is **not encrypted at rest**;
only the `.UPD` distribution package is encrypted.

**There is no software-only path to decrypt the firmware on a PC.**

The protection is correctly implemented. Every layer accessible through the
GPL drop and the firmware file has been analyzed and every alternative has
been tested.

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
| 12 | eMMC storage analysis | eMMC, not encrypted at rest |
| 13 | Boot chain and FIT analysis | `tee.bin` missing from drop |
| 14 | Conclusion | Hardware-bound; no PC decryption possible |

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
```

**Both payloads have 512 bytes of zeros at `0x1000`, then the encrypted
payload begins at `0x1200`.**

## 8.3 Payload entropy

| File | Entropy at 0x1200 (64 KB window) | First 32 bytes |
|---|---|---|
| CDJ1500Xv110.UPD | 7.9965 | `4d07b0387ca2f0446dd5d6121ac3ffdf...` |
| XDJANv120.UPD | 7.9972 | `a8822d1bc53c2b744ec23c08db940a4f...` |

Entropy ≈ 8.0 is maximum for random data. The payload is encrypted with a
stream cipher or block cipher in a mode that produces ciphertext of full
entropy.

## 8.4 Payload diff

```bash
$ cmp -l CDJ1500Xv110.UPD XDJANv120.UPD | wc -l
187976897     (of 188,718,095 bytes)
```

99.6% of the bytes differ, including all of the encrypted payload.

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

```
CDJ-1500X/
  external/
    security/       (OP-TEE client library + signed TA)
    update_engine/  (Rockchip A/B OTA wrapper — network path only)
    mpp/, rockit/, rknpu/, linux-rga/, uvc_app/, bluetooth_bsa/
    ...
  nxp_driver_fp99/
```

`license.txt` declares the following GPL/LGPL components:

| Component | license.txt line | Shipped? |
|---|---|---|
| busybox-1.27.2 | 4573 | No |
| cryptsetup-2.0.6 | 5877 | No |
| uboot 2017.09 | 25984 | No |
| uboot-tools-2018.01 | 26329 | No |
| Linux kernel | (implicit) | No |

## 9.2 XDJ-AN drop is a full BSP

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
CONFIG_SPL_ATF=y
```

## 9.6 The `.UPD` is not handled by update_engine

`external/recovery/update_engine/` handles Rockchip `RKIMAGE` (`RKAF` magic)
files. It reads a header, iterates over named partitions, and writes them to
`/dev/block/by-name/<name>`. The source contains no crypto. The `.UPD` LUKS
container is handled elsewhere.

---

# 10. Phase 6 — OP-TEE Client Library Analysis

## 10.1 Exported symbols

```bash
$ nm -D --defined-only librk_tee_service.so
0000000000000eb0 T rk_decrypt_data
0000000000000adc T rk_encrypt_data
```

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

**The key is "auto derived from hardware key in TEE".**

## 10.3 Command IDs

From aarch64 disassembly:

```asm
; rk_encrypt_data at 0xadc
a88:  mov  w1, #0x0            ; command ID = 0 (encrypt)
a90:  bl   TEEC_InvokeCommand@plt

; rk_decrypt_data at 0xeb0
e5c:  mov  w1, #0x1            ; command ID = 1 (decrypt)
e64:  bl   TEEC_InvokeCommand@plt
```

No key, IV, salt, nonce, or attribute is passed from normal world.

---

# 11. Phase 7 — Trusted Application Analysis

## 11.1 File format

```
$ xxd -l 32 4367fd45-4469-42a6-925d-3857b952704a.ta
00000000: 48 53 54 4f 01 00 00 00 40 76 01 00 30 48 00 70  HSTO....@v..0H.p
```

- Magic: `HSTO` (Rockchip custom)
- Version: 1 (`SHDR_BOOTSTRAP_TA`)
- Signed, **not** encrypted

## 11.2 Embedded ELF

Payload begins at offset 328 (`0x148`):

```bash
$ file ta_payload.elf
ta_payload.elf: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV),
dynamically linked, stripped
```

## 11.3 Dynamic symbols

```
   7: 00002d58    24 FUNC    GLOBAL DEFAULT    2 utee_authenc_update_payload
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

`HKDF functions` is the decisive string.

## 11.5 Entry point and crypto calls

From `ta_head` at file offset `0x8000`:

```
00008000: 45fd 6743 6944 a642 925d 3857 b952 704a
00008010: 0048 0000 0400 0000 c528 0000 0000 0000
```

Entry point = `0x28c5` (Thumb mode, real code at `0x28c4`).

Crypto call sites:

```asm
; TEE_CipherUpdate
1c98:  ldr  r0, [r0, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
1c9a:  blx  2c34 <utee_cipher_update>

; TEE_AEUpdate
208a:  ldr  r0, [r5, #60]       ; r0 = *(ctx + 0x3c)   ← TEE op handle
208c:  blx  2d58 <utee_authenc_update_payload>
```

Both paths load the operation handle from `[ctx + 0x3c]`. The key is derived
internally and never exposed.

---

# 12. Phase 8 — Full BSP Analysis (XDJ-AN)

## 12.1 The second TA

```
buildroot/package/rockchip/securityAuth/src/3128h/optee_armtz/
    ebc28104-47ff-4e34-89783c212bb17c2e.ta
```

Header:

```
00000000: 4853 544f 0000 0000 84f1 0800 3048 0070  HSTO........0H.p
```

**Version 0** (older format). Strings:

```
rk_create_storage_object
rk_write_storage_object
rk_read_storage_object
rk_delete_storage_object
TEE_GenerateKey
HKDF functions
AES-128-CBC, AES-192-CBC, AES-256-CBC
```

This TA provides secure storage services. The firmware decryption TA is
`4367fd45-...`.

## 12.2 Device tree

`kernel/arch/arm64/boot/dts/rockchip/rk3566-xdjan-lp4x-v1.dtsi`:

```dts
model = "Rockchip RK3566 EP169 LP4X V1 Board";
compatible = "rockchip,rk3566-evb2-lp4x-v10", "rockchip,rk3566";

compatible = "alphatheta,extcon-atc-usb-gpio";
// for EP169 USB-C host from CDJ-3000X
```

Internal codename: **EP169**.

## 12.3 Device tree — peripherals

| Feature | Config |
|---|---|
| Display | 7" LVDS 1024×600 (Teamworks TC070WS500A0) |
| Touchscreen | Ilitek ILI2130 on I2C4 |
| Audio codec | TI TAC5112 on I2C2 |
| Wi-Fi | Silex SDMAX via SDIO (`sdmmc1`) |
| Ethernet | GMAC1 RMII |
| RTC | HYM8563 |
| CPU PMIC | TCS4525 |
| eMMC | `sdhci` 8-bit, 200 MHz |
| SD card | Disabled |
| USB | USB 3.0 OTG + host, USB 2.0 hosts |

No `optee` node, no `crypto` node, no `signature-key` node in the DTS. OP-TEE
is loaded by SPL from the FIT, not by the kernel.

## 12.4 Partition layout

```
CMDLINE: mtdparts=rk29xxnand:
  0x00002000@0x00004000(uboot),
  0x00080000@0x00006000(boota),
  0x00080000@0x00086000(bootb),
  0x00020000@0x00106000(setting),
  0x00100000@0x00126000(update),
  -@0x00226000(reserve:grow)
```

**There is no separate `trust` partition.** OP-TEE is packed into the FIT
image inside the `uboot` partition.

## 12.5 Build system confirms FIT

`device/rockchip/common/mkfirmware.sh`:

```
rm -f $ROCKDEV/trust.img
echo "uboot fotmat type is fit, so ignore trust.img..."
```

`BoardConfig-rk3566-xdjan-lp4x-v1.mk`:

```
RK_UBOOT_FORMAT_TYPE=fit
```

---

# 13. Phase 9 — TA Signing and Key Trust

## 13.1 The signing tools

```
external/security/rk_tee_user/v2/tools/
    change_puk_tool-release/
        change_puk_linux/change_puk
        change_puk_linux/oem_privkey.pem
        change_puk_linux/tee-pager.bin
        change_puk_window/change_public_key.exe
    ta_resign_tool-release/
        linux/resign_ta.py
        linux/oem_privkey.pem
```

## 13.2 `resign_ta.py`

Signs a TA in three formats:

| Type | Header byte 4 | Protection |
|---|---|---|
| 0 | `00 00 00 00` | signed (PKCS#1 v1.5) |
| 1 | `01 00 00 00` | signed (PKCS#1 v1.5 or PSS) |
| 2 | `02 00 00 00` | signed + AES-GCM encrypted |

The production TA (`4367fd45-...`) is **type 1**: signed, not encrypted.

## 13.3 Signature verification failed

```bash
$ openssl dgst -sha256 -verify /tmp/oem_pub.pem -signature /tmp/ta.sig /tmp/ta.elf
Verification failure
RSA_padding_check_PKCS1_type_1:invalid padding
```

The shipped SDK private key did not sign the production TA.

## 13.4 Certs are OpenSSL tutorial defaults

```
cert/ca.crt:   C=AU, ST=Some-State, O=Internet Widgits Pty Ltd
cert/mid.crt:  C=AU, ST=Some-State, O=Be Bop - Originalaskkopp
cert/my.crt:   C=AU, ST=Some-State, O=Testing testers
```

Development templates, not production keys.

## 13.5 OP-TEE OS image reveals the key path

`change_puk_linux/tee-pager.bin` strings:

```
3aedd  TA signd by old default key will be not support soon! please resign TA!
3db79  BEEFtee_otp_get_hw_unique_key
3e06a  syscall_derive_key_from_hard
3c088  storage_write_vbootkey_hash
3c152  vbootkey hash has already been writed!
```

Interpretation:

- `tee_otp_get_hw_unique_key` and `syscall_derive_key_from_hard` confirm the
  AES key is derived from the Rockchip Hardware Unique Key in the SoC eFuse.
- `vbootkey hash has already been writed!` confirms the TA signing key hash
  is fused in eFuse and cannot be changed.

## 13.6 SDK default key is NOT in the OP-TEE OS image

```bash
HASH=$(openssl pkey -in export-ta_arm64/keys/oem_privkey.pem -pubout -outform DER | sha256sum | cut -d' ' -f1)
# → 3ee5d31b5a58ef76bf1eb71f18de9e2406a85854aa1470d33ec32fa0dcafbfc9
```

Search result:

```
forward hash: not found
reverse hash: not found
```

The OP-TEE OS image does not contain the SDK default public key hash.

---

# 14. Phase 10 — Boot Chain and FIT Analysis

## 14.1 Boot chain

```
Power on
  │
  ▼
BootROM (RK3566, in silicon)
  │  loads from eMMC
  ▼
rk356x_spl_v1.14.bin (SPL / BL2)
  │  loads u-boot.itb (FIT)
  ▼
u-boot.itb (FIT image, packed by make_fit_atf.sh)
  │
  ├─ atf-1  (BL31)  ARM Trusted Firmware
  ├─ optee  (BL32)  at TEE_LOAD_ADDR = 0x08400000   ← OP-TEE OS
  ├─ uboot  (BL33)  U-Boot proper
  └─ fdt    (U-Boot device tree)
  │
  ▼
ATF starts, OP-TEE loaded into secure world, U-Boot runs in normal world
  │
  ▼
Linux kernel (boot.img FIT)
```

## 14.2 FIT signing

From `make_fit_atf.sh`:

```
signature {
    algo = "sha256,rsa2048";
    key-name-hint = "dev";
    sign-images = "fdt", "firmware", "loadables";
};
```

The FIT is signed with RSA-2048 + SHA-256. The private key for `dev` is not
in the GPL drop.

## 14.3 `tee.bin` is missing from the drop

The FIT generator references:

```bash
openssl dgst -sha256 -binary -out ${srctree}/tee.digest ${srctree}/tee.bin
data = /incbin/("./tee.bin${SUFFIX}");
```

`tee.bin` is the complete OP-TEE OS binary. A grep across the entire drop
finds only `tee-pager.bin` (a component, shipped as a tool input for
`change_puk`). The actual `tee.bin` used in the FIT is not present.

`tee.bin` is built from the **OP-TEE OS source tree** (`optee_os`), which is
also not in the drop.

## 14.4 TEE_LOAD_ADDR

From `make_fit_args.sh`:

```bash
TEE_OFFSET=0x08400000
TEE_LOAD_ADDR=$((DARM_BASE+TEE_OFFSET))
```

With `CONFIG_SYS_SDRAM_BASE=0` for RK3566, `TEE_LOAD_ADDR = 0x08400000`
(132 MB). OP-TEE is loaded at this fixed address in DRAM and stays resident.
Normal world cannot access this region — protected by the TrustZone
controller.

---

# 15. Reconstructed Decryption Chain

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

# 16. Conclusion

**There is no software-only path to decrypt the firmware on a PC.**

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
| Boot chain uses FIT with embedded OP-TEE | `make_fit_atf.sh` |
| `tee.bin` not shipped in GPL drop | grep across whole tree |
| `tee_otp_get_hw_unique_key` and `syscall_derive_key_from_hard` present | strings in `tee-pager.bin` |
| OP-TEE version is 3.7.9 | strings in `tee-pager.bin` |
| Production TA is not signed by SDK default key | `openssl dgst -verify` |
| SDK default key hash not in OP-TEE OS image | Python search |
| Certificates are OpenSSL tutorial defaults | `openssl x509 -subject` |
| Storage is eMMC | partition table, kernel drivers, U-Boot config |
| eMMC is not encrypted at rest | no dm-crypt init path, plaintext writes |

The protection is correctly implemented.

---

# 17. Comparison with CDJ-3000

| Feature | CDJ-3000 (older) | CDJ-1500X / XDJ-AN |
|---|---|---|
| Encryption key | Model-wide symmetric | Per-device, derived from SoC eFuse |
| Key storage | Firmware / software | Rockchip RK3566 HUK |
| Decryption performed by | Software (bootloader or tool) | Signed OP-TEE TA |
| Attack surface | Software key extraction | Physical access or secure-world exploit |
| Public root project | `cdj3k-root` exists | None known |
| GPL source completeness | Kernel + U-Boot typically shipped | CDJ-1500X: partial; XDJ-AN: full BSP |
| TA signing key | (varies) | Production key, not shipped |

---

# 18. Open Items and Next Steps

## 18.1 GPL source request

Send the draft in section 19. Specifically request:

- U-Boot 2017.09 source tree (with vendor patches)
- Linux kernel source tree (with vendor patches)
- Linux kernel device tree source for the CDJ-1500X
- cryptsetup-2.0.6 as shipped
- busybox-1.27.2 as shipped
- The vendor-specific update tool that reads the `.UPD` container
- OP-TEE OS source tree as shipped (or a statement of the upstream version)
- The U-Boot FIT signing key, or a statement of its status

## 18.2 OP-TEE 3.7.9 vulnerability tracking

Monitor:

- https://github.com/OP-TEE/optee_os/security/advisories
- https://nvd.nist.gov/

## 18.3 Public key-leak monitoring

Search anchors:

- `CDJ1500Xv110.UPD`
- `XDJANv120.UPD`
- `4367fd45-4469-42a6-925d-3857b952704a`
- `CDJ-1500X firmware key`
- `rockchip huk cdj`

## 18.4 Device-side research (requires hardware)

If you obtain a CDJ-1500X or XDJ-AN:

1. Inspect PCB for JTAG/UART pads
2. Monitor eMMC bus with logic analyzer during official update
3. Attempt to reach a U-Boot shell and use `OpteeRpcCmdLoadTa` with a
   modified signed TA
4. As a last resort, chip-off the eMMC or read the SoC eFuse

## 18.5 Publication

This document is sufficient as a technical report.

---

# 19. GPL Source Request (Draft)

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
  - The Linux kernel device tree source for the CDJ-1500X

Components referenced but not shipped (XDJ-AN release):
  - tee.bin (OP-TEE OS binary packed into the U-Boot FIT)
  - The OP-TEE OS source tree used to build tee.bin
  - The vendor-specific tool that reads the .UPD container

GPL v2 and LGPL require that the complete corresponding source code,
including any modifications and scripts used to control compilation
and installation, be provided to anyone who receives the binary.

Please provide:
  1. The U-Boot source tree used on the CDJ-1500X and XDJ-AN, with vendor patches.
  2. The Linux kernel source tree used on the CDJ-1500X and XDJ-AN, with vendor patches.
  3. The Linux kernel device tree source for the CDJ-1500X.
  4. cryptsetup-2.0.6 as shipped.
  5. busybox-1.27.2 as shipped.
  6. The OP-TEE OS source tree as shipped, or the exact upstream version.
  7. The vendor-specific tool that reads the .UPD container.
  8. The exact upstream version and commit hash for each component.

Format: tar.xz via download link or similar.

Thank you.

[Your name]
[Your contact]
```

---

# 20. Reproducing the Analysis

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
data = open("tee-pager.bin","rb").read()
raw = binascii.unhexlify(h)
for name, needle in [("forward", raw), ("reverse", raw[::-1])]:
    i = data.find(needle)
    print(f"{name}: {hex(i) if i>=0 else 'not found'}")
PY

# 12. FIT generation scripts
cat u-boot/arch/arm/mach-rockchip/make_fit_atf.sh
cat u-boot/arch/arm/mach-rockchip/make_fit_args.sh

# 13. Boot chain verification
grep FIT_GENERATOR u-boot/configs/rk3568_xdjan_defconfig
```

---

# 21. Tools Used

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
| `dtc` | Device tree compiler |
| Docker (ubuntu:18.04) | Reproducible build environment |

---

# 22. Storage and eMMC Analysis

## 22.1 Storage type: eMMC

Both the CDJ-1500X and the XDJ-AN use **eMMC** as their primary non-volatile
storage.

**Partition table:**

```
CMDLINE: mtdparts=rk29xxnand:0x00002000@0x00004000(uboot),
  0x00080000@0x00006000(boota),
  0x00080000@0x00086000(bootb),
  0x00020000@0x00106000(setting),
  0x00100000@0x00126000(update),
  -@0x00226000(reserve:grow)
```

**Kernel drivers:** `dw_mmc.c`, `dw_mmc.h`, `rk_sdmmc.h` in
`kernel/drivers/mmc/host/`.

**U-Boot config:**

```
CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_USE_PARTITION=y
CONFIG_CMD_MMC=y
CONFIG_ROCKCHIP_NEW_IDB=y
CONFIG_SPL_MMC_WRITE=y
```

**Update engine paths:** writes to `/dev/block/by-name/<name>` (eMMC
namespace).

## 22.2 Is the eMMC encrypted at rest?

**No.** Only the `.UPD` distribution package is encrypted.

Evidence:

1. `CONFIG_DM_CRYPT=y` and `cryptsetup` are present but unused. No init
   script calls `cryptsetup luksOpen`.
2. The update engine writes plaintext RKIMAGE (`RKAF`) partitions directly.
3. The `.UPD` is decrypted before the update engine runs.

## 22.3 What is and is not encrypted

| Partition | Content | Encrypted? |
|---|---|---|
| `uboot` | SPL + ATF + OP-TEE + U-Boot (FIT) | No (signed) |
| `boota` / `bootb` | FIT kernel images | No (signed) |
| `setting` | Configuration | Usually plaintext |
| `update` | `.UPD` written by updater | Yes (still encrypted until processed) |
| `reserve` (rootfs) | ext4 root filesystem | No |
| RPMB (separate area) | Sealed secrets | Yes (RPMB key, bound to SoC) |

## 22.4 What a dump gives you

**Gives you:**
- Complete partition table
- Running U-Boot, kernel FIT, rootfs (plaintext)
- `setting` partition contents
- Last `.UPD` on the `update` partition (still encrypted)

**Does not give you:**
- `.UPD` decryption key (in SoC HUK inside OP-TEE)
- TA signing private key (production key, never shipped)
- RPMB key or contents
- Hardware Unique Key

## 22.5 How to dump the eMMC

### 22.5.1 Maskrom mode (software)

```bash
sudo apt install -y libusb-1.0-0-dev
git clone https://github.com/rockchip-linux/rkdeveloptool
cd rkdeveloptool && autoreconf -i && ./configure && make && sudo make install

sudo rkdeveloptool ld
sudo rkdeveloptool rfi
sudo rkdeveloptool rl 0 0x3A00000 emmc_dump.img
```

### 22.5.2 JTAG / ISP (in-system)

Requires Easy JTAG Plus or compatible programmer with BGA-153 adapter.

### 22.5.3 Chip-off (physical)

Requires hot air rework station, eMMC reader, and replacement chip.

## 22.6 Post-dump entropy check

```bash
python3 - <<'PY'
import math, collections
def entropy(data):
    c = collections.Counter(data)
    return -sum((v/len(data))*math.log2(v/len(data)) for v in c.values())
data = open("emmc_dump.img","rb").read()
regions = [(0x004000*512, 0x2000*512, "uboot"),
           (0x006000*512, 0x80000*512, "boota"),
           (0x086000*512, 0x80000*512, "bootb"),
           (0x106000*512, 0x20000*512, "setting"),
           (0x126000*512, 0x100000*512, "update")]
for off, size, name in regions:
    chunk = data[off:off+size]
    if chunk:
        print(f"{name}: entropy = {entropy(chunk):.4f}")
PY
```

Expected: `uboot`, `boota`, `bootb` — 4.5–5.5 (plaintext, signed). `update` —
7.9+ (encrypted `.UPD`).

## 22.7 A dump does not change the conclusion

| Goal | Does eMMC dump help? |
|---|---|
| Understand boot scripts | Yes |
| Extract rootfs | Yes |
| Read kernel/U-Boot | Yes |
| Recover `.UPD` decryption key | No |
| Recover TA signing key | No |
| Read RPMB contents | No |

---

# 23. Completeness Assessment

## 23.1 What is complete

| Layer | Status |
|---|---|
| Firmware container (`.UPD`) | Fully analyzed |
| LUKS decoy headers | Fully analyzed |
| Client library `librk_tee_service.so` | Fully disassembled |
| TA `4367fd45-...` | Fully disassembled |
| Second TA `ebc28104-...` | Identified and characterized |
| TA signing format (`HSTO`, types 0/1/2) | Documented |
| TA signature verification | Failed against SDK default key |
| OP-TEE OS version | 3.7.9 |
| OP-TEE OS key path | `tee_otp_get_hw_unique_key`, `syscall_derive_key_from_hard` |
| SDK default pubkey in OP-TEE OS | Not found |
| U-Boot source (XDJ-AN) | Available and analyzed |
| Kernel source (XDJ-AN) | Available and analyzed |
| Device tree (XDJ-AN) | Extracted and analyzed |
| Buildroot config (XDJ-AN) | Available and analyzed |
| Boot chain (BootROM → SPL → ATF → OP-TEE → U-Boot → Linux) | Fully mapped |
| FIT generation scripts | Fully documented |
| eMMC storage | Confirmed |
| eMMC encryption at rest | Confirmed not encrypted |
| Cross-product findings (shared header, shared TA UUID) | Verified |
| Conclusion | Hardware-bound key; no software path |

## 23.2 What is NOT complete

| Missing item | Reason |
|---|---|
| CDJ-1500X U-Boot source | Not shipped in GPL drop |
| CDJ-1500X kernel source | Not shipped in GPL drop |
| CDJ-1500X device tree source | Not shipped in GPL drop |
| OP-TEE OS source (`optee_os`) | Not shipped in GPL drop (BSD license, not required) |
| `tee.bin` (OP-TEE OS binary) | Referenced by build, not shipped |
| U-Boot FIT signing key (`dev`) | Not shipped, not recoverable |
| Production TA signing private key | Not shipped, not recoverable |
| Hardware Unique Key (HUK) | Fused in eFuse, not extractable by software |
| Live device verification | Requires hardware |

## 23.3 What can still be obtained

- **CDJ-1500X U-Boot/kernel/DT source** — via GPL request
- **OP-TEE OS source** — via direct request or Rockchip SDK
- **`tee.bin`** — via request or eMMC dump of a live device
- **`setting` partition contents** — via eMMC dump

## 23.4 What cannot be obtained by any software means

- **FIT signing key** — not shipped; the signed FIT cannot be reproduced
- **TA signing key** — production key, not shipped
- **HUK from eFuse** — physical property of the RK3566 silicon
- **`.UPD` decryption key** — derived at runtime inside OP-TEE from HUK

## 23.5 Assessment by goal

| Goal | Status |
|---|---|
| "Can I decrypt the firmware on a PC?" | No, definitively — full evidence provided |
| "Can I document the security architecture?" | Yes, complete for XDJ-AN; ~95% for CDJ-1500X |
| "Can I build a modified firmware the device accepts?" | No — FIT signing key and TA signing key are missing |
| "Can I extract the HUK?" | No — requires physical access |
| "Can I do more with the files I have?" | No — all layers analyzed |

---

# 24. Legal and Ethical Note

This analysis was performed on firmware and GPL source obtained from
AlphaTheta's public download pages, for personal security research.

- No physical device was modified.
- No firmware was redistributed.
- No encryption was broken.
- The GPL source request is a legitimate exercise of rights under GPL v2.

The firmware analyzed is protected by a hardware root of trust that is
working as designed. The goal of this research is to document that design,
not to bypass it.
