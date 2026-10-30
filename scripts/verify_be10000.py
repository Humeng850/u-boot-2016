#!/usr/bin/env python3
"""Static post-build checks for the Xiaomi BE10000 U-Boot image."""

import hashlib
import pathlib
import struct
import sys

APPSBL_CAPACITY = 0x180000  # 12 x 128 KiB NAND blocks in the stock MIBIB
EXPECTED_MACHID = 0x08050301


def fail(message):
    raise SystemExit("VERIFY FAILED: " + message)


def main():
    if len(sys.argv) not in (2, 3):
        fail("usage: verify_be10000.py <u-boot.mbn> [u-boot-dtb.bin]")

    image_path = pathlib.Path(sys.argv[1])
    data = image_path.read_bytes()
    size = len(data)
    if size == 0:
        fail("empty image")
    if size > APPSBL_CAPACITY:
        fail(f"image is too large for 0:APPSBL: 0x{size:x} > 0x{APPSBL_CAPACITY:x}")

    if data[:4] != b"\x7fELF":
        fail("final MBN does not contain an ELF header")
    if data[4] != 1 or data[5] != 1:
        fail("expected 32-bit little-endian ELF")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    if e_type not in (2, 3) or e_machine != 40:
        fail(f"expected ARM ELF EXEC or DYN, got type={e_type}, machine={e_machine}")
    if not e_phnum or e_phentsize < 32 or e_phoff + e_phnum * e_phentsize > size:
        fail("invalid ELF program-header table")

    print(f"image={image_path.name}")
    print(f"size={size} bytes (0x{size:x})")
    print(f"appsbl_capacity={APPSBL_CAPACITY} bytes (0x{APPSBL_CAPACITY:x})")
    print(f"appsbl_remaining={APPSBL_CAPACITY - size} bytes")
    elf_type_name = "EXEC" if e_type == 2 else "DYN"
    print(f"elf=32-bit little-endian ARM {elf_type_name}, program_headers={e_phnum}")
    print(f"sha256={hashlib.sha256(data).hexdigest()}")

    if len(sys.argv) == 3:
        dtb_image_path = pathlib.Path(sys.argv[2])
        dtb_image = dtb_image_path.read_bytes()
        if b"Xiaomi BE10000 (RC01)" not in dtb_image:
            fail("BE10000 model string missing from u-boot-dtb.bin")
        machid_be = struct.pack(">I", EXPECTED_MACHID)
        machid_le = struct.pack("<I", EXPECTED_MACHID)
        if machid_be not in dtb_image and machid_le not in dtb_image:
            fail("machid 0x08050301 missing from u-boot-dtb.bin")
        print("dtb_model=Xiaomi BE10000 (RC01)")
        print("dtb_machid=0x08050301")

    print("VERIFY PASSED: static image, capacity, ELF and board-identity checks")


if __name__ == "__main__":
    main()
