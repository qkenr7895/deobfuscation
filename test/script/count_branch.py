#!/usr/bin/env python3
"""
count_branches.py  –  VMProtect·QEMU trace에서 'path-explosion' 을 일으키는
                      조건 분기(conditional branch) 실행 횟수 / 고유 위치 수를 센다.

사용법:
    python3 count_branches.py trace.txt
"""

import re, sys, collections

# 1) x86 조건 분기 계열 정규식   (jmp / call / ret 은 제외)
BRANCH_RE = re.compile(
    r"^j([a-z]{1,2}|ecxz|cxz)$|^loop", re.IGNORECASE
)

def parse_trace(path):
    total, uniq = 0, set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.rstrip("\n").split(";")
            if len(parts) < 4:
                continue

            addr_str   = parts[1]         # 0x5555...
            asm_field  = parts[3].strip() # "jne 0x..."
            mnemonic   = asm_field.split()[0] if asm_field else ""

            if BRANCH_RE.match(mnemonic):
                total += 1
                try:
                    uniq.add(int(addr_str, 16))
                except ValueError:
                    pass   # 주소 필드가 비어있다면 무시

    return total, len(uniq)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 count_branches.py <trace.txt>", file=sys.stderr)
        sys.exit(1)

    tot, distinct = parse_trace(sys.argv[1])
    print(f"conditional-branch executions : {tot}")
    print(f"unique branch instruction sites: {distinct}")
