import sys
from pathlib import Path

def dedup_by_first_line(src: Path, dst: Path):
    out_lines       = []
    cur_block       = []
    prev_first_line = None          # 직전에 **남긴** 블록의 첫줄

    with src.open(encoding="utf-8") as fp:
        for line in fp:
            if line.strip():                    # 실내용 라인
                cur_block.append(line)
            else:                               # 빈 줄 → 블록 끝
                if cur_block:
                    first_line = cur_block[0].lstrip()
                    if first_line != prev_first_line:
                        out_lines.extend(cur_block)
                        out_lines.append("\n")   # 블록 간 빈 줄 유지
                        prev_first_line = first_line
                    # 같으면 블록 통째로 버림
                    cur_block = []
                # 빈 줄 여러 개가 이어질 때는 하나로 축약
                elif out_lines and out_lines[-1] != "\n":
                    out_lines.append("\n")

        # EOF 직전에 블록이 남았다면 처리
        if cur_block:
            first_line = cur_block[0].lstrip()
            if first_line != prev_first_line:
                out_lines.extend(cur_block)

    with dst.open("w", encoding="utf-8") as fp:
        fp.writelines(out_lines)

    print(f"Cleaned file saved to {dst}")

# ── CLI ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit(1)

    dedup_by_first_line(Path(sys.argv[1]), Path(sys.argv[2]))