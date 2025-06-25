#!/usr/bin/env python3
# pin2triton.py
from triton import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from triton import MODE
import sys, re
from triton import AST_NODE      #  enum 정의
import time
from z3 import *

REG_NAMES = [
    "RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP",
    "R8","R9","R10","R11","R12","R13","R14","R15"
]

md = Cs(CS_ARCH_X86, CS_MODE_64) 
md.detail = True  

def parse_line(line: str):
    # ------------- split & strip -------------
    parts = line.rstrip(";\n").split(";")
    seq      = int(parts[0])
    addr     = int(parts[1], 16)
    opbytes  = bytes.fromhex(parts[2])
    asm      = parts[3]

    # ----------- registers / flags -----------
    regvals  = {}
    i = 4
    while not parts[i].startswith("rflags"):
        name, val = parts[i].split(":")
        regvals[name.upper()] = int(val, 16)
        i += 1
    rflags    = int(parts[i].split(":")[1], 16)

    # ------------- mem R/W EA ----------------
    waddr   = int(parts[i+1].split(":")[1], 16)
    raddr   = int(parts[i+2].split(":")[1], 16)

    return {
        "seq": seq,  
        "addr": addr, "opbytes": opbytes, "asm": asm,
        "regs": regvals, "rflags": rflags,
        "read": raddr, "write": waddr,
    }
    
def sync_regs_for_memory(ctx: TritonContext, entry):
    ins  = next(md.disasm(entry["opbytes"], entry["addr"]))
    need = set()
    for op in ins.operands:
        if op.type == CS_OP_MEM:
            if op.mem.base:   need.add(ins.reg_name(op.mem.base).upper())
            if op.mem.index:  need.add(ins.reg_name(op.mem.index).upper())
    if "RIP" in need and "RIP" in entry["regs"]:
        ctx.setConcreteRegisterValue(ctx.registers.rip, entry["regs"]["RIP"])
    for reg in need:
        if reg in entry["regs"]:  
            ctx.setConcreteRegisterValue(getattr(ctx.registers, reg.lower()),
                                         entry["regs"][reg])
            
def replay_pin_trace(trace_path: str):
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.CONSTANT_FOLDING,   False) 
    ctx.setMode(MODE.AST_OPTIMIZATIONS,  False)

    with open(trace_path) as fp:
        for line in fp:
            if not line.strip():     # skip blanks
                continue
            entry = parse_line(line)
            
            if entry["read"] or entry["write"]:
                sync_regs_for_memory(ctx, entry)

            # ── execute instruction ─────────────────────
            inst = Instruction(entry["addr"], entry["opbytes"])
            ctx.processing(inst)

            # op_hex = bytes(inst.getOpcode()).hex()
            # if op_hex == "660fefc1":  # pxor xmm0, xmm1        
            # # if entry["seq"] == 117252:       
            #     ctx.symbolizeMemory(MemoryAccess(0x7fffffffdf58, 8), 'symbar_a')
            #     ctx.symbolizeMemory(MemoryAccess(0x7fffffffdf60, 8), 'symbar_b')
            
            seq_tag = f"[ADDR {hex(entry['addr'])}] [SEQ {entry['seq']}] {entry['asm']}"
            # seq_tag = f"{entry['asm']}"
            for se in inst.getSymbolicExpressions():
                # se.setComment(entry["asm"])    
                se.setComment(seq_tag) 
                                
            op_hex = bytes(inst.getOpcode()).hex()
            # if op_hex == "660fefd3":  # pxor xmm2, xmm3  
            if entry["seq"] == 115225:
                rax_expr = ctx.getSymbolicRegister(ctx.registers.rax)
                if rax_expr is None:
                    print("    DIL is still concrete – nothing to slice.\n")
                else:
                    slice_dict = ctx.sliceExpressions(rax_expr)

                    for sid in sorted(slice_dict):
                        se  = slice_dict[sid]
                        cmt = se.getComment() or "(no comment)"
                        print(f"{cmt}")
                        # print(f"        {se.getAst()}\n")  

                    raw_ast = rax_expr.getAst()                 
                    
                    simplified = ctx.simplify(raw_ast, True)
                    print("    [simplified  AST]")
                    print("      ", simplified, "\n")
                    
                    # ast_ctx   = ctx.getAstContext()
                    # unrolled  = ast_ctx.unroll(raw_ast)

                    # print("    [unrolled AST]")
                    # print("      ", unrolled, "\n")
                    
                    exit(1)
                
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} pin_trace.txt")
        sys.exit(1) 
    replay_pin_trace(sys.argv[1])

# def replay_trace_with_triton(trace):
#     ctx = TritonContext()
#     ctx.setArchitecture(ARCH.X86_64)

#     started_sym = False
#     op_idx = 0
    
#     accessed_memory_addresses = set()

#     # 2) Replay
#     for idx, entry in enumerate(trace):

#         inst = Instruction(entry["addr"], entry["opcode"])
#         ctx.processing(inst)

#         loads_mem = inst.getLoadAccess()
#         stores_mem = inst.getStoreAccess()
#         writes_reg = inst.getWrittenRegisters()

#         ql_reads = entry["reads"]
#         ql_read_map = {r["addr"]: r["value"] for r in ql_reads}
        
#         if loads_mem and (writes_reg or stores_mem):
#             for mem, ast in loads_mem:
#                 addr = mem.getAddress()
#                 size = mem.getSize()

#                 if addr not in accessed_memory_addresses:
#                     accessed_memory_addresses.add(addr)

#                     # Qiling에서 읽은 concrete 값을 Triton 메모리에 설정
#                     if addr in ql_read_map:
#                         concrete_val = ql_read_map[addr]
#                         ctx.setConcreteMemoryValue(MemoryAccess(addr, size), concrete_val)
#                         print(f"[Init SRC MEM] [0x{addr:X}] ← 0x{concrete_val:X}")

#                         # 해당 메모리를 심볼릭 변수로 만들기
#                         sym_var = ctx.symbolizeMemory(MemoryAccess(addr, size), f"mem_{addr:X}")

#         for reg, ast in writes_reg:
#             reg_name = reg.getName()
#             # symbolic 연결을 유지하려면 AST를 복사하면 됨
#             ctx.assignSymbolicExpressionToRegister(ast, reg)
#             print(f"[Linked] REG {reg_name} linked symbolically.")

#         for mem, ast in stores_mem:
#             dst_addr = mem.getAddress()
#             size = mem.getSize()
#             ctx.assignSymbolicExpressionToMemory(ast, mem)
#             print(f"[Linked] MEM [0x{dst_addr:X}] linked symbolically.")
        
#         for se in inst.getSymbolicExpressions():
#             se.setComment(str(inst))

#         # Conditional memory dump around PXORs
#         op_hex = bytes(inst.getOpcode()).hex()
        
#         if op_hex == "660fefc1":  # pxor xmm0, xmm1
#             print("    >>> state *after* XOR (xmm0,xmm1)")
                        
#         if op_hex == "660fefd3":  # pxor xmm2, xmm3
#             print("    >>> state *before* XOR (xmm2,xmm3)")
            
#             rax_expr = ctx.getSymbolicRegister(ctx.registers.rax)
#             if rax_expr is None:
#                 print("    DIL is still concrete – nothing to slice.\n")
#             else:
#                 slice_dict = ctx.sliceExpressions(rax_expr)

#                 for sid in sorted(slice_dict):
#                     se  = slice_dict[sid]
#                     cmt = se.getComment() or "(no comment)"
#                     print(f"{cmt}")
#                     # print(f"        {se.getAst()}\n")  
            
#             show_reg_state(ctx, ctx.registers.rbx)
        
#     print("\n[*] Trace replay finished")
