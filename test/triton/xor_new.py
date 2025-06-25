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
state_log = {}

md = Cs(CS_ARCH_X86, CS_MODE_64) 
md.detail = True  

def grab_ctx_regs(ctx):
    snap = {}
    for r in REG_NAMES:
        reg = getattr(ctx.registers, r.lower())
        se  = ctx.getSymbolicRegister(reg)
        if se is None:                     # concrete
            snap[r] = ctx.getConcreteRegisterValue(reg)
        else:                              # symbolic
            snap[r] = 'SYM'
    return snap

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
            
            pre_regs = {r: entry["regs"].get(r, None) for r in REG_NAMES}
            
            if entry["read"] or entry["write"]:
                sync_regs_for_memory(ctx, entry)

            # ── execute instruction ─────────────────────
            inst = Instruction(entry["addr"], entry["opbytes"])
            ctx.processing(inst)
            
            post_regs = grab_ctx_regs(ctx)
            
            state_log[entry["seq"]] = {"pre": pre_regs, "post": post_regs}

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
            if entry["seq"] == 115577:
                rax_expr = ctx.getSymbolicRegister(ctx.registers.rax)
                if rax_expr is None:
                    print("    DIL is still concrete – nothing to slice.\n")
                else:
                    slice_dict = ctx.sliceExpressions(rax_expr)

                    for sid in sorted(slice_dict):
                        se  = slice_dict[sid]
                        cmt = se.getComment() or "(no comment)"
                        print(f"{cmt}")
                        m = re.search(r'\[SEQ (\d+)\]', cmt)
                        if not m:
                            continue
                        seq = int(m.group(1))
                        if seq not in state_log:
                            continue

                        pre = state_log[seq]["pre"]
                        post= state_log[seq]["post"]

                        changed = [r for r in REG_NAMES if pre.get(r)!=post.get(r)]
                        if not changed:
                            print("      (registers unchanged)")
                            continue

                        pre_line  = " ".join(f"{r}={pre[r]:016x}"  if pre[r]  not in (None,'SYM') else f"{r}={pre[r]}"
                                            for r in changed)
                        post_line = " ".join(f"{r}={post[r]:016x}" if post[r] not in (None,'SYM') else f"{r}={post[r]}"
                                            for r in changed)
                        print(f"      PRE : {pre_line}")
                        # print(f"      POST: {post_line}")
                        # print(f"        {se.getAst()}\n")  
                        ast = se.getAst()
                        expr_id = se.getId() 
                        print(f"      [ref!{expr_id}] AST :", ast, "\n")

                    raw_ast = rax_expr.getAst()                 
                    
                    simplified = ctx.simplify(raw_ast, llvm=True)
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