/*
 * A pin tool to record all instructions in a binary execution.
 *
 */

#include <stdio.h>
#include <pin.H>
#include <map>
#include <vector>
#include <iostream>
#include <string>

#define WINDOW_SIZE           100

using namespace std;

std::map<ADDRINT, std::string> opcmap;
FILE *fp_trace, *fp_pushed;

REG regs_idx[16] = {REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, 
                         REG_RBP, REG_RSP, REG_R8,  REG_R9,  REG_R10, REG_R11,
                         REG_R12, REG_R13, REG_R14, REG_R15};

const char *regs_str[16] = {
    "RAX", "RBX", "RCX", "RDX", 
    "RSI", "RDI", "RBP", "RSP", 
    "R8",  "R9",  "R10", "R11", 
    "R12", "R13", "R14", "R15"
};

typedef struct trace_regs {
     uint64_t seq_num;
     uint64_t general_regs[16];
     uint64_t rflags;
}trace_regs;

vector<trace_regs> regs_pushed_list;
vector<trace_regs> regs_poped_list;

uint64_t seq_num;
uint64_t general_regs_val[16];
uint64_t rflags_val;

uint64_t addr_to_read;
uint64_t addr_to_write;

void get_context(ADDRINT addr, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr) {
     seq_num ++;
     addr_to_write = waddr;
     addr_to_read = raddr;

     for (int i = 0; i < 16; i++) {
          general_regs_val[i] = PIN_GetContextReg(fromctx, regs_idx[i]);
     }
     rflags_val = PIN_GetContextReg(fromctx, REG_RFLAGS);     

     fprintf(fp_trace, "%ld ", seq_num);
     fprintf(fp_trace, "%s;", opcmap[addr].c_str());

     for (int i = 0; i < 16; i++) {
          fprintf(fp_trace, "%lx;", general_regs_val[i]);
     }
     fprintf(fp_trace, "%lx;", rflags_val);

     fprintf(fp_trace, "\n");
}

void trace_push(ADDRINT addr, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr) {
     int matched = 0;
     struct trace_regs reg_tmp;

     if (addr_to_write == 0) {
          return;
     }

     uint64_t val_written = *((uint64_t *)addr_to_write);

     reg_tmp.seq_num = seq_num;
     for (int i = 0; i < 16; i++) {
          if (general_regs_val[i] == val_written) {
               matched = 1;
               reg_tmp.general_regs[i] = 1; 
          } else {
               reg_tmp.general_regs[i] = 0;
          }
     }
     if (rflags_val == val_written) {
          reg_tmp.rflags = 1;
     }

     if (matched) {
          
          // fprintf(fp_trace, "%ld;", copied.seq_num);
          // for (int i = 0; i < 16; i++) {
          //      if (copied.regs_copied[i]) {
          //           fprintf(fp_trace, "%s;", regs_str[i]);
          //      }
          // }
          // fprintf(fp_trace, "\n");

          regs_pushed_list.push_back(reg_tmp);
     }
}

void trace_pop(ADDRINT addr, CONTEXT *fromctx, ADDRINT raddr, ADDRINT waddr) {
}

static void instruction(INS ins, void *v) {
     ADDRINT addr = INS_Address(ins);
     if (opcmap.find(addr) == opcmap.end()) {
          opcmap.insert(std::pair<ADDRINT, std::string>(addr, INS_Disassemble(ins)));
     }

     if (INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)get_context, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_END);
     } else if (INS_IsMemoryRead(ins)) {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)get_context, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_MEMORYREAD_EA, IARG_ADDRINT, 0, IARG_END);
     } else if (INS_IsMemoryWrite(ins)) {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)get_context, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_MEMORYWRITE_EA, IARG_END);
     } else {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)get_context, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_ADDRINT, 0, IARG_ADDRINT, 0, IARG_END);
     }
     
     if (INS_IsValidForIpointAfter(ins)) {
          INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)trace_push, IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);
     }
}

typedef struct seq_range {
     uint64_t begin;
     uint64_t end;
} seq_range;

static void on_fini(INT32 code, void *v) {
     uint64_t begin_seq_num, cur_seq_num;
     vector<seq_range> seq_range_list;

     for (auto iter_begin = regs_pushed_list.begin(); iter_begin != regs_pushed_list.end(); iter_begin++) {
          uint64_t general_regs_matched[16];
          uint64_t rflags_matched;
          for (int i = 0; i < 16; i++) {
               general_regs_matched[i] = 0;
          }
          rflags_matched = 0;

          begin_seq_num = (*iter_begin).seq_num;

          for (auto iter_end = iter_begin; iter_end != regs_pushed_list.end(); iter_end++) {
               cur_seq_num = (*iter_end).seq_num;

               // if exceed window_size, begin with next seq_num
               if ((cur_seq_num-begin_seq_num) > WINDOW_SIZE) {
                    break;
               }
               for (int i = 0; i < 16; i++) {
                    if ((*iter_end).general_regs[i]) {
                         general_regs_matched[i] = 1;
                    }
               }
               if ((*iter_end).rflags) {
                    rflags_matched = 1;
               }

               int nb_pushed = 0;
               for (int i = 0; i < 16; i++) {
                    if (regs_idx[i] == REG_RSP) {
                         continue;
                    }

                    if (general_regs_matched[i]) {
                         nb_pushed++;
                    }
               }
               if (rflags_matched) {
                    nb_pushed++;
               }

               if (nb_pushed == 16) {
                    struct seq_range range;
                    range.begin = begin_seq_num;
                    range.end = cur_seq_num;
                    seq_range_list.push_back(range);
                    break;
               }
          }
     }

     uint64_t range_begin, range_end;
     auto iter = seq_range_list.begin();

     range_begin = (*iter).begin;
     range_end = (*iter).end;
     iter++;

     for (; iter != seq_range_list.end(); iter++) {
          if (range_end == (*iter).end) {
               range_begin = (*iter).begin;
               continue;
          }
          fprintf(fp_pushed, "%ld-%ld\n", range_begin, range_end);
          range_begin = (*iter).begin;
          range_end = (*iter).end;
     }
     fprintf(fp_pushed, "%ld-%ld\n", range_begin, range_end);

     fclose(fp_trace);
     fclose(fp_pushed);
}

int main(int argc, char *argv[]) {
     if (PIN_Init(argc, argv)) {
          fprintf(stderr, "command line error\n");
          return 1;
     }

     fp_trace = fopen("instrace.txt", "w");
     fp_pushed = fopen("regs_pushed", "w");

     seq_num = 1;

     PIN_InitSymbols();
     PIN_AddFiniFunction(on_fini, 0);
     INS_AddInstrumentFunction(instruction, NULL);
     PIN_StartProgram(); // Never returns

     return 0;
}
