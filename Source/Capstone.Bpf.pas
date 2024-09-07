{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Api Header                       }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: bpf.h                                     }
{    License: Mozilla Public License 2.0                }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.Bpf;

{$I Capstone.inc}

interface

type
  /// Operand type for instruction's operands
  bpf_op_type = Integer;
  Pbpf_op_type = ^bpf_op_type;

const
  BPF_OP_INVALID = 0;
  BPF_OP_REG = 1;
  BPF_OP_IMM = 2;
  BPF_OP_OFF = 3;
  BPF_OP_MEM_ = 4;
  /// M[k] in cBPF
  BPF_OP_MMEM = 5;
  /// corresponds to cBPF's BPF_MSH mode
  BPF_OP_MSH = 6;
  /// cBPF's extension (not eBPF)
  BPF_OP_EXT = 7;

/// BPF registers
type
  bpf_reg = Integer;
  Pbpf_reg = ^bpf_reg;

const
  BPF_REG_INVALID = 0;
  BPF_REG_A = 1;
  BPF_REG_X = 2;
  BPF_REG_R0 = 3;
  BPF_REG_R1 = 4;
  BPF_REG_R2 = 5;
  BPF_REG_R3 = 6;
  BPF_REG_R4 = 7;
  BPF_REG_R5 = 8;
  BPF_REG_R6 = 9;
  BPF_REG_R7 = 10;
  BPF_REG_R8 = 11;
  BPF_REG_R9 = 12;
  BPF_REG_R10 = 13;
  BPF_REG_ENDING = 14;

type
  bpf_ext_type = Integer;
  Pbpf_ext_type = ^bpf_ext_type;

const
  BPF_EXT_INVALID = 0;
  BPF_EXT_LEN = 1;

/// BPF instruction
type
  bpf_insn = Integer;
  Pbpf_insn = ^bpf_insn;

const
  BPF_INS_INVALID = 0;
  BPF_INS_ADD = 1;
  BPF_INS_SUB = 2;
  BPF_INS_MUL = 3;
  BPF_INS_DIV = 4;
  BPF_INS_OR = 5;
  BPF_INS_AND = 6;
  BPF_INS_LSH = 7;
  BPF_INS_RSH = 8;
  BPF_INS_NEG = 9;
  BPF_INS_MOD = 10;
  BPF_INS_XOR = 11;
  /// eBPF only
  BPF_INS_MOV = 12;
  /// eBPF only
  BPF_INS_ARSH = 13;
  BPF_INS_ADD64 = 14;
  BPF_INS_SUB64 = 15;
  BPF_INS_MUL64 = 16;
  BPF_INS_DIV64 = 17;
  BPF_INS_OR64 = 18;
  BPF_INS_AND64 = 19;
  BPF_INS_LSH64 = 20;
  BPF_INS_RSH64 = 21;
  BPF_INS_NEG64 = 22;
  BPF_INS_MOD64 = 23;
  BPF_INS_XOR64 = 24;
  BPF_INS_MOV64 = 25;
  BPF_INS_ARSH64 = 26;
  BPF_INS_LE16 = 27;
  BPF_INS_LE32 = 28;
  BPF_INS_LE64 = 29;
  BPF_INS_BE16 = 30;
  BPF_INS_BE32 = 31;
  BPF_INS_BE64 = 32;
  /// eBPF only
  BPF_INS_LDW = 33;
  BPF_INS_LDH = 34;
  BPF_INS_LDB = 35;
  /// eBPF only: load 64-bit imm
  BPF_INS_LDDW = 36;
  /// eBPF only
  BPF_INS_LDXW = 37;
  /// eBPF only
  BPF_INS_LDXH = 38;
  /// eBPF only
  BPF_INS_LDXB = 39;
  /// eBPF only
  BPF_INS_LDXDW = 40;
  /// eBPF only
  BPF_INS_STW = 41;
  /// eBPF only
  BPF_INS_STH = 42;
  /// eBPF only
  BPF_INS_STB = 43;
  /// eBPF only
  BPF_INS_STDW = 44;
  /// eBPF only
  BPF_INS_STXW = 45;
  /// eBPF only
  BPF_INS_STXH = 46;
  /// eBPF only
  BPF_INS_STXB = 47;
  /// eBPF only
  BPF_INS_STXDW = 48;
  /// eBPF only
  BPF_INS_XADDW = 49;
  /// eBPF only
  BPF_INS_XADDDW = 50;
  BPF_INS_JMP = 51;
  BPF_INS_JEQ = 52;
  BPF_INS_JGT = 53;
  BPF_INS_JGE = 54;
  BPF_INS_JSET = 55;
  /// eBPF only
  BPF_INS_JNE = 56;
  /// eBPF only
  BPF_INS_JSGT = 57;
  /// eBPF only
  BPF_INS_JSGE = 58;
  /// eBPF only
  BPF_INS_CALL = 59;
  /// eBPF only
  BPF_INS_CALLX = 60;
  /// eBPF only
  BPF_INS_EXIT = 61;
  /// eBPF only
  BPF_INS_JLT = 62;
  /// eBPF only
  BPF_INS_JLE = 63;
  /// eBPF only
  BPF_INS_JSLT = 64;
  /// eBPF only
  BPF_INS_JSLE = 65;
  BPF_INS_RET = 66;
  BPF_INS_TAX = 67;
  BPF_INS_TXA = 68;
  BPF_INS_ENDING = 69;
  /// cBPF only
  BPF_INS_LD = 33;
  /// cBPF only
  BPF_INS_LDX = 37;
  /// cBPF only
  BPF_INS_ST = 41;
  /// cBPF only
  BPF_INS_STX = 45;

/// Group of BPF instructions
type
  bpf_insn_group = Integer;
  Pbpf_insn_group = ^bpf_insn_group;

const
  /// = CS_GRP_INVALID
  BPF_GRP_INVALID = 0;
  BPF_GRP_LOAD = 1;
  BPF_GRP_STORE = 2;
  BPF_GRP_ALU = 3;
  BPF_GRP_JUMP = 4;
  /// eBPF only
  BPF_GRP_CALL = 5;
  BPF_GRP_RETURN = 6;
  /// cBPF only
  BPF_GRP_MISC = 7;
  BPF_GRP_ENDING = 8;

type
  // Forward declarations
  Pbpf_op_mem = ^bpf_op_mem;
  Pcs_bpf_op = ^cs_bpf_op;
  Pcs_bpf = ^cs_bpf;

  /// Instruction's operand referring to memory
  /// This is associated with BPF_OP_MEM operand type above
  bpf_op_mem = record
    /// base register
    base: bpf_reg;
    /// offset value
    disp: UInt32;
  end;

  cs_bpf_op_detail = record
    case Integer of
      0: (/// register value for REG operand
    reg: UInt8);
      1: (/// immediate value IMM operand
    imm: UInt64);
      2: (/// offset value, used in jump & call
    off: UInt32);
      3: (/// base/disp value for MEM operand
    mem: bpf_op_mem);
      4: (/// M[k] in cBPF
    mmem: UInt32);
      5: (/// corresponds to cBPF's BPF_MSH mode
    msh: UInt32);
      6: (/// cBPF's extension (not eBPF)
    ext: UInt32);
  end;

  /// Instruction operand
  cs_bpf_op = record
    type_: bpf_op_type;
    /// union op detail
    detail: cs_bpf_op_detail;
    /// How is this operand accessed? (READ, WRITE or READ|WRITE)
    /// This field is combined of cs_ac_type.
    /// NOTE: this field is irrelevant if engine is compiled in DIET mode.
    access: UInt8;
  end;

  /// Instruction structure
  cs_bpf = record
    op_count: UInt8;
    operands: array[0..3] of cs_bpf_op;
  end;

implementation

end.
