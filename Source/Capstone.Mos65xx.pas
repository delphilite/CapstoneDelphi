{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Api Header                       }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: mos65xx.h                                 }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.Mos65xx;

{$I Capstone.inc}

interface

type
  /// MOS65XX registers and special registers
  mos65xx_reg = Integer;
  Pmos65xx_reg = ^mos65xx_reg;

const
  MOS65XX_REG_INVALID = 0;
  /// accumulator
  MOS65XX_REG_ACC = 1;
  /// X index register
  MOS65XX_REG_X = 2;
  /// Y index register
  MOS65XX_REG_Y = 3;
  /// status register
  MOS65XX_REG_P = 4;
  /// stack pointer register
  MOS65XX_REG_SP = 5;
  /// direct page register
  MOS65XX_REG_DP = 6;
  /// data bank register
  MOS65XX_REG_B = 7;
  /// program bank register
  MOS65XX_REG_K = 8;
  MOS65XX_REG_ENDING = 9;

/// MOS65XX Addressing Modes
type
  mos65xx_address_mode = Integer;
  Pmos65xx_address_mode = ^mos65xx_address_mode;

const
  /// No address mode.
  MOS65XX_AM_NONE = 0;
  /// implied addressing (no addressing mode)
  MOS65XX_AM_IMP = 1;
  /// accumulator addressing
  MOS65XX_AM_ACC = 2;
  /// 8/16 Bit immediate value
  MOS65XX_AM_IMM = 3;
  /// relative addressing used by branches
  MOS65XX_AM_REL = 4;
  /// interrupt addressing
  MOS65XX_AM_INT = 5;
  /// memory block addressing
  MOS65XX_AM_BLOCK = 6;
  /// zeropage addressing
  MOS65XX_AM_ZP = 7;
  /// indexed zeropage addressing by the X index register
  MOS65XX_AM_ZP_X = 8;
  /// indexed zeropage addressing by the Y index register
  MOS65XX_AM_ZP_Y = 9;
  /// zero page address, branch relative address
  MOS65XX_AM_ZP_REL = 10;
  /// indirect zeropage addressing
  MOS65XX_AM_ZP_IND = 11;
  /// indexed zeropage indirect addressing by the X index register
  MOS65XX_AM_ZP_X_IND = 12;
  /// indirect zeropage indexed addressing by the Y index register
  MOS65XX_AM_ZP_IND_Y = 13;
  /// zeropage indirect long addressing
  MOS65XX_AM_ZP_IND_LONG = 14;
  /// zeropage indirect long addressing indexed by Y register
  MOS65XX_AM_ZP_IND_LONG_Y = 15;
  /// absolute addressing
  MOS65XX_AM_ABS = 16;
  /// indexed absolute addressing by the X index register
  MOS65XX_AM_ABS_X = 17;
  /// indexed absolute addressing by the Y index register
  MOS65XX_AM_ABS_Y = 18;
  /// absolute indirect addressing
  MOS65XX_AM_ABS_IND = 19;
  /// indexed absolute indirect addressing by the X index register
  MOS65XX_AM_ABS_X_IND = 20;
  /// absolute indirect long addressing
  MOS65XX_AM_ABS_IND_LONG = 21;
  /// absolute long address mode
  MOS65XX_AM_ABS_LONG = 22;
  /// absolute long address mode, indexed by X register
  MOS65XX_AM_ABS_LONG_X = 23;
  /// stack relative addressing
  MOS65XX_AM_SR = 24;
  /// indirect stack relative addressing indexed by the Y index register
  MOS65XX_AM_SR_IND_Y = 25;

/// MOS65XX instruction
type
  mos65xx_insn = Integer;
  Pmos65xx_insn = ^mos65xx_insn;

const
  MOS65XX_INS_INVALID = 0;
  MOS65XX_INS_ADC = 1;
  MOS65XX_INS_AND = 2;
  MOS65XX_INS_ASL = 3;
  MOS65XX_INS_BBR = 4;
  MOS65XX_INS_BBS = 5;
  MOS65XX_INS_BCC = 6;
  MOS65XX_INS_BCS = 7;
  MOS65XX_INS_BEQ = 8;
  MOS65XX_INS_BIT = 9;
  MOS65XX_INS_BMI = 10;
  MOS65XX_INS_BNE = 11;
  MOS65XX_INS_BPL = 12;
  MOS65XX_INS_BRA = 13;
  MOS65XX_INS_BRK = 14;
  MOS65XX_INS_BRL = 15;
  MOS65XX_INS_BVC = 16;
  MOS65XX_INS_BVS = 17;
  MOS65XX_INS_CLC = 18;
  MOS65XX_INS_CLD = 19;
  MOS65XX_INS_CLI = 20;
  MOS65XX_INS_CLV = 21;
  MOS65XX_INS_CMP = 22;
  MOS65XX_INS_COP = 23;
  MOS65XX_INS_CPX = 24;
  MOS65XX_INS_CPY = 25;
  MOS65XX_INS_DEC = 26;
  MOS65XX_INS_DEX = 27;
  MOS65XX_INS_DEY = 28;
  MOS65XX_INS_EOR = 29;
  MOS65XX_INS_INC = 30;
  MOS65XX_INS_INX = 31;
  MOS65XX_INS_INY = 32;
  MOS65XX_INS_JML = 33;
  MOS65XX_INS_JMP = 34;
  MOS65XX_INS_JSL = 35;
  MOS65XX_INS_JSR = 36;
  MOS65XX_INS_LDA = 37;
  MOS65XX_INS_LDX = 38;
  MOS65XX_INS_LDY = 39;
  MOS65XX_INS_LSR = 40;
  MOS65XX_INS_MVN = 41;
  MOS65XX_INS_MVP = 42;
  MOS65XX_INS_NOP = 43;
  MOS65XX_INS_ORA = 44;
  MOS65XX_INS_PEA = 45;
  MOS65XX_INS_PEI = 46;
  MOS65XX_INS_PER = 47;
  MOS65XX_INS_PHA = 48;
  MOS65XX_INS_PHB = 49;
  MOS65XX_INS_PHD = 50;
  MOS65XX_INS_PHK = 51;
  MOS65XX_INS_PHP = 52;
  MOS65XX_INS_PHX = 53;
  MOS65XX_INS_PHY = 54;
  MOS65XX_INS_PLA = 55;
  MOS65XX_INS_PLB = 56;
  MOS65XX_INS_PLD = 57;
  MOS65XX_INS_PLP = 58;
  MOS65XX_INS_PLX = 59;
  MOS65XX_INS_PLY = 60;
  MOS65XX_INS_REP = 61;
  MOS65XX_INS_RMB = 62;
  MOS65XX_INS_ROL = 63;
  MOS65XX_INS_ROR = 64;
  MOS65XX_INS_RTI = 65;
  MOS65XX_INS_RTL = 66;
  MOS65XX_INS_RTS = 67;
  MOS65XX_INS_SBC = 68;
  MOS65XX_INS_SEC = 69;
  MOS65XX_INS_SED = 70;
  MOS65XX_INS_SEI = 71;
  MOS65XX_INS_SEP = 72;
  MOS65XX_INS_SMB = 73;
  MOS65XX_INS_STA = 74;
  MOS65XX_INS_STP = 75;
  MOS65XX_INS_STX = 76;
  MOS65XX_INS_STY = 77;
  MOS65XX_INS_STZ = 78;
  MOS65XX_INS_TAX = 79;
  MOS65XX_INS_TAY = 80;
  MOS65XX_INS_TCD = 81;
  MOS65XX_INS_TCS = 82;
  MOS65XX_INS_TDC = 83;
  MOS65XX_INS_TRB = 84;
  MOS65XX_INS_TSB = 85;
  MOS65XX_INS_TSC = 86;
  MOS65XX_INS_TSX = 87;
  MOS65XX_INS_TXA = 88;
  MOS65XX_INS_TXS = 89;
  MOS65XX_INS_TXY = 90;
  MOS65XX_INS_TYA = 91;
  MOS65XX_INS_TYX = 92;
  MOS65XX_INS_WAI = 93;
  MOS65XX_INS_WDM = 94;
  MOS65XX_INS_XBA = 95;
  MOS65XX_INS_XCE = 96;
  MOS65XX_INS_ENDING = 97;

/// Group of MOS65XX instructions
type
  mos65xx_group_type = Integer;
  Pmos65xx_group_type = ^mos65xx_group_type;

const
  /// CS_GRP_INVALID
  MOS65XX_GRP_INVALID = 0;
  /// = CS_GRP_JUMP
  MOS65XX_GRP_JUMP = 1;
  /// = CS_GRP_RET
  MOS65XX_GRP_CALL = 2;
  /// = CS_GRP_RET
  MOS65XX_GRP_RET = 3;
  /// = CS_GRP_INT
  MOS65XX_GRP_INT = 4;
  /// = CS_GRP_IRET
  MOS65XX_GRP_IRET = 5;
  /// = CS_GRP_BRANCH_RELATIVE
  MOS65XX_GRP_BRANCH_RELATIVE = 6;
  MOS65XX_GRP_ENDING = 7;

/// Operand type for instruction's operands
type
  mos65xx_op_type = Integer;
  Pmos65xx_op_type = ^mos65xx_op_type;

const
  /// = CS_OP_INVALID (Uninitialized).
  MOS65XX_OP_INVALID = 0;
  /// = CS_OP_REG (Register operand).
  MOS65XX_OP_REG = 1;
  /// = CS_OP_IMM (Immediate operand).
  MOS65XX_OP_IMM = 2;
  /// = CS_OP_MEM (Memory operand).
  MOS65XX_OP_MEM = 3;

type
  // Forward declarations
  Pcs_mos65xx_op = ^cs_mos65xx_op;
  Pcs_mos65xx = ^cs_mos65xx;

  cs_mos65xx_op_detail = record
    case Integer of
      0: (/// register value for REG operand
    reg: mos65xx_reg);
      1: (/// immediate value for IMM operand
    imm: UInt16);
      2: (/// address for MEM operand
    mem: UInt32);
  end;

  /// Instruction operand
  cs_mos65xx_op = record
    /// operand type
    type_: mos65xx_op_type;
    /// union op detail
    detail: cs_mos65xx_op_detail;
  end;

  /// The MOS65XX address mode and it's operands
  cs_mos65xx = record
    am: mos65xx_address_mode;
    modifies_flags: Boolean;
    /// Number of operands of this instruction,
    /// or 0 when instruction has no operand.
    op_count: UInt8;
    /// operands for this instruction.
    operands: array[0..2] of cs_mos65xx_op;
  end;

implementation

end.
