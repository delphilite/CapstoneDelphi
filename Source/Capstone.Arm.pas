{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Api Header                       }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: arm.h                                     }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.Arm;

{$I Capstone.inc}

interface

type
  /// ARM shift type
  arm_shifter = Integer;
  Parm_shifter = ^arm_shifter;

const
  ARM_SFT_INVALID = 0;
  /// shift with immediate const
  ARM_SFT_ASR = 1;
  /// shift with immediate const
  ARM_SFT_LSL = 2;
  /// shift with immediate const
  ARM_SFT_LSR = 3;
  /// shift with immediate const
  ARM_SFT_ROR = 4;
  /// shift with immediate const
  ARM_SFT_RRX = 5;
  /// shift with register
  ARM_SFT_ASR_REG = 6;
  /// shift with register
  ARM_SFT_LSL_REG = 7;
  /// shift with register
  ARM_SFT_LSR_REG = 8;
  /// shift with register
  ARM_SFT_ROR_REG = 9;
  /// shift with register
  ARM_SFT_RRX_REG = 10;

/// ARM condition code
type
  arm_cc = Integer;
  Parm_cc = ^arm_cc;

const
  ARM_CC_INVALID = 0;
  /// Equal                      Equal
  ARM_CC_EQ = 1;
  /// Not equal                  Not equal, or unordered
  ARM_CC_NE = 2;
  /// Carry set                  >, ==, or unordered
  ARM_CC_HS = 3;
  /// Carry clear                Less than
  ARM_CC_LO = 4;
  /// Minus, negative            Less than
  ARM_CC_MI = 5;
  /// Plus, positive or zero     >, ==, or unordered
  ARM_CC_PL = 6;
  /// Overflow                   Unordered
  ARM_CC_VS = 7;
  /// No overflow                Not unordered
  ARM_CC_VC = 8;
  /// Unsigned higher            Greater than, or unordered
  ARM_CC_HI = 9;
  /// Unsigned lower or same     Less than or equal
  ARM_CC_LS = 10;
  /// Greater than or equal      Greater than or equal
  ARM_CC_GE = 11;
  /// Less than                  Less than, or unordered
  ARM_CC_LT = 12;
  /// Greater than               Greater than
  ARM_CC_GT = 13;
  /// Less than or equal         <, ==, or unordered
  ARM_CC_LE = 14;
  /// Always (unconditional)     Always (unconditional)
  ARM_CC_AL = 15;

type
  arm_sysreg = Integer;
  Parm_sysreg = ^arm_sysreg;

const
  /// Special registers for MSR
  ARM_SYSREG_INVALID = 0;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_C = 1;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_X = 2;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_S = 4;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_F = 8;
  /// Special registers for MSR
  ARM_SYSREG_CPSR_C = 16;
  /// Special registers for MSR
  ARM_SYSREG_CPSR_X = 32;
  /// Special registers for MSR
  ARM_SYSREG_CPSR_S = 64;
  /// Special registers for MSR
  ARM_SYSREG_CPSR_F = 128;
  /// Special registers for MSR
  ARM_SYSREG_APSR = 256;
  /// Special registers for MSR
  ARM_SYSREG_APSR_G = 257;
  /// Special registers for MSR
  ARM_SYSREG_APSR_NZCVQ = 258;
  /// Special registers for MSR
  ARM_SYSREG_APSR_NZCVQG = 259;
  /// Special registers for MSR
  ARM_SYSREG_IAPSR = 260;
  /// Special registers for MSR
  ARM_SYSREG_IAPSR_G = 261;
  /// Special registers for MSR
  ARM_SYSREG_IAPSR_NZCVQG = 262;
  /// Special registers for MSR
  ARM_SYSREG_IAPSR_NZCVQ = 263;
  /// Special registers for MSR
  ARM_SYSREG_EAPSR = 264;
  /// Special registers for MSR
  ARM_SYSREG_EAPSR_G = 265;
  /// Special registers for MSR
  ARM_SYSREG_EAPSR_NZCVQG = 266;
  /// Special registers for MSR
  ARM_SYSREG_EAPSR_NZCVQ = 267;
  /// Special registers for MSR
  ARM_SYSREG_XPSR = 268;
  /// Special registers for MSR
  ARM_SYSREG_XPSR_G = 269;
  /// Special registers for MSR
  ARM_SYSREG_XPSR_NZCVQG = 270;
  /// Special registers for MSR
  ARM_SYSREG_XPSR_NZCVQ = 271;
  /// Special registers for MSR
  ARM_SYSREG_IPSR = 272;
  /// Special registers for MSR
  ARM_SYSREG_EPSR = 273;
  /// Special registers for MSR
  ARM_SYSREG_IEPSR = 274;
  /// Special registers for MSR
  ARM_SYSREG_MSP = 275;
  /// Special registers for MSR
  ARM_SYSREG_PSP = 276;
  /// Special registers for MSR
  ARM_SYSREG_PRIMASK = 277;
  /// Special registers for MSR
  ARM_SYSREG_BASEPRI = 278;
  /// Special registers for MSR
  ARM_SYSREG_BASEPRI_MAX = 279;
  /// Special registers for MSR
  ARM_SYSREG_FAULTMASK = 280;
  /// Special registers for MSR
  ARM_SYSREG_CONTROL = 281;
  /// Special registers for MSR
  ARM_SYSREG_R8_USR = 282;
  /// Special registers for MSR
  ARM_SYSREG_R9_USR = 283;
  /// Special registers for MSR
  ARM_SYSREG_R10_USR = 284;
  /// Special registers for MSR
  ARM_SYSREG_R11_USR = 285;
  /// Special registers for MSR
  ARM_SYSREG_R12_USR = 286;
  /// Special registers for MSR
  ARM_SYSREG_SP_USR = 287;
  /// Special registers for MSR
  ARM_SYSREG_LR_USR = 288;
  /// Special registers for MSR
  ARM_SYSREG_R8_FIQ = 289;
  /// Special registers for MSR
  ARM_SYSREG_R9_FIQ = 290;
  /// Special registers for MSR
  ARM_SYSREG_R10_FIQ = 291;
  /// Special registers for MSR
  ARM_SYSREG_R11_FIQ = 292;
  /// Special registers for MSR
  ARM_SYSREG_R12_FIQ = 293;
  /// Special registers for MSR
  ARM_SYSREG_SP_FIQ = 294;
  /// Special registers for MSR
  ARM_SYSREG_LR_FIQ = 295;
  /// Special registers for MSR
  ARM_SYSREG_LR_IRQ = 296;
  /// Special registers for MSR
  ARM_SYSREG_SP_IRQ = 297;
  /// Special registers for MSR
  ARM_SYSREG_LR_SVC = 298;
  /// Special registers for MSR
  ARM_SYSREG_SP_SVC = 299;
  /// Special registers for MSR
  ARM_SYSREG_LR_ABT = 300;
  /// Special registers for MSR
  ARM_SYSREG_SP_ABT = 301;
  /// Special registers for MSR
  ARM_SYSREG_LR_UND = 302;
  /// Special registers for MSR
  ARM_SYSREG_SP_UND = 303;
  /// Special registers for MSR
  ARM_SYSREG_LR_MON = 304;
  /// Special registers for MSR
  ARM_SYSREG_SP_MON = 305;
  /// Special registers for MSR
  ARM_SYSREG_ELR_HYP = 306;
  /// Special registers for MSR
  ARM_SYSREG_SP_HYP = 307;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_FIQ = 308;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_IRQ = 309;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_SVC = 310;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_ABT = 311;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_UND = 312;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_MON = 313;
  /// Special registers for MSR
  ARM_SYSREG_SPSR_HYP = 314;

/// The memory barrier constants map directly to the 4-bit encoding of
/// the option field for Memory Barrier operations.
type
  arm_mem_barrier = Integer;
  Parm_mem_barrier = ^arm_mem_barrier;

const
  ARM_MB_INVALID = 0;
  ARM_MB_RESERVED_0 = 1;
  ARM_MB_OSHLD = 2;
  ARM_MB_OSHST = 3;
  ARM_MB_OSH = 4;
  ARM_MB_RESERVED_4 = 5;
  ARM_MB_NSHLD = 6;
  ARM_MB_NSHST = 7;
  ARM_MB_NSH = 8;
  ARM_MB_RESERVED_8 = 9;
  ARM_MB_ISHLD = 10;
  ARM_MB_ISHST = 11;
  ARM_MB_ISH = 12;
  ARM_MB_RESERVED_12 = 13;
  ARM_MB_LD = 14;
  ARM_MB_ST = 15;
  ARM_MB_SY = 16;

/// Operand type for instruction's operands
type
  arm_op_type = Integer;
  Parm_op_type = ^arm_op_type;

const
  /// = CS_OP_INVALID (Uninitialized).
  ARM_OP_INVALID = 0;
  /// = CS_OP_REG (Register operand).
  ARM_OP_REG = 1;
  /// = CS_OP_IMM (Immediate operand).
  ARM_OP_IMM = 2;
  /// = CS_OP_MEM (Memory operand).
  ARM_OP_MEM_ = 3;
  /// = CS_OP_FP (Floating-Point operand).
  ARM_OP_FP = 4;
  /// C-Immediate (coprocessor registers)
  ARM_OP_CIMM = 64;
  /// P-Immediate (coprocessor registers)
  ARM_OP_PIMM = 65;
  /// operand for SETEND instruction
  ARM_OP_SETEND = 66;
  /// MSR/MRS special register operand
  ARM_OP_SYSREG = 67;

/// Operand type for SETEND instruction
type
  arm_setend_type = Integer;
  Parm_setend_type = ^arm_setend_type;

const
  /// Uninitialized.
  ARM_SETEND_INVALID = 0;
  /// BE operand.
  ARM_SETEND_BE = 1;
  /// LE operand
  ARM_SETEND_LE = 2;

type
  arm_cpsmode_type = Integer;
  Parm_cpsmode_type = ^arm_cpsmode_type;

const
  ARM_CPSMODE_INVALID = 0;
  ARM_CPSMODE_IE = 2;
  ARM_CPSMODE_ID = 3;

/// Operand type for SETEND instruction
type
  arm_cpsflag_type = Integer;
  Parm_cpsflag_type = ^arm_cpsflag_type;

const
  ARM_CPSFLAG_INVALID = 0;
  ARM_CPSFLAG_F = 1;
  ARM_CPSFLAG_I = 2;
  ARM_CPSFLAG_A = 4;
  /// no flag
  ARM_CPSFLAG_NONE = 16;

/// Data type for elements of vector instructions.
type
  arm_vectordata_type = Integer;
  Parm_vectordata_type = ^arm_vectordata_type;

const
  ARM_VECTORDATA_INVALID = 0;
  ARM_VECTORDATA_I8 = 1;
  ARM_VECTORDATA_I16 = 2;
  ARM_VECTORDATA_I32 = 3;
  ARM_VECTORDATA_I64 = 4;
  ARM_VECTORDATA_S8 = 5;
  ARM_VECTORDATA_S16 = 6;
  ARM_VECTORDATA_S32 = 7;
  ARM_VECTORDATA_S64 = 8;
  ARM_VECTORDATA_U8 = 9;
  ARM_VECTORDATA_U16 = 10;
  ARM_VECTORDATA_U32 = 11;
  ARM_VECTORDATA_U64 = 12;
  ARM_VECTORDATA_P8 = 13;
  ARM_VECTORDATA_F32 = 14;
  ARM_VECTORDATA_F64 = 15;
  ARM_VECTORDATA_F16F64 = 16;
  ARM_VECTORDATA_F64F16 = 17;
  ARM_VECTORDATA_F32F16 = 18;
  ARM_VECTORDATA_F16F32 = 19;
  ARM_VECTORDATA_F64F32 = 20;
  ARM_VECTORDATA_F32F64 = 21;
  ARM_VECTORDATA_S32F32 = 22;
  ARM_VECTORDATA_U32F32 = 23;
  ARM_VECTORDATA_F32S32 = 24;
  ARM_VECTORDATA_F32U32 = 25;
  ARM_VECTORDATA_F64S16 = 26;
  ARM_VECTORDATA_F32S16 = 27;
  ARM_VECTORDATA_F64S32 = 28;
  ARM_VECTORDATA_S16F64 = 29;
  ARM_VECTORDATA_S16F32 = 30;
  ARM_VECTORDATA_S32F64 = 31;
  ARM_VECTORDATA_U16F64 = 32;
  ARM_VECTORDATA_U16F32 = 33;
  ARM_VECTORDATA_U32F64 = 34;
  ARM_VECTORDATA_F64U16 = 35;
  ARM_VECTORDATA_F32U16 = 36;
  ARM_VECTORDATA_F64U32 = 37;

/// ARM registers
type
  arm_reg = Integer;
  Parm_reg = ^arm_reg;

const
  ARM_REG_INVALID = 0;
  ARM_REG_APSR = 1;
  ARM_REG_APSR_NZCV = 2;
  ARM_REG_CPSR = 3;
  ARM_REG_FPEXC = 4;
  ARM_REG_FPINST = 5;
  ARM_REG_FPSCR = 6;
  ARM_REG_FPSCR_NZCV = 7;
  ARM_REG_FPSID = 8;
  ARM_REG_ITSTATE = 9;
  ARM_REG_LR = 10;
  ARM_REG_PC = 11;
  ARM_REG_SP = 12;
  ARM_REG_SPSR = 13;
  ARM_REG_D0 = 14;
  ARM_REG_D1 = 15;
  ARM_REG_D2 = 16;
  ARM_REG_D3 = 17;
  ARM_REG_D4 = 18;
  ARM_REG_D5 = 19;
  ARM_REG_D6 = 20;
  ARM_REG_D7 = 21;
  ARM_REG_D8 = 22;
  ARM_REG_D9 = 23;
  ARM_REG_D10 = 24;
  ARM_REG_D11 = 25;
  ARM_REG_D12 = 26;
  ARM_REG_D13 = 27;
  ARM_REG_D14 = 28;
  ARM_REG_D15 = 29;
  ARM_REG_D16 = 30;
  ARM_REG_D17 = 31;
  ARM_REG_D18 = 32;
  ARM_REG_D19 = 33;
  ARM_REG_D20 = 34;
  ARM_REG_D21 = 35;
  ARM_REG_D22 = 36;
  ARM_REG_D23 = 37;
  ARM_REG_D24 = 38;
  ARM_REG_D25 = 39;
  ARM_REG_D26 = 40;
  ARM_REG_D27 = 41;
  ARM_REG_D28 = 42;
  ARM_REG_D29 = 43;
  ARM_REG_D30 = 44;
  ARM_REG_D31 = 45;
  ARM_REG_FPINST2 = 46;
  ARM_REG_MVFR0 = 47;
  ARM_REG_MVFR1 = 48;
  ARM_REG_MVFR2 = 49;
  ARM_REG_Q0 = 50;
  ARM_REG_Q1 = 51;
  ARM_REG_Q2 = 52;
  ARM_REG_Q3 = 53;
  ARM_REG_Q4 = 54;
  ARM_REG_Q5 = 55;
  ARM_REG_Q6 = 56;
  ARM_REG_Q7 = 57;
  ARM_REG_Q8 = 58;
  ARM_REG_Q9 = 59;
  ARM_REG_Q10 = 60;
  ARM_REG_Q11 = 61;
  ARM_REG_Q12 = 62;
  ARM_REG_Q13 = 63;
  ARM_REG_Q14 = 64;
  ARM_REG_Q15 = 65;
  ARM_REG_R0 = 66;
  ARM_REG_R1 = 67;
  ARM_REG_R2 = 68;
  ARM_REG_R3 = 69;
  ARM_REG_R4 = 70;
  ARM_REG_R5 = 71;
  ARM_REG_R6 = 72;
  ARM_REG_R7 = 73;
  ARM_REG_R8 = 74;
  ARM_REG_R9 = 75;
  ARM_REG_R10 = 76;
  ARM_REG_R11 = 77;
  ARM_REG_R12 = 78;
  ARM_REG_S0 = 79;
  ARM_REG_S1 = 80;
  ARM_REG_S2 = 81;
  ARM_REG_S3 = 82;
  ARM_REG_S4 = 83;
  ARM_REG_S5 = 84;
  ARM_REG_S6 = 85;
  ARM_REG_S7 = 86;
  ARM_REG_S8 = 87;
  ARM_REG_S9 = 88;
  ARM_REG_S10 = 89;
  ARM_REG_S11 = 90;
  ARM_REG_S12 = 91;
  ARM_REG_S13 = 92;
  ARM_REG_S14 = 93;
  ARM_REG_S15 = 94;
  ARM_REG_S16 = 95;
  ARM_REG_S17 = 96;
  ARM_REG_S18 = 97;
  ARM_REG_S19 = 98;
  ARM_REG_S20 = 99;
  ARM_REG_S21 = 100;
  ARM_REG_S22 = 101;
  ARM_REG_S23 = 102;
  ARM_REG_S24 = 103;
  ARM_REG_S25 = 104;
  ARM_REG_S26 = 105;
  ARM_REG_S27 = 106;
  ARM_REG_S28 = 107;
  ARM_REG_S29 = 108;
  ARM_REG_S30 = 109;
  ARM_REG_S31 = 110;
  ARM_REG_ENDING = 111;
  ARM_REG_R13 = 12;
  ARM_REG_R14 = 10;
  ARM_REG_R15 = 11;
  ARM_REG_SB = 75;
  ARM_REG_SL = 76;
  ARM_REG_FP = 77;
  ARM_REG_IP = 78;

/// ARM instruction
type
  arm_insn = Integer;
  Parm_insn = ^arm_insn;

const
  ARM_INS_INVALID = 0;
  ARM_INS_ADC = 1;
  ARM_INS_ADD = 2;
  ARM_INS_ADR = 3;
  ARM_INS_AESD = 4;
  ARM_INS_AESE = 5;
  ARM_INS_AESIMC = 6;
  ARM_INS_AESMC = 7;
  ARM_INS_AND = 8;
  ARM_INS_BFC = 9;
  ARM_INS_BFI = 10;
  ARM_INS_BIC = 11;
  ARM_INS_BKPT = 12;
  ARM_INS_BL = 13;
  ARM_INS_BLX = 14;
  ARM_INS_BX = 15;
  ARM_INS_BXJ = 16;
  ARM_INS_B = 17;
  ARM_INS_CDP = 18;
  ARM_INS_CDP2 = 19;
  ARM_INS_CLREX = 20;
  ARM_INS_CLZ = 21;
  ARM_INS_CMN = 22;
  ARM_INS_CMP = 23;
  ARM_INS_CPS = 24;
  ARM_INS_CRC32B = 25;
  ARM_INS_CRC32CB = 26;
  ARM_INS_CRC32CH = 27;
  ARM_INS_CRC32CW = 28;
  ARM_INS_CRC32H = 29;
  ARM_INS_CRC32W = 30;
  ARM_INS_DBG = 31;
  ARM_INS_DMB = 32;
  ARM_INS_DSB = 33;
  ARM_INS_EOR = 34;
  ARM_INS_ERET = 35;
  ARM_INS_VMOV = 36;
  ARM_INS_FLDMDBX = 37;
  ARM_INS_FLDMIAX = 38;
  ARM_INS_VMRS = 39;
  ARM_INS_FSTMDBX = 40;
  ARM_INS_FSTMIAX = 41;
  ARM_INS_HINT = 42;
  ARM_INS_HLT = 43;
  ARM_INS_HVC = 44;
  ARM_INS_ISB = 45;
  ARM_INS_LDA = 46;
  ARM_INS_LDAB = 47;
  ARM_INS_LDAEX = 48;
  ARM_INS_LDAEXB = 49;
  ARM_INS_LDAEXD = 50;
  ARM_INS_LDAEXH = 51;
  ARM_INS_LDAH = 52;
  ARM_INS_LDC2L = 53;
  ARM_INS_LDC2 = 54;
  ARM_INS_LDCL = 55;
  ARM_INS_LDC = 56;
  ARM_INS_LDMDA = 57;
  ARM_INS_LDMDB = 58;
  ARM_INS_LDM = 59;
  ARM_INS_LDMIB = 60;
  ARM_INS_LDRBT = 61;
  ARM_INS_LDRB = 62;
  ARM_INS_LDRD = 63;
  ARM_INS_LDREX = 64;
  ARM_INS_LDREXB = 65;
  ARM_INS_LDREXD = 66;
  ARM_INS_LDREXH = 67;
  ARM_INS_LDRH = 68;
  ARM_INS_LDRHT = 69;
  ARM_INS_LDRSB = 70;
  ARM_INS_LDRSBT = 71;
  ARM_INS_LDRSH = 72;
  ARM_INS_LDRSHT = 73;
  ARM_INS_LDRT = 74;
  ARM_INS_LDR = 75;
  ARM_INS_MCR = 76;
  ARM_INS_MCR2 = 77;
  ARM_INS_MCRR = 78;
  ARM_INS_MCRR2 = 79;
  ARM_INS_MLA = 80;
  ARM_INS_MLS = 81;
  ARM_INS_MOV = 82;
  ARM_INS_MOVT = 83;
  ARM_INS_MOVW = 84;
  ARM_INS_MRC = 85;
  ARM_INS_MRC2 = 86;
  ARM_INS_MRRC = 87;
  ARM_INS_MRRC2 = 88;
  ARM_INS_MRS = 89;
  ARM_INS_MSR = 90;
  ARM_INS_MUL = 91;
  ARM_INS_MVN = 92;
  ARM_INS_ORR = 93;
  ARM_INS_PKHBT = 94;
  ARM_INS_PKHTB = 95;
  ARM_INS_PLDW = 96;
  ARM_INS_PLD = 97;
  ARM_INS_PLI = 98;
  ARM_INS_QADD = 99;
  ARM_INS_QADD16 = 100;
  ARM_INS_QADD8 = 101;
  ARM_INS_QASX = 102;
  ARM_INS_QDADD = 103;
  ARM_INS_QDSUB = 104;
  ARM_INS_QSAX = 105;
  ARM_INS_QSUB = 106;
  ARM_INS_QSUB16 = 107;
  ARM_INS_QSUB8 = 108;
  ARM_INS_RBIT = 109;
  ARM_INS_REV = 110;
  ARM_INS_REV16 = 111;
  ARM_INS_REVSH = 112;
  ARM_INS_RFEDA = 113;
  ARM_INS_RFEDB = 114;
  ARM_INS_RFEIA = 115;
  ARM_INS_RFEIB = 116;
  ARM_INS_RSB = 117;
  ARM_INS_RSC = 118;
  ARM_INS_SADD16 = 119;
  ARM_INS_SADD8 = 120;
  ARM_INS_SASX = 121;
  ARM_INS_SBC = 122;
  ARM_INS_SBFX = 123;
  ARM_INS_SDIV = 124;
  ARM_INS_SEL = 125;
  ARM_INS_SETEND = 126;
  ARM_INS_SHA1C = 127;
  ARM_INS_SHA1H = 128;
  ARM_INS_SHA1M = 129;
  ARM_INS_SHA1P = 130;
  ARM_INS_SHA1SU0 = 131;
  ARM_INS_SHA1SU1 = 132;
  ARM_INS_SHA256H = 133;
  ARM_INS_SHA256H2 = 134;
  ARM_INS_SHA256SU0 = 135;
  ARM_INS_SHA256SU1 = 136;
  ARM_INS_SHADD16 = 137;
  ARM_INS_SHADD8 = 138;
  ARM_INS_SHASX = 139;
  ARM_INS_SHSAX = 140;
  ARM_INS_SHSUB16 = 141;
  ARM_INS_SHSUB8 = 142;
  ARM_INS_SMC = 143;
  ARM_INS_SMLABB = 144;
  ARM_INS_SMLABT = 145;
  ARM_INS_SMLAD = 146;
  ARM_INS_SMLADX = 147;
  ARM_INS_SMLAL = 148;
  ARM_INS_SMLALBB = 149;
  ARM_INS_SMLALBT = 150;
  ARM_INS_SMLALD = 151;
  ARM_INS_SMLALDX = 152;
  ARM_INS_SMLALTB = 153;
  ARM_INS_SMLALTT = 154;
  ARM_INS_SMLATB = 155;
  ARM_INS_SMLATT = 156;
  ARM_INS_SMLAWB = 157;
  ARM_INS_SMLAWT = 158;
  ARM_INS_SMLSD = 159;
  ARM_INS_SMLSDX = 160;
  ARM_INS_SMLSLD = 161;
  ARM_INS_SMLSLDX = 162;
  ARM_INS_SMMLA = 163;
  ARM_INS_SMMLAR = 164;
  ARM_INS_SMMLS = 165;
  ARM_INS_SMMLSR = 166;
  ARM_INS_SMMUL = 167;
  ARM_INS_SMMULR = 168;
  ARM_INS_SMUAD = 169;
  ARM_INS_SMUADX = 170;
  ARM_INS_SMULBB = 171;
  ARM_INS_SMULBT = 172;
  ARM_INS_SMULL = 173;
  ARM_INS_SMULTB = 174;
  ARM_INS_SMULTT = 175;
  ARM_INS_SMULWB = 176;
  ARM_INS_SMULWT = 177;
  ARM_INS_SMUSD = 178;
  ARM_INS_SMUSDX = 179;
  ARM_INS_SRSDA = 180;
  ARM_INS_SRSDB = 181;
  ARM_INS_SRSIA = 182;
  ARM_INS_SRSIB = 183;
  ARM_INS_SSAT = 184;
  ARM_INS_SSAT16 = 185;
  ARM_INS_SSAX = 186;
  ARM_INS_SSUB16 = 187;
  ARM_INS_SSUB8 = 188;
  ARM_INS_STC2L = 189;
  ARM_INS_STC2 = 190;
  ARM_INS_STCL = 191;
  ARM_INS_STC = 192;
  ARM_INS_STL = 193;
  ARM_INS_STLB = 194;
  ARM_INS_STLEX = 195;
  ARM_INS_STLEXB = 196;
  ARM_INS_STLEXD = 197;
  ARM_INS_STLEXH = 198;
  ARM_INS_STLH = 199;
  ARM_INS_STMDA = 200;
  ARM_INS_STMDB = 201;
  ARM_INS_STM = 202;
  ARM_INS_STMIB = 203;
  ARM_INS_STRBT = 204;
  ARM_INS_STRB = 205;
  ARM_INS_STRD = 206;
  ARM_INS_STREX = 207;
  ARM_INS_STREXB = 208;
  ARM_INS_STREXD = 209;
  ARM_INS_STREXH = 210;
  ARM_INS_STRH = 211;
  ARM_INS_STRHT = 212;
  ARM_INS_STRT = 213;
  ARM_INS_STR = 214;
  ARM_INS_SUB = 215;
  ARM_INS_SVC = 216;
  ARM_INS_SWP = 217;
  ARM_INS_SWPB = 218;
  ARM_INS_SXTAB = 219;
  ARM_INS_SXTAB16 = 220;
  ARM_INS_SXTAH = 221;
  ARM_INS_SXTB = 222;
  ARM_INS_SXTB16 = 223;
  ARM_INS_SXTH = 224;
  ARM_INS_TEQ = 225;
  ARM_INS_TRAP = 226;
  ARM_INS_TST = 227;
  ARM_INS_UADD16 = 228;
  ARM_INS_UADD8 = 229;
  ARM_INS_UASX = 230;
  ARM_INS_UBFX = 231;
  ARM_INS_UDF = 232;
  ARM_INS_UDIV = 233;
  ARM_INS_UHADD16 = 234;
  ARM_INS_UHADD8 = 235;
  ARM_INS_UHASX = 236;
  ARM_INS_UHSAX = 237;
  ARM_INS_UHSUB16 = 238;
  ARM_INS_UHSUB8 = 239;
  ARM_INS_UMAAL = 240;
  ARM_INS_UMLAL = 241;
  ARM_INS_UMULL = 242;
  ARM_INS_UQADD16 = 243;
  ARM_INS_UQADD8 = 244;
  ARM_INS_UQASX = 245;
  ARM_INS_UQSAX = 246;
  ARM_INS_UQSUB16 = 247;
  ARM_INS_UQSUB8 = 248;
  ARM_INS_USAD8 = 249;
  ARM_INS_USADA8 = 250;
  ARM_INS_USAT = 251;
  ARM_INS_USAT16 = 252;
  ARM_INS_USAX = 253;
  ARM_INS_USUB16 = 254;
  ARM_INS_USUB8 = 255;
  ARM_INS_UXTAB = 256;
  ARM_INS_UXTAB16 = 257;
  ARM_INS_UXTAH = 258;
  ARM_INS_UXTB = 259;
  ARM_INS_UXTB16 = 260;
  ARM_INS_UXTH = 261;
  ARM_INS_VABAL = 262;
  ARM_INS_VABA = 263;
  ARM_INS_VABDL = 264;
  ARM_INS_VABD = 265;
  ARM_INS_VABS = 266;
  ARM_INS_VACGE = 267;
  ARM_INS_VACGT = 268;
  ARM_INS_VADD = 269;
  ARM_INS_VADDHN = 270;
  ARM_INS_VADDL = 271;
  ARM_INS_VADDW = 272;
  ARM_INS_VAND = 273;
  ARM_INS_VBIC = 274;
  ARM_INS_VBIF = 275;
  ARM_INS_VBIT = 276;
  ARM_INS_VBSL = 277;
  ARM_INS_VCEQ = 278;
  ARM_INS_VCGE = 279;
  ARM_INS_VCGT = 280;
  ARM_INS_VCLE = 281;
  ARM_INS_VCLS = 282;
  ARM_INS_VCLT = 283;
  ARM_INS_VCLZ = 284;
  ARM_INS_VCMP = 285;
  ARM_INS_VCMPE = 286;
  ARM_INS_VCNT = 287;
  ARM_INS_VCVTA = 288;
  ARM_INS_VCVTB = 289;
  ARM_INS_VCVT = 290;
  ARM_INS_VCVTM = 291;
  ARM_INS_VCVTN = 292;
  ARM_INS_VCVTP = 293;
  ARM_INS_VCVTT = 294;
  ARM_INS_VDIV = 295;
  ARM_INS_VDUP = 296;
  ARM_INS_VEOR = 297;
  ARM_INS_VEXT = 298;
  ARM_INS_VFMA = 299;
  ARM_INS_VFMS = 300;
  ARM_INS_VFNMA = 301;
  ARM_INS_VFNMS = 302;
  ARM_INS_VHADD = 303;
  ARM_INS_VHSUB = 304;
  ARM_INS_VLD1 = 305;
  ARM_INS_VLD2 = 306;
  ARM_INS_VLD3 = 307;
  ARM_INS_VLD4 = 308;
  ARM_INS_VLDMDB = 309;
  ARM_INS_VLDMIA = 310;
  ARM_INS_VLDR = 311;
  ARM_INS_VMAXNM = 312;
  ARM_INS_VMAX = 313;
  ARM_INS_VMINNM = 314;
  ARM_INS_VMIN = 315;
  ARM_INS_VMLA = 316;
  ARM_INS_VMLAL = 317;
  ARM_INS_VMLS = 318;
  ARM_INS_VMLSL = 319;
  ARM_INS_VMOVL = 320;
  ARM_INS_VMOVN = 321;
  ARM_INS_VMSR = 322;
  ARM_INS_VMUL = 323;
  ARM_INS_VMULL = 324;
  ARM_INS_VMVN = 325;
  ARM_INS_VNEG = 326;
  ARM_INS_VNMLA = 327;
  ARM_INS_VNMLS = 328;
  ARM_INS_VNMUL = 329;
  ARM_INS_VORN = 330;
  ARM_INS_VORR = 331;
  ARM_INS_VPADAL = 332;
  ARM_INS_VPADDL = 333;
  ARM_INS_VPADD = 334;
  ARM_INS_VPMAX = 335;
  ARM_INS_VPMIN = 336;
  ARM_INS_VQABS = 337;
  ARM_INS_VQADD = 338;
  ARM_INS_VQDMLAL = 339;
  ARM_INS_VQDMLSL = 340;
  ARM_INS_VQDMULH = 341;
  ARM_INS_VQDMULL = 342;
  ARM_INS_VQMOVUN = 343;
  ARM_INS_VQMOVN = 344;
  ARM_INS_VQNEG = 345;
  ARM_INS_VQRDMULH = 346;
  ARM_INS_VQRSHL = 347;
  ARM_INS_VQRSHRN = 348;
  ARM_INS_VQRSHRUN = 349;
  ARM_INS_VQSHL = 350;
  ARM_INS_VQSHLU = 351;
  ARM_INS_VQSHRN = 352;
  ARM_INS_VQSHRUN = 353;
  ARM_INS_VQSUB = 354;
  ARM_INS_VRADDHN = 355;
  ARM_INS_VRECPE = 356;
  ARM_INS_VRECPS = 357;
  ARM_INS_VREV16 = 358;
  ARM_INS_VREV32 = 359;
  ARM_INS_VREV64 = 360;
  ARM_INS_VRHADD = 361;
  ARM_INS_VRINTA = 362;
  ARM_INS_VRINTM = 363;
  ARM_INS_VRINTN = 364;
  ARM_INS_VRINTP = 365;
  ARM_INS_VRINTR = 366;
  ARM_INS_VRINTX = 367;
  ARM_INS_VRINTZ = 368;
  ARM_INS_VRSHL = 369;
  ARM_INS_VRSHRN = 370;
  ARM_INS_VRSHR = 371;
  ARM_INS_VRSQRTE = 372;
  ARM_INS_VRSQRTS = 373;
  ARM_INS_VRSRA = 374;
  ARM_INS_VRSUBHN = 375;
  ARM_INS_VSELEQ = 376;
  ARM_INS_VSELGE = 377;
  ARM_INS_VSELGT = 378;
  ARM_INS_VSELVS = 379;
  ARM_INS_VSHLL = 380;
  ARM_INS_VSHL = 381;
  ARM_INS_VSHRN = 382;
  ARM_INS_VSHR = 383;
  ARM_INS_VSLI = 384;
  ARM_INS_VSQRT = 385;
  ARM_INS_VSRA = 386;
  ARM_INS_VSRI = 387;
  ARM_INS_VST1 = 388;
  ARM_INS_VST2 = 389;
  ARM_INS_VST3 = 390;
  ARM_INS_VST4 = 391;
  ARM_INS_VSTMDB = 392;
  ARM_INS_VSTMIA = 393;
  ARM_INS_VSTR = 394;
  ARM_INS_VSUB = 395;
  ARM_INS_VSUBHN = 396;
  ARM_INS_VSUBL = 397;
  ARM_INS_VSUBW = 398;
  ARM_INS_VSWP = 399;
  ARM_INS_VTBL = 400;
  ARM_INS_VTBX = 401;
  ARM_INS_VCVTR = 402;
  ARM_INS_VTRN = 403;
  ARM_INS_VTST = 404;
  ARM_INS_VUZP = 405;
  ARM_INS_VZIP = 406;
  ARM_INS_ADDW = 407;
  ARM_INS_ASR = 408;
  ARM_INS_DCPS1 = 409;
  ARM_INS_DCPS2 = 410;
  ARM_INS_DCPS3 = 411;
  ARM_INS_IT = 412;
  ARM_INS_LSL = 413;
  ARM_INS_LSR = 414;
  ARM_INS_ORN = 415;
  ARM_INS_ROR = 416;
  ARM_INS_RRX = 417;
  ARM_INS_SUBW = 418;
  ARM_INS_TBB = 419;
  ARM_INS_TBH = 420;
  ARM_INS_CBNZ = 421;
  ARM_INS_CBZ = 422;
  ARM_INS_POP = 423;
  ARM_INS_PUSH = 424;
  ARM_INS_NOP = 425;
  ARM_INS_YIELD = 426;
  ARM_INS_WFE = 427;
  ARM_INS_WFI = 428;
  ARM_INS_SEV = 429;
  ARM_INS_SEVL = 430;
  ARM_INS_VPUSH = 431;
  ARM_INS_VPOP = 432;
  ARM_INS_ENDING = 433;

/// Group of ARM instructions
type
  arm_insn_group = Integer;
  Parm_insn_group = ^arm_insn_group;

const
  /// = CS_GRP_INVALID
  ARM_GRP_INVALID = 0;
  /// = CS_GRP_JUMP
  ARM_GRP_JUMP = 1;
  /// = CS_GRP_CALL
  ARM_GRP_CALL = 2;
  /// = CS_GRP_INT
  ARM_GRP_INT = 4;
  /// = CS_GRP_PRIVILEGE
  ARM_GRP_PRIVILEGE = 6;
  /// = CS_GRP_BRANCH_RELATIVE
  ARM_GRP_BRANCH_RELATIVE = 7;
  ARM_GRP_CRYPTO = 128;
  ARM_GRP_DATABARRIER = 129;
  ARM_GRP_DIVIDE = 130;
  ARM_GRP_FPARMV8 = 131;
  ARM_GRP_MULTPRO = 132;
  ARM_GRP_NEON = 133;
  ARM_GRP_T2EXTRACTPACK = 134;
  ARM_GRP_THUMB2DSP = 135;
  ARM_GRP_TRUSTZONE = 136;
  ARM_GRP_V4T = 137;
  ARM_GRP_V5T = 138;
  ARM_GRP_V5TE = 139;
  ARM_GRP_V6 = 140;
  ARM_GRP_V6T2 = 141;
  ARM_GRP_V7 = 142;
  ARM_GRP_V8 = 143;
  ARM_GRP_VFP2 = 144;
  ARM_GRP_VFP3 = 145;
  ARM_GRP_VFP4 = 146;
  ARM_GRP_ARM = 147;
  ARM_GRP_MCLASS = 148;
  ARM_GRP_NOTMCLASS = 149;
  ARM_GRP_THUMB = 150;
  ARM_GRP_THUMB1ONLY = 151;
  ARM_GRP_THUMB2 = 152;
  ARM_GRP_PREV8 = 153;
  ARM_GRP_FPVMLX = 154;
  ARM_GRP_MULOPS = 155;
  ARM_GRP_CRC = 156;
  ARM_GRP_DPVFP = 157;
  ARM_GRP_V6M = 158;
  ARM_GRP_VIRTUALIZATION = 159;
  ARM_GRP_ENDING = 160;

type
  // Forward declarations
  Parm_op_mem = ^arm_op_mem;
  Pcs_arm_op = ^cs_arm_op;
  Pcs_arm = ^cs_arm;

  /// Instruction's operand referring to memory
  /// This is associated with ARM_OP_MEM operand type above
  arm_op_mem = record
    /// base register
    base: arm_reg;
    /// index register
    index: arm_reg;
    /// scale for index register (can be 1, or -1)
    scale: Integer;
    /// displacement/offset value
    disp: Integer;
    /// left-shift on index register, or 0 if irrelevant
    /// NOTE: this value can also be fetched via operand.shift.value
    lshift: Integer;
  end;

  cs_arm_op_shift = record
    type_: arm_shifter;
    value: Cardinal;
  end;

  cs_arm_op_detail = record
    case Integer of
      0: (/// register value for REG/SYSREG operand
    reg: Integer);
      1: (/// immediate value for C-IMM, P-IMM or IMM operand
    imm: Int32);
      2: (/// floating point value for FP operand
    fp: Double);
      3: (/// base/index/scale/disp value for MEM operand
    mem: arm_op_mem);
      4: (/// SETEND instruction's operand type
    setend: arm_setend_type);
  end;

  /// Instruction operand
  cs_arm_op = record
    /// Vector Index for some vector operands (or -1 if irrelevant)
    vector_index: Integer;
    shift: cs_arm_op_shift;
    /// operand type
    type_: arm_op_type;
    /// union detail
    detail: cs_arm_op_detail;
    /// in some instructions, an operand can be subtracted or added to
    /// the base register,
    /// if TRUE, this operand is subtracted. otherwise, it is added.
    subtracted: Boolean;
    /// How is this operand accessed? (READ, WRITE or READ|WRITE)
    /// This field is combined of cs_ac_type.
    /// NOTE: this field is irrelevant if engine is compiled in DIET mode.
    access: UInt8;
    /// Neon lane index for NEON instructions (or -1 if irrelevant)
    neon_lane: Int8;
  end;

  /// Instruction structure
  cs_arm = record
    /// User-mode registers to be loaded (for LDM/STM instructions)
    usermode: Boolean;
    /// Scalar size for vector instructions
    vector_size: Integer;
    /// Data type for elements of vector instructions
    vector_data: arm_vectordata_type;
    /// CPS mode for CPS instruction
    cps_mode: arm_cpsmode_type;
    /// CPS mode for CPS instruction
    cps_flag: arm_cpsflag_type;
    /// conditional code for this insn
    cc: arm_cc;
    /// does this insn update flags?
    update_flags: Boolean;
    /// does this insn write-back?
    writeback: Boolean;
    /// Option for some memory barrier instructions
    mem_barrier: arm_mem_barrier;
    /// Number of operands of this instruction,
    /// or 0 when instruction has no operand.
    op_count: UInt8;
    /// operands for this instruction.
    operands: array[0..35] of cs_arm_op;
  end;

implementation

end.
