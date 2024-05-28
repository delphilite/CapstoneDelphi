{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Sparc header                     }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: sparc.h                                   }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.Sparc;

{$I Capstone.inc}

interface

type
  /// Enums corresponding to Sparc condition codes, both icc's and fcc's.
  sparc_cc = Integer;
  Psparc_cc = ^sparc_cc;

const
  /// invalid CC (default)
  SPARC_CC_INVALID = 0;
  /// Always
  SPARC_CC_ICC_A = 264;
  /// Never
  SPARC_CC_ICC_N = 256;
  /// Not Equal
  SPARC_CC_ICC_NE = 265;
  /// Equal
  SPARC_CC_ICC_E = 257;
  /// Greater
  SPARC_CC_ICC_G = 266;
  /// Less or Equal
  SPARC_CC_ICC_LE = 258;
  /// Greater or Equal
  SPARC_CC_ICC_GE = 267;
  /// Less
  SPARC_CC_ICC_L = 259;
  /// Greater Unsigned
  SPARC_CC_ICC_GU = 268;
  /// Less or Equal Unsigned
  SPARC_CC_ICC_LEU = 260;
  /// Carry Clear/Great or Equal Unsigned
  SPARC_CC_ICC_CC = 269;
  /// Carry Set/Less Unsigned
  SPARC_CC_ICC_CS = 261;
  /// Positive
  SPARC_CC_ICC_POS = 270;
  /// Negative
  SPARC_CC_ICC_NEG = 262;
  /// Overflow Clear
  SPARC_CC_ICC_VC = 271;
  /// Overflow Set
  SPARC_CC_ICC_VS = 263;
  /// Always
  SPARC_CC_FCC_A = 280;
  /// Never
  SPARC_CC_FCC_N = 272;
  /// Unordered
  SPARC_CC_FCC_U = 279;
  /// Greater
  SPARC_CC_FCC_G = 278;
  /// Unordered or Greater
  SPARC_CC_FCC_UG = 277;
  /// Less
  SPARC_CC_FCC_L = 276;
  /// Unordered or Less
  SPARC_CC_FCC_UL = 275;
  /// Less or Greater
  SPARC_CC_FCC_LG = 274;
  /// Not Equal
  SPARC_CC_FCC_NE = 273;
  /// Equal
  SPARC_CC_FCC_E = 281;
  /// Unordered or Equal
  SPARC_CC_FCC_UE = 282;
  /// Greater or Equal
  SPARC_CC_FCC_GE = 283;
  /// Unordered or Greater or Equal
  SPARC_CC_FCC_UGE = 284;
  /// Less or Equal
  SPARC_CC_FCC_LE = 285;
  /// Unordered or Less or Equal
  SPARC_CC_FCC_ULE = 286;
  /// Ordered
  SPARC_CC_FCC_O = 287;

/// Branch hint
type
  sparc_hint = Integer;
  Psparc_hint = ^sparc_hint;

const
  /// no hint
  SPARC_HINT_INVALID = 0;
  /// annul delay slot instruction
  SPARC_HINT_A = 1;
  /// branch taken
  SPARC_HINT_PT = 2;
  /// branch NOT taken
  SPARC_HINT_PN = 4;

/// Operand type for instruction's operands
type
  sparc_op_type = Integer;
  Psparc_op_type = ^sparc_op_type;

const
  /// = CS_OP_INVALID (Uninitialized).
  SPARC_OP_INVALID = 0;
  /// = CS_OP_REG (Register operand).
  SPARC_OP_REG = 1;
  /// = CS_OP_IMM (Immediate operand).
  SPARC_OP_IMM = 2;
  /// = CS_OP_MEM (Memory operand).
  SPARC_OP_MEM_ = 3;

/// SPARC registers
type
  sparc_reg = Integer;
  Psparc_reg = ^sparc_reg;

const
  SPARC_REG_INVALID = 0;
  SPARC_REG_F0 = 1;
  SPARC_REG_F1 = 2;
  SPARC_REG_F2 = 3;
  SPARC_REG_F3 = 4;
  SPARC_REG_F4 = 5;
  SPARC_REG_F5 = 6;
  SPARC_REG_F6 = 7;
  SPARC_REG_F7 = 8;
  SPARC_REG_F8 = 9;
  SPARC_REG_F9 = 10;
  SPARC_REG_F10 = 11;
  SPARC_REG_F11 = 12;
  SPARC_REG_F12 = 13;
  SPARC_REG_F13 = 14;
  SPARC_REG_F14 = 15;
  SPARC_REG_F15 = 16;
  SPARC_REG_F16 = 17;
  SPARC_REG_F17 = 18;
  SPARC_REG_F18 = 19;
  SPARC_REG_F19 = 20;
  SPARC_REG_F20 = 21;
  SPARC_REG_F21 = 22;
  SPARC_REG_F22 = 23;
  SPARC_REG_F23 = 24;
  SPARC_REG_F24 = 25;
  SPARC_REG_F25 = 26;
  SPARC_REG_F26 = 27;
  SPARC_REG_F27 = 28;
  SPARC_REG_F28 = 29;
  SPARC_REG_F29 = 30;
  SPARC_REG_F30 = 31;
  SPARC_REG_F31 = 32;
  SPARC_REG_F32 = 33;
  SPARC_REG_F34 = 34;
  SPARC_REG_F36 = 35;
  SPARC_REG_F38 = 36;
  SPARC_REG_F40 = 37;
  SPARC_REG_F42 = 38;
  SPARC_REG_F44 = 39;
  SPARC_REG_F46 = 40;
  SPARC_REG_F48 = 41;
  SPARC_REG_F50 = 42;
  SPARC_REG_F52 = 43;
  SPARC_REG_F54 = 44;
  SPARC_REG_F56 = 45;
  SPARC_REG_F58 = 46;
  SPARC_REG_F60 = 47;
  SPARC_REG_F62 = 48;
  SPARC_REG_FCC0 = 49;
  SPARC_REG_FCC1 = 50;
  SPARC_REG_FCC2 = 51;
  SPARC_REG_FCC3 = 52;
  SPARC_REG_FP = 53;
  SPARC_REG_G0 = 54;
  SPARC_REG_G1 = 55;
  SPARC_REG_G2 = 56;
  SPARC_REG_G3 = 57;
  SPARC_REG_G4 = 58;
  SPARC_REG_G5 = 59;
  SPARC_REG_G6 = 60;
  SPARC_REG_G7 = 61;
  SPARC_REG_I0 = 62;
  SPARC_REG_I1 = 63;
  SPARC_REG_I2 = 64;
  SPARC_REG_I3 = 65;
  SPARC_REG_I4 = 66;
  SPARC_REG_I5 = 67;
  SPARC_REG_I7 = 68;
  SPARC_REG_ICC = 69;
  SPARC_REG_L0 = 70;
  SPARC_REG_L1 = 71;
  SPARC_REG_L2 = 72;
  SPARC_REG_L3 = 73;
  SPARC_REG_L4 = 74;
  SPARC_REG_L5 = 75;
  SPARC_REG_L6 = 76;
  SPARC_REG_L7 = 77;
  SPARC_REG_O0 = 78;
  SPARC_REG_O1 = 79;
  SPARC_REG_O2 = 80;
  SPARC_REG_O3 = 81;
  SPARC_REG_O4 = 82;
  SPARC_REG_O5 = 83;
  SPARC_REG_O7 = 84;
  SPARC_REG_SP = 85;
  SPARC_REG_Y = 86;
  SPARC_REG_XCC = 87;
  SPARC_REG_ENDING = 88;
  SPARC_REG_O6 = 85;
  SPARC_REG_I6 = 53;

/// SPARC instruction
type
  sparc_insn = Integer;
  Psparc_insn = ^sparc_insn;

const
  SPARC_INS_INVALID = 0;
  SPARC_INS_ADDCC = 1;
  SPARC_INS_ADDX = 2;
  SPARC_INS_ADDXCC = 3;
  SPARC_INS_ADDXC = 4;
  SPARC_INS_ADDXCCC = 5;
  SPARC_INS_ADD = 6;
  SPARC_INS_ALIGNADDR = 7;
  SPARC_INS_ALIGNADDRL = 8;
  SPARC_INS_ANDCC = 9;
  SPARC_INS_ANDNCC = 10;
  SPARC_INS_ANDN = 11;
  SPARC_INS_AND = 12;
  SPARC_INS_ARRAY16 = 13;
  SPARC_INS_ARRAY32 = 14;
  SPARC_INS_ARRAY8 = 15;
  SPARC_INS_B = 16;
  SPARC_INS_JMP = 17;
  SPARC_INS_BMASK = 18;
  SPARC_INS_FB = 19;
  SPARC_INS_BRGEZ = 20;
  SPARC_INS_BRGZ = 21;
  SPARC_INS_BRLEZ = 22;
  SPARC_INS_BRLZ = 23;
  SPARC_INS_BRNZ = 24;
  SPARC_INS_BRZ = 25;
  SPARC_INS_BSHUFFLE = 26;
  SPARC_INS_CALL = 27;
  SPARC_INS_CASX = 28;
  SPARC_INS_CAS = 29;
  SPARC_INS_CMASK16 = 30;
  SPARC_INS_CMASK32 = 31;
  SPARC_INS_CMASK8 = 32;
  SPARC_INS_CMP = 33;
  SPARC_INS_EDGE16 = 34;
  SPARC_INS_EDGE16L = 35;
  SPARC_INS_EDGE16LN = 36;
  SPARC_INS_EDGE16N = 37;
  SPARC_INS_EDGE32 = 38;
  SPARC_INS_EDGE32L = 39;
  SPARC_INS_EDGE32LN = 40;
  SPARC_INS_EDGE32N = 41;
  SPARC_INS_EDGE8 = 42;
  SPARC_INS_EDGE8L = 43;
  SPARC_INS_EDGE8LN = 44;
  SPARC_INS_EDGE8N = 45;
  SPARC_INS_FABSD = 46;
  SPARC_INS_FABSQ = 47;
  SPARC_INS_FABSS = 48;
  SPARC_INS_FADDD = 49;
  SPARC_INS_FADDQ = 50;
  SPARC_INS_FADDS = 51;
  SPARC_INS_FALIGNDATA = 52;
  SPARC_INS_FAND = 53;
  SPARC_INS_FANDNOT1 = 54;
  SPARC_INS_FANDNOT1S = 55;
  SPARC_INS_FANDNOT2 = 56;
  SPARC_INS_FANDNOT2S = 57;
  SPARC_INS_FANDS = 58;
  SPARC_INS_FCHKSM16 = 59;
  SPARC_INS_FCMPD = 60;
  SPARC_INS_FCMPEQ16 = 61;
  SPARC_INS_FCMPEQ32 = 62;
  SPARC_INS_FCMPGT16 = 63;
  SPARC_INS_FCMPGT32 = 64;
  SPARC_INS_FCMPLE16 = 65;
  SPARC_INS_FCMPLE32 = 66;
  SPARC_INS_FCMPNE16 = 67;
  SPARC_INS_FCMPNE32 = 68;
  SPARC_INS_FCMPQ = 69;
  SPARC_INS_FCMPS = 70;
  SPARC_INS_FDIVD = 71;
  SPARC_INS_FDIVQ = 72;
  SPARC_INS_FDIVS = 73;
  SPARC_INS_FDMULQ = 74;
  SPARC_INS_FDTOI = 75;
  SPARC_INS_FDTOQ = 76;
  SPARC_INS_FDTOS = 77;
  SPARC_INS_FDTOX = 78;
  SPARC_INS_FEXPAND = 79;
  SPARC_INS_FHADDD = 80;
  SPARC_INS_FHADDS = 81;
  SPARC_INS_FHSUBD = 82;
  SPARC_INS_FHSUBS = 83;
  SPARC_INS_FITOD = 84;
  SPARC_INS_FITOQ = 85;
  SPARC_INS_FITOS = 86;
  SPARC_INS_FLCMPD = 87;
  SPARC_INS_FLCMPS = 88;
  SPARC_INS_FLUSHW = 89;
  SPARC_INS_FMEAN16 = 90;
  SPARC_INS_FMOVD = 91;
  SPARC_INS_FMOVQ = 92;
  SPARC_INS_FMOVRDGEZ = 93;
  SPARC_INS_FMOVRQGEZ = 94;
  SPARC_INS_FMOVRSGEZ = 95;
  SPARC_INS_FMOVRDGZ = 96;
  SPARC_INS_FMOVRQGZ = 97;
  SPARC_INS_FMOVRSGZ = 98;
  SPARC_INS_FMOVRDLEZ = 99;
  SPARC_INS_FMOVRQLEZ = 100;
  SPARC_INS_FMOVRSLEZ = 101;
  SPARC_INS_FMOVRDLZ = 102;
  SPARC_INS_FMOVRQLZ = 103;
  SPARC_INS_FMOVRSLZ = 104;
  SPARC_INS_FMOVRDNZ = 105;
  SPARC_INS_FMOVRQNZ = 106;
  SPARC_INS_FMOVRSNZ = 107;
  SPARC_INS_FMOVRDZ = 108;
  SPARC_INS_FMOVRQZ = 109;
  SPARC_INS_FMOVRSZ = 110;
  SPARC_INS_FMOVS = 111;
  SPARC_INS_FMUL8SUX16 = 112;
  SPARC_INS_FMUL8ULX16 = 113;
  SPARC_INS_FMUL8X16 = 114;
  SPARC_INS_FMUL8X16AL = 115;
  SPARC_INS_FMUL8X16AU = 116;
  SPARC_INS_FMULD = 117;
  SPARC_INS_FMULD8SUX16 = 118;
  SPARC_INS_FMULD8ULX16 = 119;
  SPARC_INS_FMULQ = 120;
  SPARC_INS_FMULS = 121;
  SPARC_INS_FNADDD = 122;
  SPARC_INS_FNADDS = 123;
  SPARC_INS_FNAND = 124;
  SPARC_INS_FNANDS = 125;
  SPARC_INS_FNEGD = 126;
  SPARC_INS_FNEGQ = 127;
  SPARC_INS_FNEGS = 128;
  SPARC_INS_FNHADDD = 129;
  SPARC_INS_FNHADDS = 130;
  SPARC_INS_FNOR = 131;
  SPARC_INS_FNORS = 132;
  SPARC_INS_FNOT1 = 133;
  SPARC_INS_FNOT1S = 134;
  SPARC_INS_FNOT2 = 135;
  SPARC_INS_FNOT2S = 136;
  SPARC_INS_FONE = 137;
  SPARC_INS_FONES = 138;
  SPARC_INS_FOR = 139;
  SPARC_INS_FORNOT1 = 140;
  SPARC_INS_FORNOT1S = 141;
  SPARC_INS_FORNOT2 = 142;
  SPARC_INS_FORNOT2S = 143;
  SPARC_INS_FORS = 144;
  SPARC_INS_FPACK16 = 145;
  SPARC_INS_FPACK32 = 146;
  SPARC_INS_FPACKFIX = 147;
  SPARC_INS_FPADD16 = 148;
  SPARC_INS_FPADD16S = 149;
  SPARC_INS_FPADD32 = 150;
  SPARC_INS_FPADD32S = 151;
  SPARC_INS_FPADD64 = 152;
  SPARC_INS_FPMERGE = 153;
  SPARC_INS_FPSUB16 = 154;
  SPARC_INS_FPSUB16S = 155;
  SPARC_INS_FPSUB32 = 156;
  SPARC_INS_FPSUB32S = 157;
  SPARC_INS_FQTOD = 158;
  SPARC_INS_FQTOI = 159;
  SPARC_INS_FQTOS = 160;
  SPARC_INS_FQTOX = 161;
  SPARC_INS_FSLAS16 = 162;
  SPARC_INS_FSLAS32 = 163;
  SPARC_INS_FSLL16 = 164;
  SPARC_INS_FSLL32 = 165;
  SPARC_INS_FSMULD = 166;
  SPARC_INS_FSQRTD = 167;
  SPARC_INS_FSQRTQ = 168;
  SPARC_INS_FSQRTS = 169;
  SPARC_INS_FSRA16 = 170;
  SPARC_INS_FSRA32 = 171;
  SPARC_INS_FSRC1 = 172;
  SPARC_INS_FSRC1S = 173;
  SPARC_INS_FSRC2 = 174;
  SPARC_INS_FSRC2S = 175;
  SPARC_INS_FSRL16 = 176;
  SPARC_INS_FSRL32 = 177;
  SPARC_INS_FSTOD = 178;
  SPARC_INS_FSTOI = 179;
  SPARC_INS_FSTOQ = 180;
  SPARC_INS_FSTOX = 181;
  SPARC_INS_FSUBD = 182;
  SPARC_INS_FSUBQ = 183;
  SPARC_INS_FSUBS = 184;
  SPARC_INS_FXNOR = 185;
  SPARC_INS_FXNORS = 186;
  SPARC_INS_FXOR = 187;
  SPARC_INS_FXORS = 188;
  SPARC_INS_FXTOD = 189;
  SPARC_INS_FXTOQ = 190;
  SPARC_INS_FXTOS = 191;
  SPARC_INS_FZERO = 192;
  SPARC_INS_FZEROS = 193;
  SPARC_INS_JMPL = 194;
  SPARC_INS_LDD = 195;
  SPARC_INS_LD = 196;
  SPARC_INS_LDQ = 197;
  SPARC_INS_LDSB = 198;
  SPARC_INS_LDSH = 199;
  SPARC_INS_LDSW = 200;
  SPARC_INS_LDUB = 201;
  SPARC_INS_LDUH = 202;
  SPARC_INS_LDX = 203;
  SPARC_INS_LZCNT = 204;
  SPARC_INS_MEMBAR = 205;
  SPARC_INS_MOVDTOX = 206;
  SPARC_INS_MOV = 207;
  SPARC_INS_MOVRGEZ = 208;
  SPARC_INS_MOVRGZ = 209;
  SPARC_INS_MOVRLEZ = 210;
  SPARC_INS_MOVRLZ = 211;
  SPARC_INS_MOVRNZ = 212;
  SPARC_INS_MOVRZ = 213;
  SPARC_INS_MOVSTOSW = 214;
  SPARC_INS_MOVSTOUW = 215;
  SPARC_INS_MULX = 216;
  SPARC_INS_NOP = 217;
  SPARC_INS_ORCC = 218;
  SPARC_INS_ORNCC = 219;
  SPARC_INS_ORN = 220;
  SPARC_INS_OR = 221;
  SPARC_INS_PDIST = 222;
  SPARC_INS_PDISTN = 223;
  SPARC_INS_POPC = 224;
  SPARC_INS_RD = 225;
  SPARC_INS_RESTORE = 226;
  SPARC_INS_RETT = 227;
  SPARC_INS_SAVE = 228;
  SPARC_INS_SDIVCC = 229;
  SPARC_INS_SDIVX = 230;
  SPARC_INS_SDIV = 231;
  SPARC_INS_SETHI = 232;
  SPARC_INS_SHUTDOWN = 233;
  SPARC_INS_SIAM = 234;
  SPARC_INS_SLLX = 235;
  SPARC_INS_SLL = 236;
  SPARC_INS_SMULCC = 237;
  SPARC_INS_SMUL = 238;
  SPARC_INS_SRAX = 239;
  SPARC_INS_SRA = 240;
  SPARC_INS_SRLX = 241;
  SPARC_INS_SRL = 242;
  SPARC_INS_STBAR = 243;
  SPARC_INS_STB = 244;
  SPARC_INS_STD = 245;
  SPARC_INS_ST = 246;
  SPARC_INS_STH = 247;
  SPARC_INS_STQ = 248;
  SPARC_INS_STX = 249;
  SPARC_INS_SUBCC = 250;
  SPARC_INS_SUBX = 251;
  SPARC_INS_SUBXCC = 252;
  SPARC_INS_SUB = 253;
  SPARC_INS_SWAP = 254;
  SPARC_INS_TADDCCTV = 255;
  SPARC_INS_TADDCC = 256;
  SPARC_INS_T = 257;
  SPARC_INS_TSUBCCTV = 258;
  SPARC_INS_TSUBCC = 259;
  SPARC_INS_UDIVCC = 260;
  SPARC_INS_UDIVX = 261;
  SPARC_INS_UDIV = 262;
  SPARC_INS_UMULCC = 263;
  SPARC_INS_UMULXHI = 264;
  SPARC_INS_UMUL = 265;
  SPARC_INS_UNIMP = 266;
  SPARC_INS_FCMPED = 267;
  SPARC_INS_FCMPEQ = 268;
  SPARC_INS_FCMPES = 269;
  SPARC_INS_WR = 270;
  SPARC_INS_XMULX = 271;
  SPARC_INS_XMULXHI = 272;
  SPARC_INS_XNORCC = 273;
  SPARC_INS_XNOR = 274;
  SPARC_INS_XORCC = 275;
  SPARC_INS_XOR = 276;
  SPARC_INS_RET = 277;
  SPARC_INS_RETL = 278;
  SPARC_INS_ENDING = 279;

/// Group of SPARC instructions
type
  sparc_insn_group = Integer;
  Psparc_insn_group = ^sparc_insn_group;

const
  /// = CS_GRP_INVALID
  SPARC_GRP_INVALID = 0;
  /// = CS_GRP_JUMP
  SPARC_GRP_JUMP = 1;
  SPARC_GRP_HARDQUAD = 128;
  SPARC_GRP_V9 = 129;
  SPARC_GRP_VIS = 130;
  SPARC_GRP_VIS2 = 131;
  SPARC_GRP_VIS3 = 132;
  SPARC_GRP_32BIT = 133;
  SPARC_GRP_64BIT = 134;
  SPARC_GRP_ENDING = 135;

type
  // Forward declarations
  Psparc_op_mem = ^sparc_op_mem;
  Pcs_sparc_op = ^cs_sparc_op;
  Pcs_sparc = ^cs_sparc;

  /// Instruction's operand referring to memory
  /// This is associated with SPARC_OP_MEM operand type above
  sparc_op_mem = record
    /// base register, can be safely interpreted as
    ///< a value of type `sparc_reg`, but it is only
    ///< one byte wide
    base: UInt8;
    /// index register, same conditions apply here
    index: UInt8;
    /// displacement/offset value
    disp: Int32;
  end;

  P_anonymous_type_1 = ^_anonymous_type_1;
  _anonymous_type_1 = record
    case Integer of
      0: (/// register value for REG operand
    reg: sparc_reg);
      1: (/// immediate value for IMM operand
    imm: Int64);
      2: (/// base/disp value for MEM operand
    mem: sparc_op_mem);
  end;

  /// Instruction operand
  cs_sparc_op = record
    /// operand type
    &type: sparc_op_type;
    f2: _anonymous_type_1;
  end;

  /// Instruction structure
  cs_sparc = record
    /// code condition for this insn
    cc: sparc_cc;
    /// branch hint: encoding as bitwise OR of sparc_hint.
    hint: sparc_hint;
    /// Number of operands of this instruction,
    /// or 0 when instruction has no operand.
    op_count: UInt8;
    /// operands for this instruction.
    operands: array [0..3] of cs_sparc_op;
  end;

implementation

end.
