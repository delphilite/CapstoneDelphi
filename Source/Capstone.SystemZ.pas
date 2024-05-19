{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone SystemZ header                   }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: systemz.h                                 }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.SystemZ;

{$I Capstone.inc}

interface

type
  /// Enums corresponding to SystemZ condition codes
  sysz_cc = Integer;
  Psysz_cc = ^sysz_cc;

const
  /// invalid CC (default)
  SYSZ_CC_INVALID = 0;
  SYSZ_CC_O = 1;
  SYSZ_CC_H = 2;
  SYSZ_CC_NLE = 3;
  SYSZ_CC_L = 4;
  SYSZ_CC_NHE = 5;
  SYSZ_CC_LH = 6;
  SYSZ_CC_NE = 7;
  SYSZ_CC_E = 8;
  SYSZ_CC_NLH = 9;
  SYSZ_CC_HE = 10;
  SYSZ_CC_NL = 11;
  SYSZ_CC_LE = 12;
  SYSZ_CC_NH = 13;
  SYSZ_CC_NO = 14;

/// Operand type for instruction's operands
type
  sysz_op_type = Integer;
  Psysz_op_type = ^sysz_op_type;

const
  /// = CS_OP_INVALID (Uninitialized).
  SYSZ_OP_INVALID = 0;
  /// = CS_OP_REG (Register operand).
  SYSZ_OP_REG = 1;
  /// = CS_OP_IMM (Immediate operand).
  SYSZ_OP_IMM = 2;
  /// = CS_OP_MEM (Memory operand).
  SYSZ_OP_MEM_ = 3;
  /// Access register operand.
  SYSZ_OP_ACREG = 64;

/// SystemZ registers
type
  sysz_reg = Integer;
  Psysz_reg = ^sysz_reg;

const
  SYSZ_REG_INVALID = 0;
  SYSZ_REG_0 = 1;
  SYSZ_REG_1 = 2;
  SYSZ_REG_2 = 3;
  SYSZ_REG_3 = 4;
  SYSZ_REG_4 = 5;
  SYSZ_REG_5 = 6;
  SYSZ_REG_6 = 7;
  SYSZ_REG_7 = 8;
  SYSZ_REG_8 = 9;
  SYSZ_REG_9 = 10;
  SYSZ_REG_10 = 11;
  SYSZ_REG_11 = 12;
  SYSZ_REG_12 = 13;
  SYSZ_REG_13 = 14;
  SYSZ_REG_14 = 15;
  SYSZ_REG_15 = 16;
  SYSZ_REG_CC = 17;
  SYSZ_REG_F0 = 18;
  SYSZ_REG_F1 = 19;
  SYSZ_REG_F2 = 20;
  SYSZ_REG_F3 = 21;
  SYSZ_REG_F4 = 22;
  SYSZ_REG_F5 = 23;
  SYSZ_REG_F6 = 24;
  SYSZ_REG_F7 = 25;
  SYSZ_REG_F8 = 26;
  SYSZ_REG_F9 = 27;
  SYSZ_REG_F10 = 28;
  SYSZ_REG_F11 = 29;
  SYSZ_REG_F12 = 30;
  SYSZ_REG_F13 = 31;
  SYSZ_REG_F14 = 32;
  SYSZ_REG_F15 = 33;
  SYSZ_REG_R0L = 34;
  SYSZ_REG_ENDING = 35;

/// SystemZ instruction
type
  sysz_insn = Integer;
  Psysz_insn = ^sysz_insn;

const
  SYSZ_INS_INVALID = 0;
  SYSZ_INS_A = 1;
  SYSZ_INS_ADB = 2;
  SYSZ_INS_ADBR = 3;
  SYSZ_INS_AEB = 4;
  SYSZ_INS_AEBR = 5;
  SYSZ_INS_AFI = 6;
  SYSZ_INS_AG = 7;
  SYSZ_INS_AGF = 8;
  SYSZ_INS_AGFI = 9;
  SYSZ_INS_AGFR = 10;
  SYSZ_INS_AGHI = 11;
  SYSZ_INS_AGHIK = 12;
  SYSZ_INS_AGR = 13;
  SYSZ_INS_AGRK = 14;
  SYSZ_INS_AGSI = 15;
  SYSZ_INS_AH = 16;
  SYSZ_INS_AHI = 17;
  SYSZ_INS_AHIK = 18;
  SYSZ_INS_AHY = 19;
  SYSZ_INS_AIH = 20;
  SYSZ_INS_AL = 21;
  SYSZ_INS_ALC = 22;
  SYSZ_INS_ALCG = 23;
  SYSZ_INS_ALCGR = 24;
  SYSZ_INS_ALCR = 25;
  SYSZ_INS_ALFI = 26;
  SYSZ_INS_ALG = 27;
  SYSZ_INS_ALGF = 28;
  SYSZ_INS_ALGFI = 29;
  SYSZ_INS_ALGFR = 30;
  SYSZ_INS_ALGHSIK = 31;
  SYSZ_INS_ALGR = 32;
  SYSZ_INS_ALGRK = 33;
  SYSZ_INS_ALHSIK = 34;
  SYSZ_INS_ALR = 35;
  SYSZ_INS_ALRK = 36;
  SYSZ_INS_ALY = 37;
  SYSZ_INS_AR = 38;
  SYSZ_INS_ARK = 39;
  SYSZ_INS_ASI = 40;
  SYSZ_INS_AXBR = 41;
  SYSZ_INS_AY = 42;
  SYSZ_INS_BCR = 43;
  SYSZ_INS_BRC = 44;
  SYSZ_INS_BRCL = 45;
  SYSZ_INS_CGIJ = 46;
  SYSZ_INS_CGRJ = 47;
  SYSZ_INS_CIJ = 48;
  SYSZ_INS_CLGIJ = 49;
  SYSZ_INS_CLGRJ = 50;
  SYSZ_INS_CLIJ = 51;
  SYSZ_INS_CLRJ = 52;
  SYSZ_INS_CRJ = 53;
  SYSZ_INS_BER = 54;
  SYSZ_INS_JE = 55;
  SYSZ_INS_JGE = 56;
  SYSZ_INS_LOCE = 57;
  SYSZ_INS_LOCGE = 58;
  SYSZ_INS_LOCGRE = 59;
  SYSZ_INS_LOCRE = 60;
  SYSZ_INS_STOCE = 61;
  SYSZ_INS_STOCGE = 62;
  SYSZ_INS_BHR = 63;
  SYSZ_INS_BHER = 64;
  SYSZ_INS_JHE = 65;
  SYSZ_INS_JGHE = 66;
  SYSZ_INS_LOCHE = 67;
  SYSZ_INS_LOCGHE = 68;
  SYSZ_INS_LOCGRHE = 69;
  SYSZ_INS_LOCRHE = 70;
  SYSZ_INS_STOCHE = 71;
  SYSZ_INS_STOCGHE = 72;
  SYSZ_INS_JH = 73;
  SYSZ_INS_JGH = 74;
  SYSZ_INS_LOCH = 75;
  SYSZ_INS_LOCGH = 76;
  SYSZ_INS_LOCGRH = 77;
  SYSZ_INS_LOCRH = 78;
  SYSZ_INS_STOCH = 79;
  SYSZ_INS_STOCGH = 80;
  SYSZ_INS_CGIJNLH = 81;
  SYSZ_INS_CGRJNLH = 82;
  SYSZ_INS_CIJNLH = 83;
  SYSZ_INS_CLGIJNLH = 84;
  SYSZ_INS_CLGRJNLH = 85;
  SYSZ_INS_CLIJNLH = 86;
  SYSZ_INS_CLRJNLH = 87;
  SYSZ_INS_CRJNLH = 88;
  SYSZ_INS_CGIJE = 89;
  SYSZ_INS_CGRJE = 90;
  SYSZ_INS_CIJE = 91;
  SYSZ_INS_CLGIJE = 92;
  SYSZ_INS_CLGRJE = 93;
  SYSZ_INS_CLIJE = 94;
  SYSZ_INS_CLRJE = 95;
  SYSZ_INS_CRJE = 96;
  SYSZ_INS_CGIJNLE = 97;
  SYSZ_INS_CGRJNLE = 98;
  SYSZ_INS_CIJNLE = 99;
  SYSZ_INS_CLGIJNLE = 100;
  SYSZ_INS_CLGRJNLE = 101;
  SYSZ_INS_CLIJNLE = 102;
  SYSZ_INS_CLRJNLE = 103;
  SYSZ_INS_CRJNLE = 104;
  SYSZ_INS_CGIJH = 105;
  SYSZ_INS_CGRJH = 106;
  SYSZ_INS_CIJH = 107;
  SYSZ_INS_CLGIJH = 108;
  SYSZ_INS_CLGRJH = 109;
  SYSZ_INS_CLIJH = 110;
  SYSZ_INS_CLRJH = 111;
  SYSZ_INS_CRJH = 112;
  SYSZ_INS_CGIJNL = 113;
  SYSZ_INS_CGRJNL = 114;
  SYSZ_INS_CIJNL = 115;
  SYSZ_INS_CLGIJNL = 116;
  SYSZ_INS_CLGRJNL = 117;
  SYSZ_INS_CLIJNL = 118;
  SYSZ_INS_CLRJNL = 119;
  SYSZ_INS_CRJNL = 120;
  SYSZ_INS_CGIJHE = 121;
  SYSZ_INS_CGRJHE = 122;
  SYSZ_INS_CIJHE = 123;
  SYSZ_INS_CLGIJHE = 124;
  SYSZ_INS_CLGRJHE = 125;
  SYSZ_INS_CLIJHE = 126;
  SYSZ_INS_CLRJHE = 127;
  SYSZ_INS_CRJHE = 128;
  SYSZ_INS_CGIJNHE = 129;
  SYSZ_INS_CGRJNHE = 130;
  SYSZ_INS_CIJNHE = 131;
  SYSZ_INS_CLGIJNHE = 132;
  SYSZ_INS_CLGRJNHE = 133;
  SYSZ_INS_CLIJNHE = 134;
  SYSZ_INS_CLRJNHE = 135;
  SYSZ_INS_CRJNHE = 136;
  SYSZ_INS_CGIJL = 137;
  SYSZ_INS_CGRJL = 138;
  SYSZ_INS_CIJL = 139;
  SYSZ_INS_CLGIJL = 140;
  SYSZ_INS_CLGRJL = 141;
  SYSZ_INS_CLIJL = 142;
  SYSZ_INS_CLRJL = 143;
  SYSZ_INS_CRJL = 144;
  SYSZ_INS_CGIJNH = 145;
  SYSZ_INS_CGRJNH = 146;
  SYSZ_INS_CIJNH = 147;
  SYSZ_INS_CLGIJNH = 148;
  SYSZ_INS_CLGRJNH = 149;
  SYSZ_INS_CLIJNH = 150;
  SYSZ_INS_CLRJNH = 151;
  SYSZ_INS_CRJNH = 152;
  SYSZ_INS_CGIJLE = 153;
  SYSZ_INS_CGRJLE = 154;
  SYSZ_INS_CIJLE = 155;
  SYSZ_INS_CLGIJLE = 156;
  SYSZ_INS_CLGRJLE = 157;
  SYSZ_INS_CLIJLE = 158;
  SYSZ_INS_CLRJLE = 159;
  SYSZ_INS_CRJLE = 160;
  SYSZ_INS_CGIJNE = 161;
  SYSZ_INS_CGRJNE = 162;
  SYSZ_INS_CIJNE = 163;
  SYSZ_INS_CLGIJNE = 164;
  SYSZ_INS_CLGRJNE = 165;
  SYSZ_INS_CLIJNE = 166;
  SYSZ_INS_CLRJNE = 167;
  SYSZ_INS_CRJNE = 168;
  SYSZ_INS_CGIJLH = 169;
  SYSZ_INS_CGRJLH = 170;
  SYSZ_INS_CIJLH = 171;
  SYSZ_INS_CLGIJLH = 172;
  SYSZ_INS_CLGRJLH = 173;
  SYSZ_INS_CLIJLH = 174;
  SYSZ_INS_CLRJLH = 175;
  SYSZ_INS_CRJLH = 176;
  SYSZ_INS_BLR = 177;
  SYSZ_INS_BLER = 178;
  SYSZ_INS_JLE = 179;
  SYSZ_INS_JGLE = 180;
  SYSZ_INS_LOCLE = 181;
  SYSZ_INS_LOCGLE = 182;
  SYSZ_INS_LOCGRLE = 183;
  SYSZ_INS_LOCRLE = 184;
  SYSZ_INS_STOCLE = 185;
  SYSZ_INS_STOCGLE = 186;
  SYSZ_INS_BLHR = 187;
  SYSZ_INS_JLH = 188;
  SYSZ_INS_JGLH = 189;
  SYSZ_INS_LOCLH = 190;
  SYSZ_INS_LOCGLH = 191;
  SYSZ_INS_LOCGRLH = 192;
  SYSZ_INS_LOCRLH = 193;
  SYSZ_INS_STOCLH = 194;
  SYSZ_INS_STOCGLH = 195;
  SYSZ_INS_JL = 196;
  SYSZ_INS_JGL = 197;
  SYSZ_INS_LOCL = 198;
  SYSZ_INS_LOCGL = 199;
  SYSZ_INS_LOCGRL = 200;
  SYSZ_INS_LOCRL = 201;
  SYSZ_INS_LOC = 202;
  SYSZ_INS_LOCG = 203;
  SYSZ_INS_LOCGR = 204;
  SYSZ_INS_LOCR = 205;
  SYSZ_INS_STOCL = 206;
  SYSZ_INS_STOCGL = 207;
  SYSZ_INS_BNER = 208;
  SYSZ_INS_JNE = 209;
  SYSZ_INS_JGNE = 210;
  SYSZ_INS_LOCNE = 211;
  SYSZ_INS_LOCGNE = 212;
  SYSZ_INS_LOCGRNE = 213;
  SYSZ_INS_LOCRNE = 214;
  SYSZ_INS_STOCNE = 215;
  SYSZ_INS_STOCGNE = 216;
  SYSZ_INS_BNHR = 217;
  SYSZ_INS_BNHER = 218;
  SYSZ_INS_JNHE = 219;
  SYSZ_INS_JGNHE = 220;
  SYSZ_INS_LOCNHE = 221;
  SYSZ_INS_LOCGNHE = 222;
  SYSZ_INS_LOCGRNHE = 223;
  SYSZ_INS_LOCRNHE = 224;
  SYSZ_INS_STOCNHE = 225;
  SYSZ_INS_STOCGNHE = 226;
  SYSZ_INS_JNH = 227;
  SYSZ_INS_JGNH = 228;
  SYSZ_INS_LOCNH = 229;
  SYSZ_INS_LOCGNH = 230;
  SYSZ_INS_LOCGRNH = 231;
  SYSZ_INS_LOCRNH = 232;
  SYSZ_INS_STOCNH = 233;
  SYSZ_INS_STOCGNH = 234;
  SYSZ_INS_BNLR = 235;
  SYSZ_INS_BNLER = 236;
  SYSZ_INS_JNLE = 237;
  SYSZ_INS_JGNLE = 238;
  SYSZ_INS_LOCNLE = 239;
  SYSZ_INS_LOCGNLE = 240;
  SYSZ_INS_LOCGRNLE = 241;
  SYSZ_INS_LOCRNLE = 242;
  SYSZ_INS_STOCNLE = 243;
  SYSZ_INS_STOCGNLE = 244;
  SYSZ_INS_BNLHR = 245;
  SYSZ_INS_JNLH = 246;
  SYSZ_INS_JGNLH = 247;
  SYSZ_INS_LOCNLH = 248;
  SYSZ_INS_LOCGNLH = 249;
  SYSZ_INS_LOCGRNLH = 250;
  SYSZ_INS_LOCRNLH = 251;
  SYSZ_INS_STOCNLH = 252;
  SYSZ_INS_STOCGNLH = 253;
  SYSZ_INS_JNL = 254;
  SYSZ_INS_JGNL = 255;
  SYSZ_INS_LOCNL = 256;
  SYSZ_INS_LOCGNL = 257;
  SYSZ_INS_LOCGRNL = 258;
  SYSZ_INS_LOCRNL = 259;
  SYSZ_INS_STOCNL = 260;
  SYSZ_INS_STOCGNL = 261;
  SYSZ_INS_BNOR = 262;
  SYSZ_INS_JNO = 263;
  SYSZ_INS_JGNO = 264;
  SYSZ_INS_LOCNO = 265;
  SYSZ_INS_LOCGNO = 266;
  SYSZ_INS_LOCGRNO = 267;
  SYSZ_INS_LOCRNO = 268;
  SYSZ_INS_STOCNO = 269;
  SYSZ_INS_STOCGNO = 270;
  SYSZ_INS_BOR = 271;
  SYSZ_INS_JO = 272;
  SYSZ_INS_JGO = 273;
  SYSZ_INS_LOCO = 274;
  SYSZ_INS_LOCGO = 275;
  SYSZ_INS_LOCGRO = 276;
  SYSZ_INS_LOCRO = 277;
  SYSZ_INS_STOCO = 278;
  SYSZ_INS_STOCGO = 279;
  SYSZ_INS_STOC = 280;
  SYSZ_INS_STOCG = 281;
  SYSZ_INS_BASR = 282;
  SYSZ_INS_BR = 283;
  SYSZ_INS_BRAS = 284;
  SYSZ_INS_BRASL = 285;
  SYSZ_INS_J = 286;
  SYSZ_INS_JG = 287;
  SYSZ_INS_BRCT = 288;
  SYSZ_INS_BRCTG = 289;
  SYSZ_INS_C = 290;
  SYSZ_INS_CDB = 291;
  SYSZ_INS_CDBR = 292;
  SYSZ_INS_CDFBR = 293;
  SYSZ_INS_CDGBR = 294;
  SYSZ_INS_CDLFBR = 295;
  SYSZ_INS_CDLGBR = 296;
  SYSZ_INS_CEB = 297;
  SYSZ_INS_CEBR = 298;
  SYSZ_INS_CEFBR = 299;
  SYSZ_INS_CEGBR = 300;
  SYSZ_INS_CELFBR = 301;
  SYSZ_INS_CELGBR = 302;
  SYSZ_INS_CFDBR = 303;
  SYSZ_INS_CFEBR = 304;
  SYSZ_INS_CFI = 305;
  SYSZ_INS_CFXBR = 306;
  SYSZ_INS_CG = 307;
  SYSZ_INS_CGDBR = 308;
  SYSZ_INS_CGEBR = 309;
  SYSZ_INS_CGF = 310;
  SYSZ_INS_CGFI = 311;
  SYSZ_INS_CGFR = 312;
  SYSZ_INS_CGFRL = 313;
  SYSZ_INS_CGH = 314;
  SYSZ_INS_CGHI = 315;
  SYSZ_INS_CGHRL = 316;
  SYSZ_INS_CGHSI = 317;
  SYSZ_INS_CGR = 318;
  SYSZ_INS_CGRL = 319;
  SYSZ_INS_CGXBR = 320;
  SYSZ_INS_CH = 321;
  SYSZ_INS_CHF = 322;
  SYSZ_INS_CHHSI = 323;
  SYSZ_INS_CHI = 324;
  SYSZ_INS_CHRL = 325;
  SYSZ_INS_CHSI = 326;
  SYSZ_INS_CHY = 327;
  SYSZ_INS_CIH = 328;
  SYSZ_INS_CL = 329;
  SYSZ_INS_CLC = 330;
  SYSZ_INS_CLFDBR = 331;
  SYSZ_INS_CLFEBR = 332;
  SYSZ_INS_CLFHSI = 333;
  SYSZ_INS_CLFI = 334;
  SYSZ_INS_CLFXBR = 335;
  SYSZ_INS_CLG = 336;
  SYSZ_INS_CLGDBR = 337;
  SYSZ_INS_CLGEBR = 338;
  SYSZ_INS_CLGF = 339;
  SYSZ_INS_CLGFI = 340;
  SYSZ_INS_CLGFR = 341;
  SYSZ_INS_CLGFRL = 342;
  SYSZ_INS_CLGHRL = 343;
  SYSZ_INS_CLGHSI = 344;
  SYSZ_INS_CLGR = 345;
  SYSZ_INS_CLGRL = 346;
  SYSZ_INS_CLGXBR = 347;
  SYSZ_INS_CLHF = 348;
  SYSZ_INS_CLHHSI = 349;
  SYSZ_INS_CLHRL = 350;
  SYSZ_INS_CLI = 351;
  SYSZ_INS_CLIH = 352;
  SYSZ_INS_CLIY = 353;
  SYSZ_INS_CLR = 354;
  SYSZ_INS_CLRL = 355;
  SYSZ_INS_CLST = 356;
  SYSZ_INS_CLY = 357;
  SYSZ_INS_CPSDR = 358;
  SYSZ_INS_CR = 359;
  SYSZ_INS_CRL = 360;
  SYSZ_INS_CS = 361;
  SYSZ_INS_CSG = 362;
  SYSZ_INS_CSY = 363;
  SYSZ_INS_CXBR = 364;
  SYSZ_INS_CXFBR = 365;
  SYSZ_INS_CXGBR = 366;
  SYSZ_INS_CXLFBR = 367;
  SYSZ_INS_CXLGBR = 368;
  SYSZ_INS_CY = 369;
  SYSZ_INS_DDB = 370;
  SYSZ_INS_DDBR = 371;
  SYSZ_INS_DEB = 372;
  SYSZ_INS_DEBR = 373;
  SYSZ_INS_DL = 374;
  SYSZ_INS_DLG = 375;
  SYSZ_INS_DLGR = 376;
  SYSZ_INS_DLR = 377;
  SYSZ_INS_DSG = 378;
  SYSZ_INS_DSGF = 379;
  SYSZ_INS_DSGFR = 380;
  SYSZ_INS_DSGR = 381;
  SYSZ_INS_DXBR = 382;
  SYSZ_INS_EAR = 383;
  SYSZ_INS_FIDBR = 384;
  SYSZ_INS_FIDBRA = 385;
  SYSZ_INS_FIEBR = 386;
  SYSZ_INS_FIEBRA = 387;
  SYSZ_INS_FIXBR = 388;
  SYSZ_INS_FIXBRA = 389;
  SYSZ_INS_FLOGR = 390;
  SYSZ_INS_IC = 391;
  SYSZ_INS_ICY = 392;
  SYSZ_INS_IIHF = 393;
  SYSZ_INS_IIHH = 394;
  SYSZ_INS_IIHL = 395;
  SYSZ_INS_IILF = 396;
  SYSZ_INS_IILH = 397;
  SYSZ_INS_IILL = 398;
  SYSZ_INS_IPM = 399;
  SYSZ_INS_L = 400;
  SYSZ_INS_LA = 401;
  SYSZ_INS_LAA = 402;
  SYSZ_INS_LAAG = 403;
  SYSZ_INS_LAAL = 404;
  SYSZ_INS_LAALG = 405;
  SYSZ_INS_LAN = 406;
  SYSZ_INS_LANG = 407;
  SYSZ_INS_LAO = 408;
  SYSZ_INS_LAOG = 409;
  SYSZ_INS_LARL = 410;
  SYSZ_INS_LAX = 411;
  SYSZ_INS_LAXG = 412;
  SYSZ_INS_LAY = 413;
  SYSZ_INS_LB = 414;
  SYSZ_INS_LBH = 415;
  SYSZ_INS_LBR = 416;
  SYSZ_INS_LCDBR = 417;
  SYSZ_INS_LCEBR = 418;
  SYSZ_INS_LCGFR = 419;
  SYSZ_INS_LCGR = 420;
  SYSZ_INS_LCR = 421;
  SYSZ_INS_LCXBR = 422;
  SYSZ_INS_LD = 423;
  SYSZ_INS_LDEB = 424;
  SYSZ_INS_LDEBR = 425;
  SYSZ_INS_LDGR = 426;
  SYSZ_INS_LDR = 427;
  SYSZ_INS_LDXBR = 428;
  SYSZ_INS_LDXBRA = 429;
  SYSZ_INS_LDY = 430;
  SYSZ_INS_LE = 431;
  SYSZ_INS_LEDBR = 432;
  SYSZ_INS_LEDBRA = 433;
  SYSZ_INS_LER = 434;
  SYSZ_INS_LEXBR = 435;
  SYSZ_INS_LEXBRA = 436;
  SYSZ_INS_LEY = 437;
  SYSZ_INS_LFH = 438;
  SYSZ_INS_LG = 439;
  SYSZ_INS_LGB = 440;
  SYSZ_INS_LGBR = 441;
  SYSZ_INS_LGDR = 442;
  SYSZ_INS_LGF = 443;
  SYSZ_INS_LGFI = 444;
  SYSZ_INS_LGFR = 445;
  SYSZ_INS_LGFRL = 446;
  SYSZ_INS_LGH = 447;
  SYSZ_INS_LGHI = 448;
  SYSZ_INS_LGHR = 449;
  SYSZ_INS_LGHRL = 450;
  SYSZ_INS_LGR = 451;
  SYSZ_INS_LGRL = 452;
  SYSZ_INS_LH = 453;
  SYSZ_INS_LHH = 454;
  SYSZ_INS_LHI = 455;
  SYSZ_INS_LHR = 456;
  SYSZ_INS_LHRL = 457;
  SYSZ_INS_LHY = 458;
  SYSZ_INS_LLC = 459;
  SYSZ_INS_LLCH = 460;
  SYSZ_INS_LLCR = 461;
  SYSZ_INS_LLGC = 462;
  SYSZ_INS_LLGCR = 463;
  SYSZ_INS_LLGF = 464;
  SYSZ_INS_LLGFR = 465;
  SYSZ_INS_LLGFRL = 466;
  SYSZ_INS_LLGH = 467;
  SYSZ_INS_LLGHR = 468;
  SYSZ_INS_LLGHRL = 469;
  SYSZ_INS_LLH = 470;
  SYSZ_INS_LLHH = 471;
  SYSZ_INS_LLHR = 472;
  SYSZ_INS_LLHRL = 473;
  SYSZ_INS_LLIHF = 474;
  SYSZ_INS_LLIHH = 475;
  SYSZ_INS_LLIHL = 476;
  SYSZ_INS_LLILF = 477;
  SYSZ_INS_LLILH = 478;
  SYSZ_INS_LLILL = 479;
  SYSZ_INS_LMG = 480;
  SYSZ_INS_LNDBR = 481;
  SYSZ_INS_LNEBR = 482;
  SYSZ_INS_LNGFR = 483;
  SYSZ_INS_LNGR = 484;
  SYSZ_INS_LNR = 485;
  SYSZ_INS_LNXBR = 486;
  SYSZ_INS_LPDBR = 487;
  SYSZ_INS_LPEBR = 488;
  SYSZ_INS_LPGFR = 489;
  SYSZ_INS_LPGR = 490;
  SYSZ_INS_LPR = 491;
  SYSZ_INS_LPXBR = 492;
  SYSZ_INS_LR = 493;
  SYSZ_INS_LRL = 494;
  SYSZ_INS_LRV = 495;
  SYSZ_INS_LRVG = 496;
  SYSZ_INS_LRVGR = 497;
  SYSZ_INS_LRVR = 498;
  SYSZ_INS_LT = 499;
  SYSZ_INS_LTDBR = 500;
  SYSZ_INS_LTEBR = 501;
  SYSZ_INS_LTG = 502;
  SYSZ_INS_LTGF = 503;
  SYSZ_INS_LTGFR = 504;
  SYSZ_INS_LTGR = 505;
  SYSZ_INS_LTR = 506;
  SYSZ_INS_LTXBR = 507;
  SYSZ_INS_LXDB = 508;
  SYSZ_INS_LXDBR = 509;
  SYSZ_INS_LXEB = 510;
  SYSZ_INS_LXEBR = 511;
  SYSZ_INS_LXR = 512;
  SYSZ_INS_LY = 513;
  SYSZ_INS_LZDR = 514;
  SYSZ_INS_LZER = 515;
  SYSZ_INS_LZXR = 516;
  SYSZ_INS_MADB = 517;
  SYSZ_INS_MADBR = 518;
  SYSZ_INS_MAEB = 519;
  SYSZ_INS_MAEBR = 520;
  SYSZ_INS_MDB = 521;
  SYSZ_INS_MDBR = 522;
  SYSZ_INS_MDEB = 523;
  SYSZ_INS_MDEBR = 524;
  SYSZ_INS_MEEB = 525;
  SYSZ_INS_MEEBR = 526;
  SYSZ_INS_MGHI = 527;
  SYSZ_INS_MH = 528;
  SYSZ_INS_MHI = 529;
  SYSZ_INS_MHY = 530;
  SYSZ_INS_MLG = 531;
  SYSZ_INS_MLGR = 532;
  SYSZ_INS_MS = 533;
  SYSZ_INS_MSDB = 534;
  SYSZ_INS_MSDBR = 535;
  SYSZ_INS_MSEB = 536;
  SYSZ_INS_MSEBR = 537;
  SYSZ_INS_MSFI = 538;
  SYSZ_INS_MSG = 539;
  SYSZ_INS_MSGF = 540;
  SYSZ_INS_MSGFI = 541;
  SYSZ_INS_MSGFR = 542;
  SYSZ_INS_MSGR = 543;
  SYSZ_INS_MSR = 544;
  SYSZ_INS_MSY = 545;
  SYSZ_INS_MVC = 546;
  SYSZ_INS_MVGHI = 547;
  SYSZ_INS_MVHHI = 548;
  SYSZ_INS_MVHI = 549;
  SYSZ_INS_MVI = 550;
  SYSZ_INS_MVIY = 551;
  SYSZ_INS_MVST = 552;
  SYSZ_INS_MXBR = 553;
  SYSZ_INS_MXDB = 554;
  SYSZ_INS_MXDBR = 555;
  SYSZ_INS_N = 556;
  SYSZ_INS_NC = 557;
  SYSZ_INS_NG = 558;
  SYSZ_INS_NGR = 559;
  SYSZ_INS_NGRK = 560;
  SYSZ_INS_NI = 561;
  SYSZ_INS_NIHF = 562;
  SYSZ_INS_NIHH = 563;
  SYSZ_INS_NIHL = 564;
  SYSZ_INS_NILF = 565;
  SYSZ_INS_NILH = 566;
  SYSZ_INS_NILL = 567;
  SYSZ_INS_NIY = 568;
  SYSZ_INS_NR = 569;
  SYSZ_INS_NRK = 570;
  SYSZ_INS_NY = 571;
  SYSZ_INS_O = 572;
  SYSZ_INS_OC = 573;
  SYSZ_INS_OG = 574;
  SYSZ_INS_OGR = 575;
  SYSZ_INS_OGRK = 576;
  SYSZ_INS_OI = 577;
  SYSZ_INS_OIHF = 578;
  SYSZ_INS_OIHH = 579;
  SYSZ_INS_OIHL = 580;
  SYSZ_INS_OILF = 581;
  SYSZ_INS_OILH = 582;
  SYSZ_INS_OILL = 583;
  SYSZ_INS_OIY = 584;
  SYSZ_INS_OR = 585;
  SYSZ_INS_ORK = 586;
  SYSZ_INS_OY = 587;
  SYSZ_INS_PFD = 588;
  SYSZ_INS_PFDRL = 589;
  SYSZ_INS_RISBG = 590;
  SYSZ_INS_RISBHG = 591;
  SYSZ_INS_RISBLG = 592;
  SYSZ_INS_RLL = 593;
  SYSZ_INS_RLLG = 594;
  SYSZ_INS_RNSBG = 595;
  SYSZ_INS_ROSBG = 596;
  SYSZ_INS_RXSBG = 597;
  SYSZ_INS_S = 598;
  SYSZ_INS_SDB = 599;
  SYSZ_INS_SDBR = 600;
  SYSZ_INS_SEB = 601;
  SYSZ_INS_SEBR = 602;
  SYSZ_INS_SG = 603;
  SYSZ_INS_SGF = 604;
  SYSZ_INS_SGFR = 605;
  SYSZ_INS_SGR = 606;
  SYSZ_INS_SGRK = 607;
  SYSZ_INS_SH = 608;
  SYSZ_INS_SHY = 609;
  SYSZ_INS_SL = 610;
  SYSZ_INS_SLB = 611;
  SYSZ_INS_SLBG = 612;
  SYSZ_INS_SLBR = 613;
  SYSZ_INS_SLFI = 614;
  SYSZ_INS_SLG = 615;
  SYSZ_INS_SLBGR = 616;
  SYSZ_INS_SLGF = 617;
  SYSZ_INS_SLGFI = 618;
  SYSZ_INS_SLGFR = 619;
  SYSZ_INS_SLGR = 620;
  SYSZ_INS_SLGRK = 621;
  SYSZ_INS_SLL = 622;
  SYSZ_INS_SLLG = 623;
  SYSZ_INS_SLLK = 624;
  SYSZ_INS_SLR = 625;
  SYSZ_INS_SLRK = 626;
  SYSZ_INS_SLY = 627;
  SYSZ_INS_SQDB = 628;
  SYSZ_INS_SQDBR = 629;
  SYSZ_INS_SQEB = 630;
  SYSZ_INS_SQEBR = 631;
  SYSZ_INS_SQXBR = 632;
  SYSZ_INS_SR = 633;
  SYSZ_INS_SRA = 634;
  SYSZ_INS_SRAG = 635;
  SYSZ_INS_SRAK = 636;
  SYSZ_INS_SRK = 637;
  SYSZ_INS_SRL = 638;
  SYSZ_INS_SRLG = 639;
  SYSZ_INS_SRLK = 640;
  SYSZ_INS_SRST = 641;
  SYSZ_INS_ST = 642;
  SYSZ_INS_STC = 643;
  SYSZ_INS_STCH = 644;
  SYSZ_INS_STCY = 645;
  SYSZ_INS_STD = 646;
  SYSZ_INS_STDY = 647;
  SYSZ_INS_STE = 648;
  SYSZ_INS_STEY = 649;
  SYSZ_INS_STFH = 650;
  SYSZ_INS_STG = 651;
  SYSZ_INS_STGRL = 652;
  SYSZ_INS_STH = 653;
  SYSZ_INS_STHH = 654;
  SYSZ_INS_STHRL = 655;
  SYSZ_INS_STHY = 656;
  SYSZ_INS_STMG = 657;
  SYSZ_INS_STRL = 658;
  SYSZ_INS_STRV = 659;
  SYSZ_INS_STRVG = 660;
  SYSZ_INS_STY = 661;
  SYSZ_INS_SXBR = 662;
  SYSZ_INS_SY = 663;
  SYSZ_INS_TM = 664;
  SYSZ_INS_TMHH = 665;
  SYSZ_INS_TMHL = 666;
  SYSZ_INS_TMLH = 667;
  SYSZ_INS_TMLL = 668;
  SYSZ_INS_TMY = 669;
  SYSZ_INS_X = 670;
  SYSZ_INS_XC = 671;
  SYSZ_INS_XG = 672;
  SYSZ_INS_XGR = 673;
  SYSZ_INS_XGRK = 674;
  SYSZ_INS_XI = 675;
  SYSZ_INS_XIHF = 676;
  SYSZ_INS_XILF = 677;
  SYSZ_INS_XIY = 678;
  SYSZ_INS_XR = 679;
  SYSZ_INS_XRK = 680;
  SYSZ_INS_XY = 681;
  SYSZ_INS_ENDING = 682;

/// Group of SystemZ instructions
type
  sysz_insn_group = Integer;
  Psysz_insn_group = ^sysz_insn_group;

const
  /// = CS_GRP_INVALID
  SYSZ_GRP_INVALID = 0;
  /// = CS_GRP_JUMP
  SYSZ_GRP_JUMP = 1;
  SYSZ_GRP_DISTINCTOPS = 128;
  SYSZ_GRP_FPEXTENSION = 129;
  SYSZ_GRP_HIGHWORD = 130;
  SYSZ_GRP_INTERLOCKEDACCESS1 = 131;
  SYSZ_GRP_LOADSTOREONCOND = 132;
  SYSZ_GRP_ENDING = 133;

type
  // Forward declarations
  Psysz_op_mem = ^sysz_op_mem;
  Pcs_sysz_op = ^cs_sysz_op;
  Pcs_sysz = ^cs_sysz;

  /// Instruction's operand referring to memory
  /// This is associated with SYSZ_OP_MEM operand type above
  sysz_op_mem = record
    /// base register, can be safely interpreted as
    				///< a value of type `sysz_reg`, but it is only
    				///< one byte wide
    base: UInt8;
    /// index register, same conditions apply here
    index: UInt8;
    /// BDLAddr operand
    length: UInt64;
    /// displacement/offset value
    disp: Int64;
  end;

  P_anonymous_type_1 = ^_anonymous_type_1;
  _anonymous_type_1 = record
    case Integer of
      0: (/// register value for REG operand
    reg: sysz_reg);
      1: (/// immediate value for IMM operand
    imm: Int64);
      2: (/// base/disp value for MEM operand
    mem: sysz_op_mem);
  end;

  /// Instruction operand
  cs_sysz_op = record
    /// operand type
    &type: sysz_op_type;
    f2: _anonymous_type_1;
  end;

  cs_sysz = record
    /// Code condition
    cc: sysz_cc;
    /// Number of operands of this instruction,
    	/// or 0 when instruction has no operand.
    op_count: UInt8;
    /// operands for this instruction.
    operands: array [0..5] of cs_sysz_op;
  end;

implementation

end.