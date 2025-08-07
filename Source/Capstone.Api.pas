{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Api Header                       }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: capstone.h                                }
{    License: Mozilla Public License 2.0                }
{                                                       }
{  Copyright (c) 1998-2025 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone.Api;

{$I Capstone.inc}

{.$DEFINE CS_STATICLINK}

{$IFDEF CS_STATICLINK}
  {$IFDEF FPC}
    {$MESSAGE ERROR 'staticlink not supported'}
  {$ENDIF}
  {$IFNDEF MSWINDOWS}
    {$MESSAGE ERROR 'staticlink not supported'}
  {$ENDIF}
  {$IFNDEF CPUX64}
    {$DEFINE CS_USE_UNDERSCORE}
  {$ENDIF}
{$ELSE}
  {$DEFINE CS_USE_EXTNAME}
{$ENDIF}

interface

uses
  Capstone.Arm, Capstone.Arm64, Capstone.Bpf, Capstone.Evm, Capstone.M680X, Capstone.M68K,
  Capstone.Mips, Capstone.Mos65xx, Capstone.Ppc, Capstone.RiscV, Capstone.SH, Capstone.Sparc,
  Capstone.SystemZ, Capstone.Tms320c64x, Capstone.TriCore, Capstone.Wasm, Capstone.X86,
  Capstone.XCore;

const
{$IFDEF MSWINDOWS}
  capstone = 'capstone.dll';
{$ENDIF}
{$IFDEF LINUX}
  capstone = 'libcapstone.so';
{$ENDIF}
{$IFDEF MACOS}
  {$IF DEFINED(IOS) or DEFINED(MACOS64)}
    capstone = '/usr/lib/libcapstone.dylib';
  {$ELSE}
    capstone = 'libcapstone.dylib';
  {$IFEND}
{$ENDIF}
{$IF DEFINED(FPC) and DEFINED(DARWIN)}
  capstone = 'libcapstone.dylib';
  {$LINKLIB libcapstone}
{$IFEND}
{$IFDEF ANDROID}
  capstone = 'libcapstone.so';
{$ENDIF ANDROID}

{$IFDEF CS_USE_UNDERSCORE}
  _PU = '_';
{$ELSE}
  _PU = '';
{$ENDIF}

const
  // Capstone API version
  CS_API_MAJOR = 5;
  CS_API_MINOR = 0;

  // Version for bleeding edge code of the Github's "next" branch.
  // Use this if you want the absolutely latest development code.
  // This version number will be bumped up whenever we have a new major change.
  CS_NEXT_VERSION = 5;

  // Capstone package version
  CS_VERSION_MAJOR = CS_API_MAJOR;
  CS_VERSION_MINOR = CS_API_MINOR;
  CS_VERSION_EXTRA = 6;

  /// Maximum size of an instruction mnemonic string.
  CS_MNEMONIC_SIZE = 32;

/// Handle using with all API
type
  csh = NativeUInt;

/// Architecture type
type
  cs_arch = Integer;

const
  /// ARM architecture (including Thumb, Thumb-2)
  CS_ARCH_ARM = 0;
  /// ARM-64, also called AArch64
  CS_ARCH_ARM64 = 1;
  /// Mips architecture
  CS_ARCH_MIPS = 2;
  /// X86 architecture (including x86 & x86-64)
  CS_ARCH_X86 = 3;
  /// PowerPC architecture
  CS_ARCH_PPC = 4;
  /// Sparc architecture
  CS_ARCH_SPARC = 5;
  /// SystemZ architecture
  CS_ARCH_SYSZ = 6;
  /// XCore architecture
  CS_ARCH_XCORE = 7;
  /// 68K architecture
  CS_ARCH_M68K = 8;
  /// TMS320C64x architecture
  CS_ARCH_TMS320C64X = 9;
  /// 680X architecture
  CS_ARCH_M680X = 10;
  /// Ethereum architecture
  CS_ARCH_EVM = 11;
  /// MOS65XX architecture (including MOS6502)
  CS_ARCH_MOS65XX = 12;
  /// WebAssembly architecture
  CS_ARCH_WASM = 13;
  /// Berkeley Packet Filter architecture (including eBPF)
  CS_ARCH_BPF = 14;
  /// RISCV architecture
  CS_ARCH_RISCV = 15;
  /// SH architecture
  CS_ARCH_SH = 16;
  /// TriCore architecture
  CS_ARCH_TRICORE = 17;
  /// Max architecture
  CS_ARCH_MAX = 18;
  /// All architectures - for cs_support()
  CS_ARCH_ALL = $FFFF;

const
  // Support value to verify diet mode of the engine.
  // If cs_support(CS_SUPPORT_DIET) return True, the engine was compiled
  // in diet mode.
  CS_SUPPORT_DIET = (CS_ARCH_ALL + 1);

  // Support value to verify X86 reduce mode of the engine.
  // If cs_support(CS_SUPPORT_X86_REDUCE) return True, the engine was compiled
  // in X86 reduce mode.
  CS_SUPPORT_X86_REDUCE = (CS_ARCH_ALL + 2);

/// Mode type
type
  cs_mode = Integer;

const
  /// little-endian mode (default mode)
  CS_MODE_LITTLE_ENDIAN = 0;
  /// 32-bit ARM
  CS_MODE_ARM = CS_MODE_LITTLE_ENDIAN;
  /// 16-bit mode (X86)
  CS_MODE_16 = 1 shl 1;
  /// 32-bit mode (X86)
  CS_MODE_32 = 1 shl 2;
  /// 64-bit mode (X86, PPC)
  CS_MODE_64 = 1 shl 3;
  /// ARM's Thumb mode, including Thumb-2
  CS_MODE_THUMB = 1 shl 4;
  /// ARM's Cortex-M series
  CS_MODE_MCLASS = 1 shl 5;
  /// ARMv8 A32 encodings for ARM
  CS_MODE_V8 = 1 shl 6;
  /// MicroMips mode (MIPS)
  CS_MODE_MICRO = 1 shl 4;
  /// Mips III ISA
  CS_MODE_MIPS3 = 1 shl 5;
  /// Mips32r6 ISA
  CS_MODE_MIPS32R6 = 1 shl 6;
  /// Mips II ISA
  CS_MODE_MIPS2 = 1 shl 7;
  /// SparcV9 mode (Sparc)
  CS_MODE_V9 = 1 shl 4;
  /// Quad Processing eXtensions mode (PPC)
  CS_MODE_QPX = 1 shl 4;
  /// Signal Processing Engine mode (PPC)
  CS_MODE_SPE = 1 shl 5;
  /// Book-E mode (PPC)
  CS_MODE_BOOKE = 1 shl 6;
  /// Paired-singles mode (PPC)
  CS_MODE_PS = 1 shl 7;
  /// M68K 68000 mode
  CS_MODE_M68K_000 = 1 shl 1;
  /// M68K 68010 mode
  CS_MODE_M68K_010 = 1 shl 2;
  /// M68K 68020 mode
  CS_MODE_M68K_020 = 1 shl 3;
  /// M68K 68030 mode
  CS_MODE_M68K_030 = 1 shl 4;
  /// M68K 68040 mode
  CS_MODE_M68K_040 = 1 shl 5;
  /// M68K 68060 mode
  CS_MODE_M68K_060 = 1 shl 6;
  /// big-endian mode
  CS_MODE_BIG_ENDIAN = Int32(1) shl 31;
  /// Mips32 ISA (Mips)
  CS_MODE_MIPS32 = CS_MODE_32;
  /// Mips64 ISA (Mips)
  CS_MODE_MIPS64 = CS_MODE_64;
  /// M680X Hitachi 6301,6303 mode
  CS_MODE_M680X_6301 = 1 shl 1;
  /// M680X Hitachi 6309 mode
  CS_MODE_M680X_6309 = 1 shl 2;
  /// M680X Motorola 6800,6802 mode
  CS_MODE_M680X_6800 = 1 shl 3;
  /// M680X Motorola 6801,6803 mode
  CS_MODE_M680X_6801 = 1 shl 4;
  /// M680X Motorola/Freescale 6805 mode
  CS_MODE_M680X_6805 = 1 shl 5;
  /// M680X Motorola/Freescale/NXP 68HC08 mode
  CS_MODE_M680X_6808 = 1 shl 6;
  /// M680X Motorola 6809 mode
  CS_MODE_M680X_6809 = 1 shl 7;
  /// M680X Motorola/Freescale/NXP 68HC11 mode
  CS_MODE_M680X_6811 = 1 shl 8;
  /// M680X Motorola/Freescale/NXP CPU12
  /// used on M68HC12/HCS12
  CS_MODE_M680X_CPU12 = 1 shl 9;
  /// M680X Freescale/NXP HCS08 mode
  CS_MODE_M680X_HCS08 = 1 shl 10;
  /// Classic BPF mode (default)
  CS_MODE_BPF_CLASSIC = 0;
  /// Extended BPF mode
  CS_MODE_BPF_EXTENDED = 1 shl 0;
  /// RISCV RV32G
  CS_MODE_RISCV32 = 1 shl 0;
  /// RISCV RV64G
  CS_MODE_RISCV64 = 1 shl 1;
  /// RISCV compressed instructure mode
  CS_MODE_RISCVC = 1 shl 2;
  /// MOS65XXX MOS 6502
  CS_MODE_MOS65XX_6502 = 1 shl 1;
  /// MOS65XXX WDC 65c02
  CS_MODE_MOS65XX_65C02 = 1 shl 2;
  /// MOS65XXX WDC W65c02
  CS_MODE_MOS65XX_W65C02 = 1 shl 3;
  /// MOS65XXX WDC 65816, 8-bit m/x
  CS_MODE_MOS65XX_65816 = 1 shl 4;
  /// MOS65XXX WDC 65816, 16-bit m, 8-bit x
  CS_MODE_MOS65XX_65816_LONG_M = 1 shl 5;
  /// MOS65XXX WDC 65816, 8-bit m, 16-bit x
  CS_MODE_MOS65XX_65816_LONG_X = 1 shl 6;
  CS_MODE_MOS65XX_65816_LONG_MX = CS_MODE_MOS65XX_65816_LONG_M or CS_MODE_MOS65XX_65816_LONG_X;
  /// SH2
  CS_MODE_SH2 = 1 shl 1;
  /// SH2A
  CS_MODE_SH2A = 1 shl 2;
  /// SH3
  CS_MODE_SH3 = 1 shl 3;
  /// SH4
  CS_MODE_SH4 = 1 shl 4;
  /// SH4A
  CS_MODE_SH4A = 1 shl 5;
  /// w/ FPU
  CS_MODE_SHFPU = 1 shl 6;
  /// w/ DSP
  CS_MODE_SHDSP = 1 shl 7;
  /// Tricore 1.1
  CS_MODE_TRICORE_110 = 1 shl 1;
  /// Tricore 1.2
  CS_MODE_TRICORE_120 = 1 shl 2;
  /// Tricore 1.3
  CS_MODE_TRICORE_130 = 1 shl 3;
  /// Tricore 1.3.1
  CS_MODE_TRICORE_131 = 1 shl 4;
  /// Tricore 1.6
  CS_MODE_TRICORE_160 = 1 shl 5;
  /// Tricore 1.6.1
  CS_MODE_TRICORE_161 = 1 shl 6;
  /// Tricore 1.6.2
  CS_MODE_TRICORE_162 = 1 shl 7;

type
  /// User-defined dynamic memory related functions: malloc/calloc/realloc/free/vsnprintf()
  cs_malloc_t = function(size: NativeUInt): Pointer; cdecl;
  cs_calloc_t = function(nmemb: NativeUInt; size: NativeUInt): Pointer; cdecl;
  cs_realloc_t = function(ptr: Pointer; size: NativeUInt): Pointer; cdecl;
  cs_free_t = procedure(ptr: Pointer); cdecl;
  cs_vsnprintf_t = function(str: PAnsiChar; size: NativeUInt; const format: PAnsiChar; ap: Pointer): Integer; cdecl;

  /// User-defined dynamic memory related functions: malloc/calloc/realloc/free/vsnprintf()
  /// By default, Capstone uses system's malloc(), calloc(), realloc(), free() & vsnprintf().
  cs_opt_mem = record
    malloc: cs_malloc_t;
    calloc: cs_calloc_t;
    realloc: cs_realloc_t;
    free: cs_free_t;
    vsnprintf: cs_vsnprintf_t;
  end;

  /// Customize mnemonic for instructions with alternative name.
  /// To reset existing customized instruction to its default mnemonic,
  /// call cs_option(CS_OPT_MNEMONIC) again with the same @id and NULL value
  /// for @mnemonic.
  cs_opt_mnem = record
    /// ID of instruction to be customized.
    id: Cardinal;
    /// Customized instruction mnemonic.
    mnemonic: PAnsiChar;
  end;

/// Runtime option for the disassembled engine
type
  cs_opt_type = Integer;

const
  /// No option specified
  CS_OPT_INVALID = 0;
  /// Assembly output syntax
  CS_OPT_SYNTAX = 1;
  /// Break down instruction structure into details
  CS_OPT_DETAIL = 2;
  /// Change engine's mode at run-time
  CS_OPT_MODE = 3;
  /// User-defined dynamic memory related functions
  CS_OPT_MEM_ = 4;
  /// Skip data when disassembling. Then engine is in SKIPDATA mode.
  CS_OPT_SKIPDATA_ = 5;
  /// Setup user-defined function for SKIPDATA option
  CS_OPT_SKIPDATA_SETUP = 6;
  /// Customize instruction mnemonic
  CS_OPT_MNEMONIC = 7;
  /// print immediate operands in unsigned form
  CS_OPT_UNSIGNED = 8;
  /// ARM, prints branch immediates without offset.
  CS_OPT_NO_BRANCH_OFFSET = 9;

/// Runtime option value (associated with option type above)
type
  cs_opt_value = Integer;

const
  /// Turn OFF an option - default for CS_OPT_DETAIL, CS_OPT_SKIPDATA, CS_OPT_UNSIGNED.
  CS_OPT_OFF = 0;
  /// Turn ON an option (CS_OPT_DETAIL, CS_OPT_SKIPDATA).
  CS_OPT_ON = 3;
  /// Default asm syntax (CS_OPT_SYNTAX).
  CS_OPT_SYNTAX_DEFAULT = 0;
  /// X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
  CS_OPT_SYNTAX_INTEL = 1;
  /// X86 ATT asm syntax (CS_OPT_SYNTAX).
  CS_OPT_SYNTAX_ATT = 2;
  /// Prints register name with only number (CS_OPT_SYNTAX)
  CS_OPT_SYNTAX_NOREGNAME = 3;
  /// X86 Intel Masm syntax (CS_OPT_SYNTAX).
  CS_OPT_SYNTAX_MASM = 4;
  /// MOS65XX use $ as hex prefix
  CS_OPT_SYNTAX_MOTOROLA = 5;

/// Common instruction operand types - to be consistent across all architectures.
type
  cs_op_type = Integer;

const
  /// uninitialized/invalid operand.
  CS_OP_INVALID = 0;
  /// Register operand.
  CS_OP_REG = 1;
  /// Immediate operand.
  CS_OP_IMM = 2;
  /// Memory operand. Can be ORed with another operand type.
  CS_OP_MEM = 3;
  /// Floating-Point operand.
  CS_OP_FP = 4;

/// Common instruction operand access types - to be consistent across all architectures.
/// It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
type
  cs_ac_type = Integer;

const
  /// Uninitialized/invalid access type.
  CS_AC_INVALID = 0;
  /// Operand read from memory or register.
  CS_AC_READ = 1;
  /// Operand write to memory or register.
  CS_AC_WRITE = 2;

/// Common instruction groups - to be consistent across all architectures.
type
  cs_group_type = Integer;

const
  /// uninitialized/invalid group.
  CS_GRP_INVALID = 0;
  /// all jump instructions (conditional+direct+indirect jumps)
  CS_GRP_JUMP = 1;
  /// all call instructions
  CS_GRP_CALL = 2;
  /// all return instructions
  CS_GRP_RET = 3;
  /// all interrupt instructions (int+syscall)
  CS_GRP_INT = 4;
  /// all interrupt return instructions
  CS_GRP_IRET = 5;
  /// all privileged instructions
  CS_GRP_PRIVILEGE = 6;
  /// all relative branching instructions
  CS_GRP_BRANCH_RELATIVE = 7;

type
  (**
   User-defined callback function for SKIPDATA option.
   See tests/test_skipdata.c for sample code demonstrating this API.

   @code: the input buffer containing code to be disassembled.
          This is the same buffer passed to cs_disasm().
   @code_size: size (in bytes) of the above @code buffer.
   @offset: the position of the currently-examining byte in the input
        buffer @code mentioned above.
   @user_data: user-data passed to cs_option() via @user_data field in
        cs_opt_skipdata struct below.

   @return: return number of bytes to skip, or 0 to immediately stop disassembling.
   *)
  cs_skipdata_cb_t = function(const code: PByte; code_size: NativeUInt; offset: NativeUInt; user_data: Pointer): NativeUInt; cdecl;

  /// User-customized setup for SKIPDATA option
  cs_opt_skipdata = record
    /// Capstone considers data to skip as special "instructions".
    /// User can specify the string for this instruction's "mnemonic" here.
    /// By default (if @mnemonic is NULL), Capstone use ".byte".
    mnemonic: PAnsiChar;
    /// User-defined callback function to be called when Capstone hits data.
    /// If the returned value from this callback is positive (>0), Capstone
    /// will skip exactly that number of bytes & continue. Otherwise, if
    /// the callback returns 0, Capstone stops disassembling and returns
    /// immediately from cs_disasm()
    /// NOTE: if this callback pointer is NULL, Capstone would skip a number
    /// of bytes depending on architectures, as following:
    /// Arm:     2 bytes (Thumb mode) or 4 bytes.
    /// Arm64:   4 bytes.
    /// Mips:    4 bytes.
    /// M680x:   1 byte.
    /// PowerPC: 4 bytes.
    /// Sparc:   4 bytes.
    /// SystemZ: 2 bytes.
    /// X86:     1 bytes.
    /// XCore:   2 bytes.
    /// EVM:     1 bytes.
    /// RISCV:   4 bytes.
    /// WASM:    1 bytes.
    /// MOS65XX: 1 bytes.
    /// BPF:     8 bytes.
    /// TriCore: 2 bytes.
    callback: cs_skipdata_cb_t;
    /// User-defined data to be passed to @callback function pointer.
    user_data: Pointer;
  end;

const
  MAX_IMPL_W_REGS = 20;
  MAX_IMPL_R_REGS = 20;
  MAX_NUM_GROUPS = 8;

type
  /// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
  /// Initialized as memset(., 0, offsetof(cs_detail, ARCH)+sizeof(cs_ARCH))
  /// by ARCH_getInstruction in arch/ARCH/ARCHDisassembler.c
  /// if cs_detail changes, in particular if a field is added after the union,
  /// then update arch/ARCH/ARCHDisassembler.c accordingly
  cs_detail = record
    /// list of implicit registers read by this insn
    regs_read: array[0..MAX_IMPL_R_REGS-1] of UInt16;
    /// number of implicit registers read by this insn
    regs_read_count: UInt8;
    /// list of implicit registers modified by this insn
    regs_write: array[0..MAX_IMPL_W_REGS-1] of UInt16;
    /// number of implicit registers modified by this insn
    regs_write_count: UInt8;
    /// list of group this instruction belong to
    groups: array[0..MAX_NUM_GROUPS-1] of UInt8;
    /// number of groups this insn belongs to
    groups_count: UInt8;
    /// Instruction has writeback operands.
    writeback: Boolean;
    /// Architecture-specific instruction info
    case Byte of
      /// X86 architecture, including 16-bit, 32-bit & 64-bit mode
      0: (x86: cs_x86);
      /// ARM64 architecture (aka AArch64)
      1: (arm64: cs_arm64);
      /// ARM architecture (including Thumb/Thumb2)
      2: (arm: cs_arm);
      /// M68K architecture
      3: (m68k: cs_m68k);
      /// MIPS architecture
      4: (mips: cs_mips);
      /// PowerPC architecture
      5: (ppc: cs_ppc);
      /// Sparc architecture
      6: (sparc: cs_sparc);
      /// SystemZ architecture
      7: (sysz: cs_sysz);
      /// XCore architecture
      8: (xcore: cs_xcore);
      /// TMS320C64x architecture
      9: (tms320c64x: cs_tms320c64x);
      /// M680X architecture
     10: (m680x: cs_m680x);
      /// Ethereum architecture
     11: (evm: cs_evm);
      /// MOS65XX architecture (including MOS6502)
     12: (mos65xx: cs_mos65xx);
      /// Web Assembly architecture
     13: (wasm: cs_wasm);
      /// Berkeley Packet Filter architecture (including eBPF)
     14: (bpf: cs_bpf);
      /// RISCV architecture
     15: (riscv: cs_riscv);
      /// SH architecture
     16: (sh: cs_sh);
      /// TriCore architecture
     17: (tricore: cs_tricore);
  end;
  Pcs_detail = ^cs_detail;

  /// Detail information of disassembled instruction
  cs_insn = record
    /// Instruction ID (basically a numeric ID for the instruction mnemonic)
    /// Find the instruction id in the '[ARCH]_insn' enum in the header file
    /// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
    /// 'x86_insn' in x86.h for X86, etc...
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    /// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
    id: Cardinal;
    /// Address (EIP) of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    address: UInt64;
    /// Size of this instruction
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    size: UInt16;
    /// Machine bytes of this instruction, with number of bytes indicated by @size above
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    bytes: array[0..23] of UInt8;
    /// Ascii text of instruction mnemonic
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    mnemonic: array[0..CS_MNEMONIC_SIZE-1] of AnsiChar;
    /// Ascii text of instruction operands
    /// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
    op_str: array[0..159] of AnsiChar;
    /// Pointer to cs_detail.
    /// NOTE: detail pointer is only valid when both requirements below are met:
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    ///
    /// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
    ///     is not NULL, its content is still irrelevant.
    detail: Pcs_detail;
  end;
  Pcs_insn = ^cs_insn;

/// All type of errors encountered by Capstone API.
/// These are values returned by cs_errno()
type
  cs_err = Integer;

const
  /// No error: everything was fine
  CS_ERR_OK = 0;
  /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
  CS_ERR_MEM = 1;
  /// Unsupported architecture: cs_open()
  CS_ERR_ARCH = 2;
  /// Invalid handle: cs_op_count(), cs_op_index()
  CS_ERR_HANDLE = 3;
  /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
  CS_ERR_CSH = 4;
  /// Invalid/unsupported mode: cs_open()
  CS_ERR_MODE = 5;
  /// Invalid/unsupported option: cs_option()
  CS_ERR_OPTION = 6;
  /// Information is unavailable because detail option is OFF
  CS_ERR_DETAIL = 7;
  /// Dynamic memory management uninitialized (see CS_OPT_MEM)
  CS_ERR_MEMSETUP = 8;
  /// Unsupported version (bindings)
  CS_ERR_VERSION = 9;
  /// Access irrelevant data in "diet" engine
  CS_ERR_DIET = 10;
  /// Access irrelevant data for "data" instruction in SKIPDATA mode
  CS_ERR_SKIPDATA = 11;
  /// X86 AT&T syntax is unsupported (opt-out at compile time)
  CS_ERR_X86_ATT = 12;
  /// X86 Intel syntax is unsupported (opt-out at compile time)
  CS_ERR_X86_INTEL = 13;
  /// X86 Masm syntax is unsupported (opt-out at compile time)
  CS_ERR_X86_MASM = 14;

type
  /// Type of array to keep the list of registers
  cs_regs = array[0..63] of UInt16;

(**
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
 major & minor versions.
 NOTE: This returned value can be compared with version number made
 with macro CS_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
 *)
function cs_version(var major: Integer; var minor: Integer): Cardinal; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_version';

(**
 This API can be used to either ask for archs supported by this library,
 or check to see if the library was compile with 'diet' option (or called
 in 'diet' mode).

 To check if a particular arch is supported by this library, set @query to
 arch mode (CS_ARCH_* value).
 To verify if this library supports all the archs, use CS_ARCH_ALL.

 To check if this library is in 'diet' mode, set @query to CS_SUPPORT_DIET.

 @return True if this library supports the given arch, or in 'diet' mode.
 *)
function cs_support(query: Integer): Boolean; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_support';

(**
 Initialize CS handle: this must be done before any usage of CS.

 @arch: architecture type (CS_ARCH_* )
 @mode: hardware mode. This is combined of CS_MODE_*
 @handle: pointer to handle, which will be updated at return time

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
 *)
function cs_open(arch: cs_arch; mode: cs_mode; var handle: csh): cs_err; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_open';

(**
 Close CS handle: MUST do to release the handle when it is not used anymore.
 NOTE: this must be only called when there is no longer usage of Capstone,
 not even access to cs_insn array. The reason is the this API releases some
 cached memory, thus access to any Capstone API after cs_close() might crash
 your application.

 In fact,this API invalidate @handle by ZERO out its value (i.e *handle = 0).

 @handle: pointer to a handle returned by cs_open()

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
 *)
function cs_close(var handle: csh): cs_err; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_close';

(**
 Set option for disassembling engine at runtime

 @handle: handle returned by cs_open()
 @type: type of option to be set
 @value: option value corresponding with @type

 @return: CS_ERR_OK on success, or other value on failure.
 Refer to cs_err enum for detailed error.

 NOTE: in the case of CS_OPT_MEM, handle's value can be anything,
 so that cs_option(handle, CS_OPT_MEM, value) can (i.e must) be called
 even before cs_open()
 *)
function cs_option(handle: csh; type_: cs_opt_type; value: NativeUInt): cs_err; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_option';

(**
 Report the last error number when some API function fail.
 Like glibc's errno, cs_errno might not retain its old value once accessed.

 @handle: handle returned by cs_open()

 @return: error code of cs_err enum type (CS_ERR_*, see above)
 *)
function cs_errno(handle: csh): cs_err; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_errno';

(**
 Return a string describing given error code.

 @code: error code (see CS_ERR_* above)

 @return: returns a pointer to a string that describes the error code
passed in the argument @code
 *)
function cs_strerror(code: cs_err): PAnsiChar; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_strerror';

(**
 Disassemble binary code, given the code buffer, size, address and number
 of instructions to be decoded.
 This API dynamically allocate memory to contain disassembled instruction.
 Resulting instructions will be put into @*insn

 NOTE 1: this API will automatically determine memory needed to contain
 output disassembled instructions in @insn.

 NOTE 2: caller must free the allocated memory itself to avoid memory leaking.

 NOTE 3: for system with scarce memory to be dynamically allocated such as
 OS kernel or firmware, the API cs_disasm_iter() might be a better choice than
 cs_disasm(). The reason is that with cs_disasm(), based on limited available
 memory, we have to calculate in advance how many instructions to be disassembled,
 which complicates things. This is especially troublesome for the case @count=0,
 when cs_disasm() runs uncontrollably (until either end of input buffer, or
 when it encounters an invalid instruction).

 @handle: handle returned by cs_open()
 @code: buffer containing raw binary code to be disassembled.
 @code_size: size of the above code buffer.
 @address: address of the first instruction in given raw code buffer.
 @insn: array of instructions filled in by this API.
   NOTE: @insn will be allocated by this function, and should be freed
   with cs_free() API.
 @count: number of instructions to be disassembled, or 0 to get all of them

 @return: the number of successfully disassembled instructions,
 or 0 if this function failed to disassemble the given code

 On failure, call cs_errno() for error code.
 *)
function cs_disasm(handle: csh; const code: PByte; code_size: NativeUInt; address: UInt64; count: NativeUInt; var insn: Pcs_insn): NativeUInt; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_disasm';

(**
 Free memory allocated by cs_malloc() or cs_disasm() (argument @insn)

 @insn: pointer returned by @insn argument in cs_disasm() or cs_malloc()
 @count: number of cs_insn structures returned by cs_disasm(), or 1
     to free memory allocated by cs_malloc().
 *)
procedure cs_free(insn: Pcs_insn; count: NativeUInt); cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_free';

(**
 Allocate memory for 1 instruction to be used by cs_disasm_iter().

 @handle: handle returned by cs_open()

 NOTE: when no longer in use, you can reclaim the memory allocated for
 this instruction with cs_free(insn, 1)
 *)
function cs_malloc(handle: csh): Pcs_insn; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_malloc';

(**
 Fast API to disassemble binary code, given the code buffer, size, address
 and number of instructions to be decoded.
 This API puts the resulting instruction into a given cache in @insn.
 See tests/test_iter.c for sample code demonstrating this API.

 NOTE 1: this API will update @code, @size & @address to point to the next
 instruction in the input buffer. Therefore, it is convenient to use
 cs_disasm_iter() inside a loop to quickly iterate all the instructions.
 While decoding one instruction at a time can also be achieved with
 cs_disasm(count=1), some benchmarks shown that cs_disasm_iter() can be 30%
 faster on random input.

 NOTE 2: the cache in @insn can be created with cs_malloc() API.

 NOTE 3: for system with scarce memory to be dynamically allocated such as
 OS kernel or firmware, this API is recommended over cs_disasm(), which
 allocates memory based on the number of instructions to be disassembled.
 The reason is that with cs_disasm(), based on limited available memory,
 we have to calculate in advance how many instructions to be disassembled,
 which complicates things. This is especially troublesome for the case
 @count=0, when cs_disasm() runs uncontrollably (until either end of input
 buffer, or when it encounters an invalid instruction).

 @handle: handle returned by cs_open()
 @code: buffer containing raw binary code to be disassembled
 @size: size of above code
 @address: address of the first insn in given raw code buffer
 @insn: pointer to instruction to be filled in by this API.

 @return: true if this API successfully decode 1 instruction,
 or false otherwise.

 On failure, call cs_errno() for error code.
 *)
function cs_disasm_iter(handle: csh; var code: PByte; var size: NativeUInt; var address: UInt64; insn: Pcs_insn): Boolean; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_disasm_iter';

(**
 Return friendly name of register in a string.
 Find the instruction id from header file of corresponding architecture (arm.h for ARM,
 x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because engine does not
 store register name.

 @handle: handle returned by cs_open()
 @reg_id: register id

 @return: string name of the register, or NULL if @reg_id is invalid.
 *)
function cs_reg_name(handle: csh; reg_id: Cardinal): PAnsiChar; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_reg_name';

(**
 Return friendly name of an instruction in a string.
 Find the instruction id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 store instruction name.

 @handle: handle returned by cs_open()
 @insn_id: instruction id

 @return: string name of the instruction, or NULL if @insn_id is invalid.
 *)
function cs_insn_name(handle: csh; insn_id: Cardinal): PAnsiChar; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_insn_name';

(**
 Return friendly name of a group id (that an instruction can belong to)
 Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 store group name.

 @handle: handle returned by cs_open()
 @group_id: group id

 @return: string name of the group, or NULL if @group_id is invalid.
 *)
function cs_group_name(handle: csh; group_id: Cardinal): PAnsiChar; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_group_name';

(**
 Check if a disassembled instruction belong to a particular group.
 Find the group id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @group_id matches any member of insn->groups array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default).

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @groups array.

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @group_id: group that you want to check if this instruction belong to.

 @return: true if this instruction indeed belongs to the given group, or false otherwise.
 *)
function cs_insn_group(handle: csh; const insn: Pcs_insn; group_id: Cardinal): Boolean; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_insn_group';

(**
 Check if a disassembled instruction IMPLICITLY used a particular register.
 Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @reg_id matches any member of insn->regs_read array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @regs_read array.

 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @reg_id: register that you want to check if this instruction used it.

 @return: true if this instruction indeed implicitly used the given register, or false otherwise.
 *)
function cs_reg_read(handle: csh; const insn: Pcs_insn; reg_id: Cardinal): Boolean; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_reg_read';

(**
 Check if a disassembled instruction IMPLICITLY modified a particular register.
 Find the register id from header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)
 Internally, this simply verifies if @reg_id matches any member of insn->regs_write array.

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 WARN: when in 'diet' mode, this API is irrelevant because the engine does not
 update @regs_write array.

 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @reg_id: register that you want to check if this instruction modified it.

 @return: true if this instruction indeed implicitly modified the given register, or false otherwise.
 *)
function cs_reg_write(handle: csh; const insn: Pcs_insn; reg_id: Cardinal): Boolean; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_reg_write';

(**
 Count the number of operands of a given type.
 Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @op_type: Operand type to be found.

 @return: number of operands of given type @op_type in instruction @insn,
 or -1 on failure.
 *)
function cs_op_count(handle: csh; const insn: Pcs_insn; op_type: Cardinal): Integer; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_op_count';

(**
 Retrieve the position of operand of given type in <arch>.operands[] array.
 Later, the operand can be accessed using the returned position.
 Find the operand type in header file of corresponding architecture (arm.h for ARM, x86.h for X86, ...)

 NOTE: this API is only valid when detail option is ON (which is OFF by default)

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure received from cs_disasm() or cs_disasm_iter()
 @op_type: Operand type to be found.
 @position: position of the operand to be found. This must be in the range
[1, cs_op_count(handle, insn, op_type)]

 @return: index of operand of given type @op_type in <arch>.operands[] array
 in instruction @insn, or -1 on failure.
 *)
function cs_op_index(handle: csh; const insn: Pcs_insn; op_type: Cardinal; position: Cardinal): Integer; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_op_index';

(**
 Retrieve all the registers accessed by an instruction, either explicitly or
 implicitly.

 WARN: when in 'diet' mode, this API is irrelevant because engine does not
 store registers.

 @handle: handle returned by cs_open()
 @insn: disassembled instruction structure returned from cs_disasm() or cs_disasm_iter()
 @regs_read: on return, this array contains all registers read by instruction.
 @regs_read_count: number of registers kept inside @regs_read array.
 @regs_write: on return, this array contains all registers written by instruction.
 @regs_write_count: number of registers kept inside @regs_write array.

 @return CS_ERR_OK on success, or other value on failure (refer to cs_err enum
 for detailed error).
 *)
function cs_regs_access(handle: csh; const insn: Pcs_insn; var regs_read: cs_regs; var regs_read_count: Byte; var regs_write: cs_regs; var regs_write_count: Byte): cs_err; cdecl;
  external {$IFDEF CS_USE_EXTNAME}capstone{$ENDIF} name _PU + 'cs_regs_access';

(**
 Macro to create combined version which can be compared to
 result of cs_version() API.
 *)
function cs_make_version(major, minor: Integer): Cardinal; cdecl;

(**
 Calculate the offset of a disassembled instruction in its buffer, given its position
 in its array of disassembled insn
 NOTE: this macro works with position (>=1), not index
 *)
function cs_insn_offset(insns: Pcs_insn; post: Integer): Integer; cdecl;

implementation

{$IFDEF CS_STATICLINK}

{$IFDEF CPUX86}
  // Win32 from Ref\Ref\capstone-5.0.6\cb\capstone.cbp + BCC bcb-win32
  {$L Win32\cs.obj}
  {$L Win32\X86Module.obj}
  {$L Win32\X86ATTInstPrinter.obj}
  {$L Win32\X86Disassembler.obj}
  {$L Win32\X86DisassemblerDecoder.obj}
  {$L Win32\X86IntelInstPrinter.obj}
  {$L Win32\X86InstPrinterCommon.obj}
  {$L Win32\X86Mapping.obj}
  {$L Win32\Mapping.obj}
  {$L Win32\MCInst.obj}
  {$L Win32\MCInstrDesc.obj}
  {$L Win32\MCRegisterInfo.obj}
  {$L Win32\SStream.obj}
  {$L Win32\utils.obj}
  {$WARN BAD_GLOBAL_SYMBOL OFF}
{$ENDIF CPUX86}

{$IFDEF CPUX64}
  // Win32 from Ref\Ref\capstone-5.0.6\cb\capstone.cbp + BCC bcb-win64
  {$L Win64\cs.o}
  {$L Win64\X86Module.o}
  {$L Win64\X86ATTInstPrinter.o}
  {$L Win64\X86Disassembler.o}
  {$L Win64\X86DisassemblerDecoder.o}
  {$L Win64\X86IntelInstPrinter.o}
  {$L Win64\X86InstPrinterCommon.o}
  {$L Win64\X86Mapping.o}
  {$L Win64\Mapping.o}
  {$L Win64\MCInst.o}
  {$L Win64\MCInstrDesc.o}
  {$L Win64\MCRegisterInfo.o}
  {$L Win64\SStream.o}
  {$L Win64\utils.o}
  {$WARN BAD_GLOBAL_SYMBOL OFF}
{$ENDIF CPUX64}

// Link static library dependency functions.
const
{$IFDEF MSWINDOWS}
  libc = 'msvcrt.dll';
{$ENDIF MSWINDOWS}
{$IF DEFINED(ANDROID) or DEFINED(LINUX)}
  libc = 'libc.so';
{$IFEND}
{$IF DEFINED(DARWIN) or DEFINED(MACOS)}
  libc = '/usr/lib/libc.dylib';
{$IFEND}

{$IFDEF CS_USE_UNDERSCORE}
procedure __assert(expr: Boolean; msg: PAnsiChar); cdecl;
{$ELSE}
procedure _assert(expr: Boolean; msg: PAnsiChar); cdecl;
{$ENDIF}
begin
end;

{$IFDEF CS_USE_UNDERSCORE}
function _malloc(size: NativeUInt): Pointer; cdecl;
{$ELSE}
function malloc(size: NativeUInt): Pointer; cdecl;
{$ENDIF}
begin
  GetMem(Result, Size);
end;

{$IFDEF CS_USE_UNDERSCORE}
function _calloc(nmemb: NativeUInt; elsize: NativeUInt): Pointer; cdecl;
{$ELSE}
function calloc(nmemb: NativeUInt; elsize: NativeUInt): Pointer; cdecl;
{$ENDIF}
var
  nBytes: NativeUInt;
begin
  nBytes := nmemb * elsize;
  if nBytes > 0 then
  begin
    GetMem(Result, nBytes);
    FillChar(Result^, nBytes, 0);
  end
  else Result := nil;
end;

{$IFDEF CS_USE_UNDERSCORE}
function _realloc(ptr: Pointer; size: NativeUInt): Pointer; cdecl;
{$ELSE}
function realloc(ptr: Pointer; size: NativeUInt): Pointer; cdecl;
{$ENDIF}
begin
  ReallocMem(ptr, size);
  Result := ptr;
end;

{$IFDEF CS_USE_UNDERSCORE}
procedure _free(ptr: Pointer); cdecl;
{$ELSE}
procedure free(ptr: Pointer); cdecl;
{$ENDIF}
begin
  FreeMem(ptr);
end;

{$IFDEF CS_USE_UNDERSCORE}
procedure _puts; cdecl; external libc name 'puts';
{$ELSE}
procedure puts; cdecl; external libc name 'puts';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _printf; cdecl; external libc name 'printf';
{$ELSE}
procedure printf; cdecl; external libc name 'printf';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _vsnprintf; cdecl; external libc name 'vsnprintf';
{$ELSE}
procedure vsnprintf; cdecl; external libc name 'vsnprintf';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _memcpy; cdecl; external libc name 'memcpy';
{$ELSE}
procedure memcpy; cdecl; external libc name 'memcpy';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _memmove; cdecl; external libc name 'memmove';
{$ELSE}
procedure memmove; cdecl; external libc name 'memmove';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _memset; cdecl; external libc name 'memset';
{$ELSE}
procedure memset; cdecl; external libc name 'memset';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _strcat; cdecl; external libc name 'strcat';
{$ELSE}
procedure strcat; cdecl; external libc name 'strcat';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _strcmp; cdecl; external libc name 'strcmp';
{$ELSE}
procedure strcmp; cdecl; external libc name 'strcmp';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _strcpy; cdecl; external libc name 'strcpy';
{$ELSE}
procedure strcpy; cdecl; external libc name 'strcpy';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _strlen; cdecl; external libc name 'strlen';
{$ELSE}
procedure strlen; cdecl; external libc name 'strlen';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
procedure _strncpy; cdecl; external libc name 'strncpy';
{$ELSE}
procedure strncpy; cdecl; external libc name 'strncpy';
{$ENDIF}

{$IFDEF CS_USE_UNDERSCORE}
var
  _cs_mem_malloc: Pointer = @_malloc;
  _cs_mem_calloc: Pointer = @_calloc;
  _cs_mem_free: Pointer = @_free;
  _cs_vsnprintf: Pointer = @_vsnprintf;
{$ELSE}
var
  cs_mem_malloc: Pointer = @malloc;
  cs_mem_calloc: Pointer = @calloc;
  cs_mem_free: Pointer = @free;
  cs_vsnprintf: Pointer = @vsnprintf;
{$ENDIF}

{$ENDIF CS_STATICLINK}

function cs_make_version(major, minor: Integer): Cardinal;
begin
  Result := major shl 8 or minor;
end;

function cs_insn_offset(insns: Pcs_insn; post: Integer): Integer;
var
  P: Pcs_insn;
begin
  P := insns;
  Inc(P, post - 1);
  Result := P.address - insns.address;
end;

end.
