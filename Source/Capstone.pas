{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Capstone Wrapper Class                    }
{     Author: Lsuper 2024.05.01                         }
{    Purpose:                                           }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit Capstone;

{$I Capstone.inc}

interface

uses
  SysUtils, Capstone.Api;

type
  TCsArch = (
    csaUnknown,            // Unknown architecture
    csaARM,                // ARM architecture (including Thumb, Thumb-2)
    csaARM64,              // ARM-64, also called AArch64
    csaMIPS,               // Mips architecture
    csaX86,                // X86 architecture (including x86 & x86-64)
    csaPPC,                // PowerPC architecture
    csaSPARC,              // Sparc architecture
    csaSYSZ,               // SystemZ architecture
    csaXCORE,              // XCore architecture
    csaM68K,               // 68K architecture
    csaTMS320C64X,         // TMS320C64x architecture
    csaM680X,              // 680X architecture
    csaEVM,                // Ethereum architecture
    csaMOS65XX,            // MOS65XX architecture (including MOS6502)
    csaWASM,               // WebAssembly architecture
    csaBPF,                // Berkeley Packet Filter architecture (including eBPF)
    csaRISCV,              // RISCV architecture
    csaSH,                 // SH architecture
    csaTRICORE             // TriCore architecture
  );

  TCsMode = (
    csmLittleEndian,       // little-endian mode (default mode)
    csmARM,                // 32-bit ARM
    csm16,                 // 16-bit mode (X86)
    csm32,                 // 32-bit mode (X86)
    csm64,                 // 64-bit mode (X86, PPC)
    csmThumb,              // ARM's Thumb mode, including Thumb-2
    csmMClass,             // ARM's Cortex-M series
    csmV8,                 // ARMv8 A32 encodings for ARM
    csmMicro,              // MicroMips mode (Mips)
    csmMips3,              // Mips III ISA
    csmMips32R6,           // Mips32r6 ISA
    csmMips2,              // Mips II ISA
    csmV9,                 // SparcV9 mode (Sparc)
    csmQPX,                // Quad Processing eXtensions mode (PPC)
    csmSPE,                // Signal Processing Engine mode (PPC)
    csmBookE,              // Book-E mode (PPC)
    csmPS,                 // Paired-singles mode (PPC)
    csmM68k000,            // M68K 68000 mode
    csmM68k010,            // M68K 68010 mode
    csmM68k020,            // M68K 68020 mode
    csmM68k030,            // M68K 68030 mode
    csmM68k040,            // M68K 68040 mode
    csmM68k060,            // M68K 68060 mode
    csmBigEndian,          // big-endian mode
    csmMips32,             // Mips32 ISA (Mips)
    csmMips64,             // Mips64 ISA (Mips)
    csmM680x6301,          // M680X Hitachi 6301,6303 mode
    csmM680x6309,          // M680X Hitachi 6309 mode
    csmM680x6800,          // M680X Motorola 6800,6802 mode
    csmM680x6801,          // M680X Motorola 6801,6803 mode
    csmM680x6805,          // M680X Motorola/Freescale 6805 mode
    csmM680x6808,          // M680X Motorola/Freescale/NXP 68HC08 mode
    csmM680x6809,          // M680X Motorola 6809 mode
    csmM680x6811,          // M680X Motorola/Freescale/NXP 68HC11 mode
    csmM680xCPU12,         // M680X Motorola/Freescale/NXP CPU12, used on M68HC12/HCS12
    csmM680xHCS08,         // M680X Freescale/NXP HCS08 mode
    csmBpfClassic,         // Classic BPF mode (default)
    csmBpfExtended,        // Extended BPF mode
    csmRISCV32,            // RISCV RV32G
    csmRISCV64,            // RISCV RV64G
    csmRISCVC,             // RISCV compressed instructure mode
    csmMos65Xx6502,        // MOS65XXX MOS 6502
    csmMos65Xx65C02,       // MOS65XXX WDC 65c02
    csmMos65XxW65C02,      // MOS65XXX WDC W65c02
    csmMos65Xx65816,       // MOS65XXX WDC 65816, 8-bit m/x
    csmMos65Xx65816LongM,  // MOS65XXX WDC 65816, 16-bit m, 8-bit x
    csmMos65Xx65816LongX,  // MOS65XXX WDC 65816, 8-bit m, 16-bit x
    csmMos65Xx65816LongMX, // MOS65XXX WDC 65816, 8-bit, 16-bit
    csmSH2,                // SH2
    csmSH2A,               // SH2A
    csmSH3,                // SH3
    csmSH4,                // SH4
    csmSH4A,               // SH4A
    csmSHFPU,              // w/ FPU
    csmSHDSP,              // w/ DSP
    csmTricore110,         // Tricore 1.1
    csmTricore120,         // Tricore 1.2
    csmTricore130,         // Tricore 1.3
    csmTricore131,         // Tricore 1.3.1
    csmTricore160,         // Tricore 1.6
    csmTricore161,         // Tricore 1.6.1
    csmTricore162          // Tricore 1.6.2
  );
  TCsModeSet = set of TCsMode;

  TCsSyntax = (
    cssIntel, cssAtt
  );

  TCsInsn = record
    id: Cardinal;
    address: UInt64;
    size: UInt16;
    bytes: array[0..15] of Byte;
    mnemonic: string;
    op_str: string;
    detail: Pcs_detail;
  public
    function  ToString(): string;
  end;

  TCsDetail = cs_detail;

  ECapstone = class(Exception);

  TCapstone = class(TObject)
  private
    FArch: TCsArch;
    FMode: TCsModeSet;
    FHandle: csh;
    FLastErrorCode: Integer;
    FCode: PByte;
    FSize: NativeUInt;
    FInsn: Pcs_insn;
    FDetails: Boolean;
    FSyntax: TCsSyntax;
  private
    function  FormatErrorMessage(ACode: Integer): string;
    function  GetHardwareMode(AMode: TCsModeSet): Integer;
    function  GetLastErrorMessage: string;
  public
    constructor Create;
    destructor Destroy; override;

    // version function
    class function EngineVersion: string;
    // library function
    class function LibraryVersion: string;

    function  Open(ACode: Pointer; const ASize: NativeUInt): Boolean;
    procedure Close();

    function  GetNext(var AAddr: UInt64; out AInsn: TCsInsn): Boolean;
    function  GetDetail(out ADetail: TCsDetail): Boolean;

    property  LastErrorCode: Integer read FLastErrorCode;
    property  LastErrorMessage: string read GetLastErrorMessage;

    property  Arch: TCsArch read FArch write FArch;
    property  Mode: TCsModeSet read FMode write FMode;
    property  Details: Boolean read FDetails write FDetails;
    property  Syntax: TCsSyntax read FSyntax write FSyntax;
  end;

  TCapstoneUtils = class
  public
    // utils function
    class function BufferToHex(const AData: Pointer; ALen: Integer): string;
  end;

implementation

const
  defArchitectureMode: array[TCsArch] of cs_arch = (
    CS_ARCH_ALL,                   // All architectures - for cs_support()
    CS_ARCH_ARM,                   // ARM architecture (including Thumb, Thumb-2)
    CS_ARCH_ARM64,                 // ARM-64, also called AArch64
    CS_ARCH_MIPS,                  // Mips architecture
    CS_ARCH_X86,                   // X86 architecture (including x86 & x86-64)
    CS_ARCH_PPC,                   // PowerPC architecture
    CS_ARCH_SPARC,                 // Sparc architecture
    CS_ARCH_SYSZ,                  // SystemZ architecture
    CS_ARCH_XCORE,                 // XCore architecture
    CS_ARCH_M68K,                  // 68K architecture
    CS_ARCH_TMS320C64X,            // TMS320C64x architecture
    CS_ARCH_M680X,                 // 680X architecture
    CS_ARCH_EVM,                   // Ethereum architecture
    CS_ARCH_MOS65XX,               // MOS65XX architecture (including MOS6502)
    CS_ARCH_WASM,                  // WebAssembly architecture
    CS_ARCH_BPF,                   // Berkeley Packet Filter architecture (including eBPF)
    CS_ARCH_RISCV,                 // RISCV architecture
    CS_ARCH_SH,                    // SH architecture
    CS_ARCH_TRICORE                // TriCore architecture
  );

  defHardwareMode: array[TCsMode] of cs_mode = (
    CS_MODE_LITTLE_ENDIAN,         // little-endian mode (default mode)
    CS_MODE_ARM,                   // 32-bit ARM
    CS_MODE_16,                    // 16-bit mode (X86)
    CS_MODE_32,                    // 32-bit mode (X86)
    CS_MODE_64,                    // 64-bit mode (X86, PPC)
    CS_MODE_THUMB,                 // ARM's Thumb mode, including Thumb-2
    CS_MODE_MCLASS,                // ARM's Cortex-M series
    CS_MODE_V8,                    // ARMv8 A32 encodings for ARM
    CS_MODE_MICRO,                 // MicroMips mode (MIPS)
    CS_MODE_MIPS3,                 // Mips III ISA
    CS_MODE_MIPS32R6,              // Mips32r6 ISA
    CS_MODE_MIPS2,                 // Mips II ISA
    CS_MODE_V9,                    // SparcV9 mode (Sparc)
    CS_MODE_QPX,                   // Quad Processing eXtensions mode (PPC)
    CS_MODE_SPE,                   // Signal Processing Engine mode (PPC)
    CS_MODE_BOOKE,                 // Book-E mode (PPC)
    CS_MODE_PS,                    // Paired-singles mode (PPC)
    CS_MODE_M68K_000,              // M68K 68000 mode
    CS_MODE_M68K_010,              // M68K 68010 mode
    CS_MODE_M68K_020,              // M68K 68020 mode
    CS_MODE_M68K_030,              // M68K 68030 mode
    CS_MODE_M68K_040,              // M68K 68040 mode
    CS_MODE_M68K_060,              // M68K 68060 mode
    CS_MODE_BIG_ENDIAN,            // big-endian mode
    CS_MODE_MIPS32,                // Mips32 ISA (Mips)
    CS_MODE_MIPS64,                // Mips64 ISA (Mips)
    CS_MODE_M680X_6301,            // M680X Hitachi 6301,6303 mode
    CS_MODE_M680X_6309,            // M680X Hitachi 6309 mode
    CS_MODE_M680X_6800,            // M680X Motorola 6800,6802 mode
    CS_MODE_M680X_6801,            // M680X Motorola 6801,6803 mode
    CS_MODE_M680X_6805,            // M680X Motorola/Freescale 6805 mode
    CS_MODE_M680X_6808,            // M680X Motorola/Freescale/NXP 68HC08 mode
    CS_MODE_M680X_6809,            // M680X Motorola 6809 mode
    CS_MODE_M680X_6811,            // M680X Motorola/Freescale/NXP 68HC11 mode
    CS_MODE_M680X_CPU12,           // M680X Motorola/Freescale/NXP CPU12, used on M68HC12/HCS12
    CS_MODE_M680X_HCS08,           // M680X Freescale/NXP HCS08 mode
    CS_MODE_BPF_CLASSIC,           // Classic BPF mode (default)
    CS_MODE_BPF_EXTENDED,          // Extended BPF mode
    CS_MODE_RISCV32,               // RISCV RV32G
    CS_MODE_RISCV64,               // RISCV RV64G
    CS_MODE_RISCVC,                // RISCV compressed instructure mode
    CS_MODE_MOS65XX_6502,          // MOS65XXX MOS 6502
    CS_MODE_MOS65XX_65C02,         // MOS65XXX WDC 65c02
    CS_MODE_MOS65XX_W65C02,        // MOS65XXX WDC W65c02
    CS_MODE_MOS65XX_65816,         // MOS65XXX WDC 65816, 8-bit m/x
    CS_MODE_MOS65XX_65816_LONG_M,  // MOS65XXX WDC 65816, 16-bit m, 8-bit x
    CS_MODE_MOS65XX_65816_LONG_X,  // MOS65XXX WDC 65816, 8-bit m, 16-bit x
    CS_MODE_MOS65XX_65816_LONG_MX, // MOS65XXX WDC 65816, 8-bit, 16-bit
    CS_MODE_SH2,                   // SH2
    CS_MODE_SH2A,                  // SH2A
    CS_MODE_SH3,                   // SH3
    CS_MODE_SH4,                   // SH4
    CS_MODE_SH4A,                  // SH4A
    CS_MODE_SHFPU,                 // w/ FPU
    CS_MODE_SHDSP,                 // w/ DSP
    CS_MODE_TRICORE_110,           // Tricore 1.1
    CS_MODE_TRICORE_120,           // Tricore 1.2
    CS_MODE_TRICORE_130,           // Tricore 1.3
    CS_MODE_TRICORE_131,           // Tricore 1.3.1
    CS_MODE_TRICORE_160,           // Tricore 1.6
    CS_MODE_TRICORE_161,           // Tricore 1.6.1
    CS_MODE_TRICORE_162            // Tricore 1.6.2
  );

type
  TCapstoneErrorInfo = record
    Code: Integer;
    Description: string;
  end;

const
  defCapstoneErrorInfos: array[0..14] of TCapstoneErrorInfo = (
    (Code: CS_ERR_OK;        Description: 'No error: everything was fine'),
    (Code: CS_ERR_MEM;       Description: 'Out-Of-Memory error'),
    (Code: CS_ERR_ARCH;      Description: 'Unsupported architecture'),
    (Code: CS_ERR_HANDLE;    Description: 'Invalid handle'),
    (Code: CS_ERR_CSH;       Description: 'Invalid csh argument'),
    (Code: CS_ERR_MODE;      Description: 'Invalid/unsupported mode'),
    (Code: CS_ERR_OPTION;    Description: 'Invalid/unsupported option'),
    (Code: CS_ERR_DETAIL;    Description: 'Information is unavailable because detail option is OFF'),
    (Code: CS_ERR_MEMSETUP;  Description: 'Dynamic memory management uninitialized (see CS_OPT_MEM)'),
    (Code: CS_ERR_VERSION;   Description: 'Unsupported version (bindings)'),
    (Code: CS_ERR_DIET;      Description: 'Access irrelevant data in "diet" engine'),
    (Code: CS_ERR_SKIPDATA;  Description: 'Access irrelevant data for "data" instruction in SKIPDATA mode'),
    (Code: CS_ERR_X86_ATT;   Description: 'X86 AT&T syntax is unsupported (opt-out at compile time)'),
    (Code: CS_ERR_X86_INTEL; Description: 'X86 Intel syntax is unsupported (opt-out at compile time)'),
    (Code: CS_ERR_X86_MASM;  Description: 'X86 Masm syntax is unsupported (opt-out at compile time)')
  );

resourcestring
  rsErrUnKnownErrorFmt  = 'Unknown Error code: %d';

  rsErrUnsupportedArchFmt = 'Unsupported architecture: %d';
  rsErrUnsupportedLibvFmt = 'Unsupported version: %x';

{ TCapstone }

procedure TCapstone.Close();
begin
  if FInsn <> nil then
  begin
    cs_free(FInsn, 1);
    FInsn := nil;
  end;
  if FHandle <> 0 then
  begin
    cs_close(FHandle);
    FHandle := 0;
  end;
end;

constructor TCapstone.Create;
begin
  inherited;

  FArch := csaUnknown;
  FMode := [];
  FDetails := False;
  FSyntax := cssIntel;
  FHandle := 0;
  FInsn := nil;
end;

destructor TCapstone.Destroy;
begin
  Close;

  inherited;
end;

class function TCapstone.EngineVersion: string;
var
  V, major, minor: Integer;
begin
  V := cs_version(major, minor);
  Result := Format('%x', [V]);
end;

function TCapstone.FormatErrorMessage(ACode: Integer): string;
var
  I: Integer;
begin
  for I := Low(defCapstoneErrorInfos) to High(defCapstoneErrorInfos) do
    if defCapstoneErrorInfos[I].Code = ACode then
  begin
    Result := defCapstoneErrorInfos[I].Description;
    Exit;
  end;
  Result := Format(rsErrUnKnownErrorFmt, [ACode]);
end;

function TCapstone.GetDetail(out ADetail: TCsDetail): Boolean;
begin
  Result := (FInsn <> nil) and (FInsn^.detail <> nil);
  if Result then
    Move(FInsn^.detail^, ADetail, SizeOf(cs_detail));
  Assert(SizeOf(TCsDetail) = SizeOf(cs_detail));
end;

function TCapstone.GetHardwareMode(AMode: TCsModeSet): Integer;
var
  E: TCsMode;
begin
  Result := 0;
  for E := Low(TCsMode) to High(TCsMode) do
  begin
    if E in AMode then
      Result := Result or defHardwareMode[E];
  end;
end;

function TCapstone.GetLastErrorMessage: string;
begin
  Result := FormatErrorMessage(FLastErrorCode);
end;

function TCapstone.GetNext(var AAddr: UInt64; out AInsn: TCsInsn): Boolean;
begin
  if FHandle = 0 then
  begin
    Result := False;
    Exit;
  end;
  if FInsn = nil then
  begin
    FInsn := cs_malloc(FHandle);
  end;

  AInsn.mnemonic := '';
  AInsn.op_str := '';
  FillChar(AInsn, SizeOf(AInsn), #0);

  Result := cs_disasm_iter(FHandle, FCode, FSize, AAddr, FInsn);
  if Result then
  begin
    AInsn.id := FInsn^.id;
    AInsn.address := FInsn^.address;
    AInsn.size := FInsn^.size;
    Move(FInsn^.bytes, AInsn.bytes, 16);
    AInsn.mnemonic := string(FInsn^.mnemonic);
    AInsn.op_str := string(FInsn^.op_str);
    AInsn.detail := FInsn^.detail;
  end
  else begin
    FLastErrorCode := cs_errno(FHandle);
  end;
end;

class function TCapstone.LibraryVersion: string;
begin
  Result := Format('%d.%d.%d', [CS_VERSION_MAJOR, CS_VERSION_MINOR, CS_VERSION_EXTRA]);
end;

function TCapstone.Open(ACode: Pointer; const ASize: NativeUInt): Boolean;
var
  A, M: Integer;
  H: csh;
  U, V, R, S: Integer;
begin
  R := cs_version(U, V);
  S := cs_make_version(CS_API_MAJOR, CS_API_MINOR);
  if R < S then
    raise ECapstone.CreateFmt(rsErrUnsupportedLibvFmt, [R]);

  if FArch = csaUnknown then
    raise ECapstone.CreateFmt(rsErrUnsupportedArchFmt, [Ord(FArch)]);

  A := defArchitectureMode[FArch];
  M := GetHardwareMode(FMode);
  H := 0;
  FLastErrorCode := cs_open(A, M, H);
  Result := FLastErrorCode = CS_ERR_OK;
  if Result then
  begin
    FHandle := H;
    cs_option(FHandle, CS_OPT_SKIPDATA_, CS_OPT_ON);
    if FDetails then
      cs_option(FHandle, CS_OPT_DETAIL, CS_OPT_ON);
    if FSyntax = cssAtt then
      cs_option(FHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    FCode := ACode;
    FSize := ASize;
  end
  else begin
    FHandle := 0;
    FCode := nil;
    FSize := 0;
  end;
end;

{ TCapstoneUtils }

class function TCapstoneUtils.BufferToHex(const AData: Pointer; ALen: Integer): string;
const
  defCharConvertTable: array[0..15] of Char = (
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
  );
var
  pData: PByte;
  pRet: PChar;
begin
  pData := AData;
  SetLength(Result, 2 * ALen);
  pRet := PChar(Result);
  while ALen > 0 do
  begin
    pRet^ := defCharConvertTable[(pData^ and $F0) shr 4];
    Inc(pRet);
    pRet^ := defCharConvertTable[pData^ and $0F];
    Inc(pRet);
    Dec(ALen);
    Inc(pData);
  end;
end;

{ TCsInsn }

function TCsInsn.ToString(): string;
var
  S: string;
begin
  if Self.size > 0 then
    S := TCapstoneUtils.BufferToHex(PByte(@Self.bytes), Self.size)
  else S := '';
  Result := Format('%.8x %-16s %s %s', [Self.address, S, Self.mnemonic, Self.op_str]);
end;

end.
