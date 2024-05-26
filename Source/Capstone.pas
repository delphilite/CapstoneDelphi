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

{.$DEFINE CS_STATICLINK}

interface

uses
{$IFDEF CS_STATICLINK}
  Capstone.StaticLib,
{$ELSE}
  Capstone.Api,
{$ENDIF}
  SysUtils;

type
  TCsArch = (
    csaARM,
    csaARM64,
    csaMIPS,
    csaX86,
    csaPPC,
    csaSPARC,
    csaSYSZ,
    csaXCORE,
    csaM68K,
    csaTMS320C64X,
    csaM680X,
    csaEVM,
    csaUnknown
  );

  TCsMode = set of (
    csmLittleEndian,
    csmARM,
    csm16,
    csm32,
    csm64,
    csmThumb,
    csmMClass,
    csmV8,
    csmMicro,
    csmMips3,
    csmMips3R6,
    csmMips2,
    csmV9,
    csmQpx,
    csmM68k000,
    csmM68k010,
    csmM68k020,
    csmM68k030,
    csmM68k040,
    csmM68k060,
    csmBigEndian,
    csmMips32,
    csmMips64,
    csmM680x6301,
    csmM680x6309,
    csmM680x6800,
    csmM680x6801,
    csmM680x6805,
    csmM680x6808,
    csmM680x6809,
    csmM680x6811,
    csmM680xCpu12,
    csmM680xHcs08
  );

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
    FMode: TCsMode;
    FHandle: csh;
    FLastErrorCode: Integer;
    FCode: PUInt8;
    FSize: NativeUInt;
    FInsn: Pcs_insn;
    FDetails: Boolean;
    FSyntax: TCsSyntax;
  private
    function  FormatErrorMessage(ACode: Integer): string;
    function  GetHardwareMode(AMode: TCsMode): Integer;
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
    property  Mode: TCsMode read FMode write FMode;
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
  defArchitectureMode: array[TCsArch] of Integer = (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_ARCH_PPC,
    CS_ARCH_SPARC,
    CS_ARCH_SYSZ,
    CS_ARCH_XCORE,
    CS_ARCH_M68K,
    CS_ARCH_TMS320C64X,
    CS_ARCH_M680X,
    CS_ARCH_EVM,
    CS_ARCH_ALL
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

function TCapstone.GetHardwareMode(AMode: TCsMode): Integer;
var
  M: Integer;
begin
  M := 0;
  if csmLittleEndian in AMode then
    M := M or CS_MODE_LITTLE_ENDIAN;
  if csmARM in AMode then
    M := M or CS_MODE_ARM;
  if csm16 in AMode then
    M := M or CS_MODE_16;
  if csm32 in AMode then
    M := M or CS_MODE_32;
  if csm64 in AMode then
    M := M or CS_MODE_64;
  if csmThumb in AMode then
    M := M or CS_MODE_THUMB;
  if csmMClass in AMode then
    M := M or CS_MODE_MCLASS;
  if csmV8 in AMode then
    M := M or CS_MODE_V8;
  if csmMicro in AMode then
    M := M or CS_MODE_MICRO;
  if csmMips3 in AMode then
    M := M or CS_MODE_MIPS3;
  if csmMips3R6 in AMode then
    M := M or CS_MODE_MIPS32R6;
  if csmMips2 in AMode then
    M := M or CS_MODE_MIPS2;
  if csmV9 in AMode then
    M := M or CS_MODE_V9;
  if csmQpx in AMode then
    M := M or CS_MODE_QPX;
  if csmM68k000 in AMode then
    M := M or CS_MODE_M68K_000;
  if csmM68k010 in AMode then
    M := M or CS_MODE_M68K_010;
  if csmM68k020 in AMode then
    M := M or CS_MODE_M68K_020;
  if csmM68k030 in AMode then
    M := M or CS_MODE_M68K_030;
  if csmM68k040 in AMode then
    M := M or CS_MODE_M68K_040;
  if csmM68k060 in AMode then
    M := M or CS_MODE_M68K_060;
  if csmBigEndian in AMode then
    M := M or CS_MODE_BIG_ENDIAN;
  if csmMips32 in AMode then
    M := M or CS_MODE_MIPS32;
  if csmMips64 in AMode then
    M := M or CS_MODE_MIPS64;
  if csmM680x6301 in AMode then
    M := M or CS_MODE_M680X_6301;
  if csmM680x6309 in AMode then
    M := M or CS_MODE_M680X_6309;
  if csmM680x6800 in AMode then
    M := M or CS_MODE_M680X_6800;
  if csmM680x6801 in AMode then
    M := M or CS_MODE_M680X_6801;
  if csmM680x6805 in AMode then
    M := M or CS_MODE_M680X_6805;
  if csmM680x6808 in AMode then
    M := M or CS_MODE_M680X_6808;
  if csmM680x6809 in AMode then
    M := M or CS_MODE_M680X_6809;
  if csmM680x6811 in AMode then
    M := M or CS_MODE_M680X_6811;
  if csmM680xCpu12 in AMode then
    M := M or CS_MODE_M680X_CPU12;
  if csmM680xHcs08 in AMode then
    M := M or CS_MODE_M680X_HCS08;
  Result := M;
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
begin
  if FArch = csaUnknown then
    raise ECapstone.Create('Unknown Architecture');
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
