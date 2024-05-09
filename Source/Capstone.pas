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
  end;

  ECapstone = class(Exception);

  TCapstone = class(TObject)
  private
    FArch: TCsArch;
    FMode: TCsMode;
    FHandle: csh;
    FCode: PUInt8;
    FSize: NativeUInt;
    FInsn: Pcs_insn;
    FDetails: Boolean;
    FSyntax: TCsSyntax;
  protected
    function  GetDetail(out AInsn: cs_insn; out ADetail: cs_detail): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    function  Open(ACode: Pointer; ASize: NativeUInt): cs_err;
    procedure Close;
    function  GetNext(var AAddr: UInt64; out AInsn: TCsInsn): Boolean;

    property  Arch: TCsArch read FArch write FArch;
    property  Mode: TCsMode read FMode write FMode;
    property  Details: Boolean read FDetails write FDetails;
    property  Syntax: TCsSyntax read FSyntax write FSyntax;
  end;

  TCapstoneEngine = class
  private
    class var VersionInited: Boolean;
    class var GlobalMajorVersion: Integer;
    class var GlobalMinorVersion: Integer;
  public
    // version function
    class function MajorVersion: Integer;
    class function MinorVersion: Integer;
  end;

  TCapstoneUtils = class
  public
    // utils function
    class function BufferToHex(const AData: PByte; ALen: Integer): string;
  end;

implementation

const
  defArchMode: array[TCsArch] of Integer = (
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

{ TCapstone }

procedure TCapstone.Close;
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

function TCapstone.GetDetail(out AInsn: cs_insn; out ADetail: cs_detail): Boolean;
begin
  if (FInsn <> nil) then
  begin
    Move(FInsn^, AInsn, SizeOf(cs_insn));
    if (FInsn^.detail <> nil) then
      Move(FInsn^.detail^, ADetail, SizeOf(cs_detail));
    Result := true;
  end
  else
    Result := False;
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
  end
  else begin
//    err := cs_errno(FHandle);
  end;
end;

function TCapstone.Open(ACode: Pointer; ASize: NativeUInt): cs_err;
var
  A, M: Integer;
  H: csh;
begin
  if FArch = csaUnknown then
    raise ECapstone.Create('Unknown Architecture');
  M := 0;
  if csmLittleEndian in FMode then
    M := M or CS_MODE_LITTLE_ENDIAN;
  if csmARM in FMode then
    M := M or CS_MODE_ARM;
  if csm16 in FMode then
    M := M or CS_MODE_16;
  if csm32 in FMode then
    M := M or CS_MODE_32;
  if csm64 in FMode then
    M := M or CS_MODE_64;
  if csmThumb in FMode then
    M := M or CS_MODE_THUMB;
  if csmMClass in FMode then
    M := M or CS_MODE_MCLASS;
  if csmV8 in FMode then
    M := M or CS_MODE_V8;
  if csmMicro in FMode then
    M := M or CS_MODE_MICRO;
  if csmMips3 in FMode then
    M := M or CS_MODE_MIPS3;
  if csmMips3R6 in FMode then
    M := M or CS_MODE_MIPS32R6;
  if csmMips2 in FMode then
    M := M or CS_MODE_MIPS2;
  if csmV9 in FMode then
    M := M or CS_MODE_V9;
  if csmQpx in FMode then
    M := M or CS_MODE_QPX;
  if csmM68k000 in FMode then
    M := M or CS_MODE_M68K_000;
  if csmM68k010 in FMode then
    M := M or CS_MODE_M68K_010;
  if csmM68k020 in FMode then
    M := M or CS_MODE_M68K_020;
  if csmM68k030 in FMode then
    M := M or CS_MODE_M68K_030;
  if csmM68k040 in FMode then
    M := M or CS_MODE_M68K_040;
  if csmM68k060 in FMode then
    M := M or CS_MODE_M68K_060;
  if csmBigEndian in FMode then
    M := M or CS_MODE_BIG_ENDIAN;
  if csmMips32 in FMode then
    M := M or CS_MODE_MIPS32;
  if csmMips64 in FMode then
    M := M or CS_MODE_MIPS64;
  if csmM680x6301 in FMode then
    M := M or CS_MODE_M680X_6301;
  if csmM680x6309 in FMode then
    M := M or CS_MODE_M680X_6309;
  if csmM680x6800 in FMode then
    M := M or CS_MODE_M680X_6800;
  if csmM680x6801 in FMode then
    M := M or CS_MODE_M680X_6801;
  if csmM680x6805 in FMode then
    M := M or CS_MODE_M680X_6805;
  if csmM680x6808 in FMode then
    M := M or CS_MODE_M680X_6808;
  if csmM680x6809 in FMode then
    M := M or CS_MODE_M680X_6809;
  if csmM680x6811 in FMode then
    M := M or CS_MODE_M680X_6811;
  if csmM680xCpu12 in FMode then
    M := M or CS_MODE_M680X_CPU12;
  if csmM680xHcs08 in FMode then
    M := M or CS_MODE_M680X_HCS08;
  A := defArchMode[FArch];
  H := 0;

  Result := cs_open(A, M, H);
  if Result = CS_ERR_OK then
  begin
    FHandle := H;
    cs_option(FHandle, CS_OPT_SKIPDATA_, CS_OPT_ON);
    if FDetails then
      cs_option(FHandle, CS_OPT_DETAIL, CS_OPT_ON);
    if FSyntax = cssAtt then
      cs_option(FHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
  end
  else begin
    FHandle := 0;
  end;

  FCode := ACode;
  FSize := ASize;
end;

{ TCapstoneEngine }

class function TCapstoneEngine.MajorVersion: Integer;
begin
  if not VersionInited then
  begin
    cs_version(GlobalMajorVersion, GlobalMinorVersion);
    VersionInited := True;
  end;
  Result := GlobalMajorVersion;
end;

class function TCapstoneEngine.MinorVersion: Integer;
begin
  if not VersionInited then
  begin
    cs_version(GlobalMajorVersion, GlobalMinorVersion);
    VersionInited := True;
  end;
  Result := GlobalMinorVersion;
end;

{ TCapstoneUtils }

class function TCapstoneUtils.BufferToHex(const AData: PByte; ALen: Integer): string;
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

end.
