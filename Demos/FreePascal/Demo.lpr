program Demo;

{$mode objfpc}{$H+}

uses
  SysUtils,

  Capstone.Arm in '..\..\Source\Capstone.Arm.pas',
  Capstone.Arm64 in '..\..\Source\Capstone.Arm64.pas',
  Capstone.Evm in '..\..\Source\Capstone.Evm.pas',
  Capstone.M680X in '..\..\Source\Capstone.M680X.pas',
  Capstone.M68K in '..\..\Source\Capstone.M68K.pas',
  Capstone.Mips in '..\..\Source\Capstone.Mips.pas',
  Capstone.Ppc in '..\..\Source\Capstone.Ppc.pas',
  Capstone.Sparc in '..\..\Source\Capstone.Sparc.pas',
  Capstone.SystemZ in '..\..\Source\Capstone.SystemZ.pas',
  Capstone.Tms320c64x in '..\..\Source\Capstone.Tms320c64x.pas',
  Capstone.X86 in '..\..\Source\Capstone.X86.pas',
  Capstone.XCore in '..\..\Source\Capstone.XCore.pas',

  Capstone.Api in '..\..\Source\Capstone.Api.pas',
  Capstone in '..\..\Source\Capstone.pas';

procedure DisAsmFunctionCode(const AFunc: Pointer; ASize: Integer = -1);
var
  aInsn: TCsInsn;
  disasm: TCapstone;
  nAddr: UInt64;
  nSize: NativeUInt;
begin
  if ASize < 0 then
    nSize := MaxInt
  else nSize := ASize;
  disasm := TCapstone.Create;
  with disasm do
  try
{$IFDEF CPUX64}
    Mode := [csm64];
{$ELSE}
    Mode := [csm32];
{$ENDIF}
    Arch := csaX86;
    if Open(AFunc, nSize) then
      while GetNext(nAddr, aInsn) do
    begin
      WriteLn(aInsn.ToString);
      if (ASize < 0) and (aInsn.mnemonic = 'ret') then
        Break;
    end;
  finally
    Free;
  end;
end;

begin
  try
    WriteLn(Format('Capstone Engine: v%s(%s), DisAsm ExpandFileNameCase ...', [TCapstone.LibraryVersion, TCapstone.EngineVersion]));
    WriteLn('');
    DisAsmFunctionCode(@SysUtils.ExpandFileNameCase);
    WriteLn('');
    WriteLn('Done.');
    ReadLn;
  except
    on E: Exception do
      WriteLn(Format('Error Decompiler: %s', [E.Message]));
  end;
end.
