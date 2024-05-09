# CapstoneDelphi
Capstone Disassembler Library Binding for Delphi . [Capstone Disassembler Library](http://www.capstone-engine.org/)

## Usage
Included is the wrapper class `TCapstone` in `Capstone.pas`. The example bellow 
is incomplete, but it may give you an impression how to use it.

~~~pas
uses
  System.SysUtils, Capstone, Capstone.Api;

procedure DisAsmFunctionCode(const AFunc: Pointer; ASize: Integer = -1);
var
  aInsn: TCsInsn;
  disasm: TCapstone;
  nAddr: UInt64;
  nSize: NativeUInt;
  pFunc: PByte;
  S: string;
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
    if Open(AFunc, nSize) <> CS_ERR_OK then
      Exit;
    nAddr := UInt64(AFunc);
    pFunc := PByte(AFunc);
    while GetNext(nAddr, aInsn) do
    begin
      S := TCapstoneUtils.BufferToHex(pFunc, aInsn.size);
      S := Format('%.8x %-16s %s %s', [aInsn.address, S, aInsn.mnemonic, aInsn.op_str]);
      WriteLn(S);
      Inc(pFunc, aInsn.size);
      if (ASize < 0) and (aInsn.mnemonic = 'ret') then
        Break;
    end;
  finally
    Free;
  end;
end;

begin
  try
    WriteLn(Format('Capstone Engine: %d.%d, DisAsm ExpandFileNameCase ...', [TCapstoneEngine.MajorVersion, TCapstoneEngine.MinorVersion]));
    WriteLn('');
    DisAsmFunctionCode(@System.SysUtils.ExpandFileNameCase);
    WriteLn('');
    WriteLn('Done.');
  except
    on E: Exception do
      WriteLn(Format('Error Decompiler: %s', [E.Message]));
  end;
  if DebugHook <> 0 then
    Readln;
end.~~~
