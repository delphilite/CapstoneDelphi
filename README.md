# CapstoneDelphi
[Capstone Disassembler Library](http://www.capstone-engine.org/) Binding for [Delphi](http://www.embarcadero.com/products/delphi) and [Free Pascal](https://www.freepascal.org/).

## Usage
Included is the wrapper class `TCapstone` in `Capstone.pas`. The example bellow 
is incomplete, but it may give you an impression how to use it.

~~~pas
uses
  SysUtils, Capstone;

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
    nAddr := UInt64(AFunc);
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
~~~
