{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: Demo                                      }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: Demo                                      }
{    License: Mozilla Public License 2.0                }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program Demo;

{$mode objfpc}{$H+}

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
  except
    on E: Exception do
      WriteLn(Format('Error Decompiler: %s', [E.Message]));
  end;
  ReadLn;
end.
