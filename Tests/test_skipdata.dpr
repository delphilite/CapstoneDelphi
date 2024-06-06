{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_skipdata                             }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_skipdata.c                     }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_skipdata;

{$APPTYPE CONSOLE}

{$I test.inc}

uses
  SysUtils, Capstone.Api, test_utils;

{$IFDEF CAPSTONE_HAS_ARM}
function mycallback(const code: PByte; code_size: NativeUInt; offset: NativeUInt; user_data: Pointer): NativeUInt; cdecl;
begin
  // always skip 2 bytes when encountering data
  Result := 2;
end;
{$ENDIF}

procedure Test;
const
{$IFDEF CAPSTONE_HAS_X86}
  X86_CODE32: array[0..14] of Byte = (
    $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00, $00, $00, $91, $92
  );
{$ENDIF}
  RANDOM_CODE: array[0..39] of Byte = (
    $ED, $00, $00, $00, $00, $1A, $5A, $0F, $1F, $FF, $C2, $09, $80, $00, $00, $00,
    $07, $F7, $EB, $2A, $FF, $FF, $7F, $57, $E3, $01, $FF, $FF, $7F, $57, $EB, $00,
    $F0, $00, $00, $24, $B2, $4F, $00, $78
  );
var
  platforms: array of TPlatform;
  handle: csh;
  address: UInt64;
  insn, item: Pcs_insn;
  err: cs_err;
  i, j: Integer;
  l: string;
  count: Integer;
  skipdata: cs_opt_skipdata;
  skipdata_callback: cs_opt_skipdata;
begin
{$IFDEF CAPSTONE_HAS_X86}
  // rename default "data" instruction from ".byte" to "db"
  FillChar(skipdata, SizeOf(skipdata), 0);
  skipdata.mnemonic := 'db';
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
  // rename default "data" instruction from ".byte" to "db"
  FillChar(skipdata_callback, SizeOf(skipdata_callback), 0);
  skipdata_callback.mnemonic := 'db';
  skipdata_callback.callback := @mycallback;
{$ENDIF}

  SetLength(platforms, 4);

  for i := Low(platforms) to High(platforms) do
  begin
    FillChar(platforms[i], SizeOf(platforms[i]), 0);
  end;

{$IFDEF CAPSTONE_HAS_X86}
  platforms[0].arch := CS_ARCH_X86;
  platforms[0].mode := CS_MODE_32;
  platforms[0].code := @X86_CODE32;
  platforms[0].size := SizeOf(X86_CODE32);
  platforms[0].comment := 'X86 32 (Intel syntax) - Skip data';

  platforms[1].arch := CS_ARCH_X86;
  platforms[1].mode := CS_MODE_32;
  platforms[1].code := @X86_CODE32;
  platforms[1].size := SizeOf(X86_CODE32);
  platforms[1].comment := 'X86 32 (Intel syntax) - Skip data with custom mnemonic';
  platforms[1].opt_type := CS_OPT_INVALID;
  platforms[1].opt_value := CS_OPT_OFF;
  platforms[1].opt_skipdata := CS_OPT_SKIPDATA_SETUP;
  platforms[1].skipdata := NativeUInt(@skipdata);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
  platforms[2].arch := CS_ARCH_ARM;
  platforms[2].mode := CS_MODE_ARM;
  platforms[2].code := @RANDOM_CODE;
  platforms[2].size := SizeOf(RANDOM_CODE);
  platforms[2].comment := 'Arm - Skip data';

  platforms[3].arch := CS_ARCH_ARM;
  platforms[3].mode := CS_MODE_ARM;
  platforms[3].code := @RANDOM_CODE;
  platforms[3].size := SizeOf(RANDOM_CODE);
  platforms[3].comment := 'Arm - Skip data with callback';
  platforms[3].opt_type := CS_OPT_INVALID;
  platforms[3].opt_value := CS_OPT_OFF;
  platforms[3].opt_skipdata := CS_OPT_SKIPDATA_SETUP;
  platforms[3].skipdata := NativeUInt(@skipdata_callback);
{$ENDIF}

  for i := Low(platforms) to High(platforms) do
  begin
    Writeln('****************');
    Writeln('Platform: ', platforms[i].comment);
    print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
    err := cs_open(platforms[i].arch, platforms[i].mode, handle);
    if err <> CS_ERR_OK then
    begin
      Writeln('Failed on cs_open() with error returned: ', err);
      Exit;
    end;

    if platforms[i].opt_type <> CS_OPT_INVALID then
      cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

    // turn on SKIPDATA mode
    cs_option(handle, CS_OPT_SKIPDATA_, CS_OPT_ON);
    cs_option(handle, platforms[i].opt_skipdata, platforms[i].skipdata);

    address := $1000;

    count := cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, insn);
    if count > 0 then
    begin
      Writeln('Disasm:');
      item := insn;
      for j := 0 to count - 1 do
      begin
        l := '0x' + format_string_hex(item.address, '%.4x');
        l := Format('%s:'#9'%s'#9#9'%s', [l, item.mnemonic, item.op_str]);
        WriteLn(l);
        if J < count - 1 then
          Inc(item);
      end;
      // print out the next offset, after the last insn
      l := '0x' + format_string_hex(item.address + item.size, '%.4x') + ':';
      Writeln(l);
      cs_free(insn, count);
    end
    else begin
      Writeln('ERROR: Failed to disasm given code!');
      cs_close(handle);
      Exit;
    end;

    WriteLn('');
    cs_close(handle);
  end;
end;

begin
  try
    Test;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
