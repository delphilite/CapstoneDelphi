{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_mips                                 }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_mips.c                         }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_mips;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.Mips, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  mips: Pcs_mips;
begin
  if ins^.detail = nil then
    Exit;

  mips := @ins^.detail^.mips;
  if mips^.op_count > 0 then
    WriteLn(#9'op_count: ', mips^.op_count);

  for i := 0 to mips^.op_count - 1 do
  begin
    case mips^.operands[i].&type of
      MIPS_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, mips^.operands[i].detail.reg));
      MIPS_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(mips^.operands[i].detail.imm, '%x'));
      MIPS_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if mips^.operands[i].detail.mem.base <> MIPS_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, mips^.operands[i].detail.mem.base));
        if mips^.operands[i].detail.mem.disp <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(mips^.operands[i].detail.mem.disp, '%x'));
      end;
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  MIPS_CODE: array[0..19] of Byte = (
    $0C, $10, $00, $97, $00, $00, $00, $00, $24, $02, $00, $0C, $8F, $A2, $00, $00,
    $34, $21, $34, $56
  );
  MIPS_CODE2: array[0..7] of Byte = (
    $56, $34, $21, $34, $C2, $17, $01, $00
  );
  MIPS_32R6M: array[0..15] of Byte = (
    $00, $07, $00, $07, $00, $11, $93, $7C, $01, $8C, $8B, $7C, $00, $C7, $48, $D0
  );
  MIPS_32R6: array[0..7] of Byte = (
    $EC, $80, $00, $19, $7C, $43, $22, $A0
  );
  MIPS_64SD: array[0..3] of Byte = (
    $70, $00, $B2, $FF
  );
const
  Platforms: array[0..5] of TPlatform = (
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS32 or CS_MODE_BIG_ENDIAN); code: @MIPS_CODE; size: SizeOf(MIPS_CODE); comment: 'MIPS-32 (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS64 or CS_MODE_LITTLE_ENDIAN); code: @MIPS_CODE2; size: SizeOf(MIPS_CODE2); comment: 'MIPS-64-EL (Little-endian)'),
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS32R6 or CS_MODE_MICRO or CS_MODE_BIG_ENDIAN); code: @MIPS_32R6M; size: SizeOf(MIPS_32R6M); comment: 'MIPS-32R6 | Micro (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS32R6 or CS_MODE_BIG_ENDIAN); code: @MIPS_32R6; size: SizeOf(MIPS_32R6); comment: 'MIPS-32R6 (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS64 or CS_MODE_MIPS2 or CS_MODE_LITTLE_ENDIAN); code: @MIPS_64SD; size: SizeOf(MIPS_64SD); comment: 'MIPS-64-EL + Mips II (Little-endian)'),
    (arch: CS_ARCH_MIPS; mode: cs_mode(CS_MODE_MIPS64 or CS_MODE_LITTLE_ENDIAN); code: @MIPS_64SD; size: SizeOf(MIPS_64SD); comment: 'MIPS-64-EL (Little-endian)')
  );
var
  handle: csh;
  address: UInt64;
  insn, item: Pcs_insn;
  i, j: Integer;
  count: Integer;
  l: string;
  err: cs_err;
begin
  for i := Low(Platforms) to High(Platforms) do
  begin
    address := $1000;
    err := cs_open(Platforms[i].arch, Platforms[i].mode, handle);
    if err <> CS_ERR_OK then
    begin
      WriteLn('Failed on cs_open() with error returned: ', err);
      Abort;
    end;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    if Platforms[i].syntax <> 0 then
      cs_option(handle, CS_OPT_SYNTAX, Platforms[i].syntax);

    count := cs_disasm(handle, Platforms[i].code, Platforms[i].size, address, 0, insn);
    if count > 0 then
    try
      WriteLn('****************');
      WriteLn('Platform: ', Platforms[i].comment);
      print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
      WriteLn('Disasm:');

      item := insn;
      for j := 0 to count - 1 do
      begin
        l := '0x' + format_string_hex(item.address);
        WriteLn(l, ':'#9, item.mnemonic, #9, item.op_str);
        print_insn_detail(handle, item);
        if j < count - 1 then
          Inc(item);
      end;
      l := '0x' + format_string_hex(item.address + item.size, '%.2x') + ':';
      WriteLn(l);
    finally
      // free memory allocated by cs_disasm()
      cs_free(insn, count);
    end
    else begin
      WriteLn('****************');
      WriteLn('Platform: ', Platforms[i].comment);
      print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
      WriteLn('ERROR: Failed to disasm given code!');
      Abort;
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
