{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_systemz                              }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_systemz.c                      }
{    License: Mozilla Public License 2.0                }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_systemz;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.SystemZ, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  sysz: Pcs_sysz;
  op: Pcs_sysz_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  sysz := @(ins.detail.sysz);
  if sysz.op_count > 0 then
    WriteLn(#9'op_count: ', sysz.op_count);

  for i := 0 to sysz.op_count - 1 do
  begin
    op := @sysz.operands[i];
    case op.type_ of
      SYSZ_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      SYSZ_OP_ACREG:
        WriteLn(#9#9'operands[', i, '].type: ACREG = ', op.detail.reg);
      SYSZ_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      SYSZ_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if op.detail.mem.base <> SYSZ_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        if op.detail.mem.index <> SYSZ_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op.detail.mem.index));
        if op.detail.mem.length <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.length: 0x', format_string_hex(op.detail.mem.length));
        if op.detail.mem.disp <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp));
      end;
    end;
  end;

  if sysz.cc <> 0 then
    WriteLn(#9'Code condition: ', sysz.cc);

  WriteLn('');
end;

procedure Test;
const
  SYSZ_CODE: array[0..45] of Byte = (
    $ED, $00, $00, $00, $00, $1A, $5A, $0F, $1F, $FF, $C2, $09, $80, $00, $00, $00,
    $07, $F7, $EB, $2A, $FF, $FF, $7F, $57, $E3, $01, $FF, $FF, $7F, $57, $EB, $00,
    $F0, $00, $00, $24, $B2, $4F, $00, $78, $EC, $18, $00, $00, $C1, $7F
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_SYSZ; mode: CS_MODE_BIG_ENDIAN; code: @SYSZ_CODE; size: SizeOf(SYSZ_CODE); comment: 'SystemZ')
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
