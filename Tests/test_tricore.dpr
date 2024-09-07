{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_mips                                 }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_mips.c                         }
{    License: Mozilla Public License 2.0                }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_tricore;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.TriCore, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  tricore: Pcs_tricore;
  op: Pcs_tricore_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  tricore := @ins.detail.tricore;

  if (tricore.op_count <> 0) then
    WriteLn(#9'op_count: ', tricore.op_count);

  for i := 0 to tricore.op_count - 1 do
  begin
    op := @tricore.operands[i];
    case op.type_ of
      TRICORE_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      TRICORE_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      TRICORE_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if (op.detail.mem.base <> TRICORE_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        if (op.detail.mem.disp <> 0) then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp, '%x'));
      end;
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  TRICORE_CODE: array[0..29] of Byte = (
    $09, $CF, $BC, $F5, $09, $F4, $01, $00, $89, $FB, $8F, $74, $89, $FE, $48, $01,
    $29, $00, $19, $25, $29, $03, $09, $F4, $85, $F9, $68, $0F, $16, $01
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_TRICORE; mode: CS_MODE_TRICORE_162; code: @TRICORE_CODE; size: SizeOf(TRICORE_CODE); comment: 'TriCore')
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
