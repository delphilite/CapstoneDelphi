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

program test_xcore;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.XCore, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  xcore: Pcs_xcore;
  op: Pcs_xcore_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins^.detail = nil then
    Exit;

  xcore := @ins^.detail^.xcore;
  if xcore^.op_count <> 0 then
    WriteLn(#9'op_count: ', xcore^.op_count);

  for i := 0 to xcore^.op_count - 1 do
  begin
    op := @xcore^.operands[i];
    case op^.&type of
      XCORE_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op^.detail.reg));
      XCORE_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op^.detail.imm, '%x'));
      XCORE_OP_MEM_:
        begin
          WriteLn(#9#9'operands[', i, '].type: MEM');
          if op^.detail.mem.base <> XCORE_REG_INVALID then
            WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op^.detail.mem.base));
          if op^.detail.mem.index <> XCORE_REG_INVALID then
            WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op^.detail.mem.index));
          if op^.detail.mem.disp <> 0 then
            WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op^.detail.mem.disp, '%x'));
          if op^.detail.mem.direct <> 1 then
            WriteLn(#9#9#9'operands[', i, '].mem.direct: -1');
        end;
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  XCORE_CODE: array[0..31] of Byte = (
    $FE, $0F, $FE, $17, $13, $17, $C6, $FE, $EC, $17, $97, $F8, $EC, $4F, $1F, $FD,
    $EC, $37, $07, $F2, $45, $5B, $F9, $FA, $02, $06, $1B, $10, $09, $FD, $EC, $A7
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_XCORE; mode: CS_MODE_BIG_ENDIAN; code: @XCORE_CODE; size: SizeOf(XCORE_CODE); comment: 'XCore')
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
