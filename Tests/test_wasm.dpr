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

program test_wasm;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Wasm, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  l: string;
  wasm: Pcs_wasm;
  op: Pcs_wasm_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  if (ins.detail.groups_count > 0) then
  begin
    l := #9'Groups: ';
    for i := 0 to ins.detail.groups_count - 1 do
      l := l + string(cs_group_name(handle, ins.detail.groups[i])) + ' ';
    WriteLn(l);
  end;

  wasm := @ins.detail.wasm;

  if (wasm.op_count > 0) then
    WriteLn(#9'Operand count: ', wasm.op_count);

  for i := 0 to wasm.op_count - 1 do
  begin
    op := @wasm.operands[i];
    case op.type_ of
      WASM_OP_INT7:
      begin
        WriteLn(#9#9'Operand[', i, '] type: int7');
        WriteLn(#9#9'Operand[', i, '] value: ', op.detail.int7);
      end;
      WASM_OP_UINT32:
      begin
        WriteLn(#9#9'Operand[', i, '] type: uint32');
        WriteLn(#9#9'Operand[', i, '] value: 0x', format_string_hex(op.detail.uint32, '%x'));
      end;
      WASM_OP_UINT64:
      begin
        WriteLn(#9#9'Operand[', i, '] type: uint64');
        WriteLn(#9#9'Operand[', i, '] value: 0x', format_string_hex(op.detail.uint64, '%x'));
      end;
      WASM_OP_VARUINT32:
      begin
        WriteLn(#9#9'Operand[', i, '] type: varuint32');
        WriteLn(#9#9'Operand[', i, '] value: 0x', format_string_hex(op.detail.varuint32, '%x'));
      end;
      WASM_OP_VARUINT64:
      begin
        WriteLn(#9#9'Operand[', i, '] type: varuint64');
        WriteLn(#9#9'Operand[', i, '] value: 0x', format_string_hex(op.detail.varuint64, '%x'));
      end;
    end;
    WriteLn(#9#9'Operand[', i, '] size: ', op.size);
  end;
end;

procedure Test;
const
  WASM_CODE: array[0..10] of Byte = (
    $20, $00, $20, $01, $41, $20, $10, $C9, $01, $45, $0B
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_WASM; mode: 0; code: @WASM_CODE; size: SizeOf(WASM_CODE); comment: 'WASM')
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
    address := $ffff;
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
