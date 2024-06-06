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

program test_riscv;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.RiscV, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  l: string;
  detail: Pcs_detail;
  riscv: Pcs_riscv;
  op: Pcs_riscv_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  riscv := @ins.detail.riscv;
  detail := ins.detail;
  if (riscv.op_count <> 0) then
    WriteLn(#9'op_count: ', riscv.op_count);

  for i := 0 to riscv.op_count - 1 do
  begin
    op := @riscv.operands[i];
    case op.type_ of
      RISCV_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      RISCV_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      RISCV_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if (op.detail.mem.base <> RISCV_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        if (op.detail.mem.disp <> 0) then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp, '%x'));
      end;
    else
      WriteLn(#9'error in opt_type: ', op.type_);
    end;
  end;

  // print the groups this instruction belongs to
  if (detail.groups_count > 0) then
  begin
    l := #9'This instruction belongs to groups: ';
    for i := 0 to detail.groups_count - 1 do
      l := l + string(cs_group_name(handle, detail.groups[i]) + ' ');
    WriteLn(l);
  end;

  WriteLn('');
end;

procedure Test;
const
  RISCV_CODE32: array[0..159] of Byte = (
    $37, $34, $00, $00, $97, $82, $00, $00, $ef, $00, $80, $00, $ef, $f0, $1f, $ff,
    $e7, $00, $45, $00, $e7, $00, $c0, $ff, $63, $05, $41, $00, $e3, $9d, $61, $fe,
    $63, $ca, $93, $00, $63, $53, $b5, $00, $63, $65, $d6, $00, $63, $76, $f7, $00,
    $03, $88, $18, $00, $03, $99, $49, $00, $03, $aa, $6a, $00, $03, $cb, $2b, $01,
    $03, $dc, $8c, $01, $23, $86, $ad, $03, $23, $9a, $ce, $03, $23, $8f, $ef, $01,
    $93, $00, $e0, $00, $13, $a1, $01, $01, $13, $b2, $02, $7d, $13, $c3, $03, $dd,
    $13, $e4, $c4, $12, $13, $f5, $85, $0c, $13, $96, $e6, $01, $13, $d7, $97, $01,
    $13, $d8, $f8, $40, $33, $89, $49, $01, $b3, $0a, $7b, $41, $33, $ac, $ac, $01,
    $b3, $3d, $de, $01, $33, $d2, $62, $40, $b3, $43, $94, $00, $33, $e5, $c5, $00,
    $b3, $76, $f7, $00, $b3, $54, $39, $01, $b3, $50, $31, $00, $33, $9f, $0f, $00
  );
  RISCV_CODE64: array[0..3] of Byte = (
    $13, $04, $a8, $7a
  );
const
  Platforms: array[0..1] of TPlatform = (
    (arch: CS_ARCH_RISCV; mode: CS_MODE_RISCV32; code: @RISCV_CODE32; size: SizeOf(RISCV_CODE32); comment: 'riscv32'),
    (arch: CS_ARCH_RISCV; mode: CS_MODE_RISCV64; code: @RISCV_CODE64; size: SizeOf(RISCV_CODE64); comment: 'riscv64')
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

    //To turn on or off the Print Details option
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
