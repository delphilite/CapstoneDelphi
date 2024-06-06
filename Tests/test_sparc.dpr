{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_sparc                                }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_sparc.c                        }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_sparc;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Sparc, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  sparc: Pcs_sparc;
  op: Pcs_sparc_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  sparc := @ins.detail.sparc;
  if sparc.op_count > 0 then
    WriteLn(#9'op_count: ', sparc.op_count);

  for i := 0 to sparc.op_count - 1 do
  begin
    op := @sparc.operands[i];
    case op.type_ of
      SPARC_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      SPARC_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      SPARC_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if op.detail.mem.base <> SPARC_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        if op.detail.mem.index <> SPARC_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op.detail.mem.index));
        if op.detail.mem.disp <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp, '%x'));
      end;
    end;
  end;

  if sparc.cc <> 0 then
    WriteLn(#9'Code condition: ', sparc.cc);

  if sparc.hint <> 0 then
    WriteLn(#9'Hint code: ', sparc.hint);

  WriteLn('');
end;

procedure Test;
const
  SPARC_CODE: array[0..63] of Byte = (
    $80, $A0, $40, $02, $85, $C2, $60, $08, $85, $E8, $20, $01, $81, $E8, $00, $00,
    $90, $10, $20, $01, $D5, $F6, $10, $16, $21, $00, $00, $0A, $86, $00, $40, $02,
    $01, $00, $00, $00, $12, $BF, $FF, $FF, $10, $BF, $FF, $FF, $A0, $02, $00, $09,
    $0D, $BF, $FF, $FF, $D4, $20, $60, $00, $D4, $4E, $00, $16, $2A, $C2, $80, $03
  );
  SPARCV9_CODE: array[0..15] of Byte = (
    $81, $A8, $0A, $24, $89, $A0, $10, $20, $89, $A0, $1A, $60, $89, $A0, $00, $E0
  );
const
  Platforms: array[0..1] of TPlatform = (
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN; code: @SPARC_CODE; size: SizeOf(SPARC_CODE); comment: 'Sparc'),
    (arch: CS_ARCH_SPARC; mode: (CS_MODE_BIG_ENDIAN or CS_MODE_V9); code: @SPARCV9_CODE; size: SizeOf(SPARCV9_CODE); comment: 'SparcV9')
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
