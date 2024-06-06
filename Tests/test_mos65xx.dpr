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

program test_mos65xx;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Mos65xx, test_utils;

function get_am_name(mode: mos65xx_address_mode): string;
begin
  case mode of
    MOS65XX_AM_NONE: Result := 'No address mode';
    MOS65XX_AM_IMP: Result := 'implied';
    MOS65XX_AM_ACC: Result := 'accumulator';
    MOS65XX_AM_IMM: Result := 'immediate value';
    MOS65XX_AM_REL: Result := 'relative';
    MOS65XX_AM_INT: Result := 'interrupt signature';
    MOS65XX_AM_BLOCK: Result := 'block move';
    MOS65XX_AM_ZP: Result := 'zero page';
    MOS65XX_AM_ZP_X: Result := 'zero page indexed with x';
    MOS65XX_AM_ZP_Y: Result := 'zero page indexed with y';
    MOS65XX_AM_ZP_REL: Result := 'relative bit branch';
    MOS65XX_AM_ZP_IND: Result := 'zero page indirect';
    MOS65XX_AM_ZP_X_IND: Result := 'zero page indexed with x indirect';
    MOS65XX_AM_ZP_IND_Y: Result := 'zero page indirect indexed with y';
    MOS65XX_AM_ZP_IND_LONG: Result := 'zero page indirect long';
    MOS65XX_AM_ZP_IND_LONG_Y: Result := 'zero page indirect long indexed with y';
    MOS65XX_AM_ABS: Result := 'absolute';
    MOS65XX_AM_ABS_X: Result := 'absolute indexed with x';
    MOS65XX_AM_ABS_Y: Result := 'absolute indexed with y';
    MOS65XX_AM_ABS_IND: Result := 'absolute indirect';
    MOS65XX_AM_ABS_X_IND: Result := 'absolute indexed with x indirect';
    MOS65XX_AM_ABS_IND_LONG: Result := 'absolute indirect long';
    MOS65XX_AM_ABS_LONG: Result := 'absolute long';
    MOS65XX_AM_ABS_LONG_X: Result := 'absolute long indexed with x';
    MOS65XX_AM_SR: Result := 'stack relative';
    MOS65XX_AM_SR_IND_Y: Result := 'stack relative indirect indexed with y';
  else
    Result := 'Unknown address mode';
  end;
end;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
const
  s_bool_strs: array[Boolean] of string = (
    'false', 'true'
  );
var
  i: Integer;
  mos65xx: Pcs_mos65xx;
  op: Pcs_mos65xx_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  mos65xx := @(ins.detail.mos65xx);

  // printf("insn_detail\n");
  Writeln(#9'address mode: ', get_am_name(mos65xx.am));
  Writeln(#9'modifies flags: ', s_bool_strs[mos65xx.modifies_flags]);

  if (mos65xx.op_count > 0) then
    Writeln(#9'op_count: ', mos65xx.op_count);

  for i := 0 to mos65xx.op_count - 1 do
  begin
    op := @mos65xx.operands[i];
    case op.type_ of
      MOS65XX_OP_REG:
        Writeln(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      MOS65XX_OP_IMM:
        Writeln(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      MOS65XX_OP_MEM:
        Writeln(#9#9'operands[', i, '].type: MEM = 0x', format_string_hex(op.detail.mem, '%x'));
    end;
  end;

  Writeln('');
end;


procedure Test;
const
  M6502_CODE: array[0..37] of Byte = (
    $a1, $12, $a5, $12, $a9, $12, $ad, $34, $12, $b1, $12, $b5, $12, $b9, $34, $12,
    $bd, $34, $12, $0d, $34, $12, $00, $81, $87, $6c, $01, $00, $85, $FF, $10, $00,
    $19, $42, $42, $00, $49, $42
  );
  M65C02_CODE: array[0..7] of Byte = (
    $1a, $3a, $02, $12, $03, $5c, $34, $12
  );
  MW65C02_CODE: array[0..29] of Byte = (
    $07, $12, $27, $12, $47, $12, $67, $12, $87, $12, $a7, $12, $c7, $12, $e7, $12,
    $10, $fe, $0f, $12, $fd, $4f, $12, $fd, $8f, $12, $fd, $cf, $12, $fd
  );
  M65816_CODE: array[0..49] of Byte = (
    $a9, $34, $12, $ad, $34, $12, $bd, $34, $12, $b9, $34, $12, $af, $56, $34, $12,
    $bf, $56, $34, $12, $a5, $12, $b5, $12, $b2, $12, $a1, $12, $b1, $12, $a7, $12,
    $b7, $12, $a3, $12, $b3, $12, $c2, $00, $e2, $00, $54, $34, $12, $44, $34, $12,
    $02, $12
  );
const
  Platforms: array[0..3] of TPlatform = (
    (arch: CS_ARCH_MOS65XX; mode: CS_MODE_MOS65XX_6502; code: @M6502_CODE; size: SizeOf(M6502_CODE); comment: 'MOS65XX_6502'),
    (arch: CS_ARCH_MOS65XX; mode: CS_MODE_MOS65XX_65C02; code: @M65C02_CODE; size: SizeOf(M65C02_CODE); comment: 'MOS65XX_65C02'),
    (arch: CS_ARCH_MOS65XX; mode: CS_MODE_MOS65XX_W65C02; code: @MW65C02_CODE; size: SizeOf(MW65C02_CODE); comment: 'MOS65XX_W65C02'),
    (arch: CS_ARCH_MOS65XX; mode: CS_MODE_MOS65XX_65816_LONG_MX; code: @M65816_CODE; size: SizeOf(M65816_CODE); comment: 'MOS65XX_65816 (long m/x)')
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
      Writeln('Failed on cs_open() with error returned: ', err);
      Abort;
    end;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MOTOROLA);

    count := cs_disasm(handle, Platforms[i].code, Platforms[i].size, address, 0, insn);
    if count > 0 then
    try
      Writeln('****************');
      Writeln('Platform: ', Platforms[i].comment);
      print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
      Writeln('Disasm:');

      item := insn;
      for j := 0 to count - 1 do
      begin
        l := '0x' + format_string_hex(item.address);
        Writeln(l, ':'#9, item.mnemonic, #9, item.op_str);
        print_insn_detail(handle, item);
        if j < count - 1 then
          Inc(item);
      end;
      l := '0x' + format_string_hex(item.address + item.size, '%.2x') + ':';
      Writeln(l);
    finally
      // free memory allocated by cs_disasm()
      cs_free(insn, count);
    end
    else begin
      Writeln('****************');
      Writeln('Platform: ', Platforms[i].comment);
      print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
      Writeln('ERROR: Failed to disasm given code!');
      Abort;
    end;

    Writeln('');

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
