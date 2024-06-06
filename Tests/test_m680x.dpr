{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_m680x                                }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_m680x.c                        }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_m680x;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.M680X, test_utils;

procedure print_read_write_regs(handle: csh; detail: Pcs_detail);
var
  i: Integer;
begin
  if detail.regs_read_count > 0 then
  begin
    Write(#9'Registers read:');
    for i := 0 to detail.regs_read_count - 1 do
    begin
      Write(Format(' %s', [cs_reg_name(handle, detail.regs_read[i])]));
    end;
    WriteLn;
  end;

  if detail.regs_write_count > 0 then
  begin
    Write(#9'Registers modified:');
    for i := 0 to detail.regs_write_count - 1 do
    begin
      Write(Format(' %s', [cs_reg_name(handle, detail.regs_write[i])]));
    end;
    WriteLn;
  end;
end;

procedure print_insn_detail(handle: csh; insn: Pcs_insn);
const
  s_access: array[0..3] of string = (
    'UNCHANGED', 'READ', 'WRITE', 'READ | WRITE'
  );
  s_idx_flags: array[Boolean] of string = (
    'pre', 'post'
  );
  s_idx_inc_dec: array[Boolean] of string = (
    'decrement', 'increment'
  );
  s_op_ext_indirect: array[Boolean] of string = (
    '', 'INDIRECT'
  );
var
  detail: Pcs_detail;
  m680x: Pcs_m680x;
  i: Integer;
  op: Pcs_m680x_op;
  comment: PAnsiChar;
begin
  detail := insn.detail;
  if detail = nil then
    Exit;

  m680x := @detail.m680x;

  if m680x.op_count > 0 then
    WriteLn(#9'op_count: ', m680x.op_count);

  for i := 0 to m680x.op_count - 1 do
  begin
    op := @m680x.operands[i];
    comment := '';

    case op.type_ of
      M680X_OP_REGISTER:
      begin
        if ((i = 0) and ((m680x.flags and M680X_FIRST_OP_IN_MNEM) <> 0)) or
           ((i = 1) and ((m680x.flags and M680X_SECOND_OP_IN_MNEM) <> 0)) then
          comment := ' (in mnemonic)';

        WriteLn(#9#9'operands[', i, '].type: REGISTER = ', cs_reg_name(handle, op.detail.reg), AnsiString(comment));
      end;
      M680X_OP_CONSTANT:
        WriteLn(#9#9'operands[', i, '].type: CONSTANT = ', op.detail.const_val);
      M680X_OP_IMMEDIATE:
        WriteLn(#9#9'operands[', i, '].type: IMMEDIATE = #', op.detail.imm);
      M680X_OP_DIRECT:
        WriteLn(#9#9'operands[', i, '].type: DIRECT = 0x', format_string_hex(op.detail.direct_addr, '%.2x'));
      M680X_OP_EXTENDED:
        WriteLn(#9#9'operands[', i, '].type: EXTENDED ', s_op_ext_indirect[op.detail.ext.indirect], ' = 0x', format_string_hex(op.detail.ext.address, '%4x'));
      M680X_OP_RELATIVE:
        WriteLn(#9#9'operands[', i, '].type: RELATIVE = 0x', format_string_hex(op.detail.rel.address, '%.4x'));
      M680X_OP_INDEXED:
      begin
        if op.detail.idx.flags and M680X_IDX_INDIRECT <> 0 then
          WriteLn(#9#9'operands[', i, '].type: INDEXED INDIRECT')
        else WriteLn(#9#9'operands[', i, '].type: INDEXED');

        if op.detail.idx.base_reg <> M680X_REG_INVALID then
          WriteLn(#9#9#9'base register: ', cs_reg_name(handle, op.detail.idx.base_reg));

        if op.detail.idx.offset_reg <> M680X_REG_INVALID then
          WriteLn(#9#9#9'offset register: ', cs_reg_name(handle, op.detail.idx.offset_reg));

        if (op.detail.idx.offset_bits <> 0) and (op.detail.idx.offset_reg = M680X_REG_INVALID) and (op.detail.idx.inc_dec = 0) then
        begin
          WriteLn(#9#9#9'offset: ', op.detail.idx.offset);

          if op.detail.idx.base_reg = M680X_REG_PC then
            WriteLn(#9#9#9'offset address: 0x', format_string_hex(op.detail.idx.offset_addr, '%x'));

          WriteLn(#9#9#9'offset bits: ', op.detail.idx.offset_bits);
        end;

        if op.detail.idx.inc_dec <> 0 then
        begin
          WriteLn(#9#9#9, s_idx_flags[op.detail.idx.flags and M680X_IDX_POST_INC_DEC <> 0], ' ',
            s_idx_inc_dec[op.detail.idx.inc_dec > 0], ': ', abs(op.detail.idx.inc_dec));
        end;
      end;
    end;

    if op.size <> 0 then
      WriteLn(#9#9#9'size: ', op.size);

    if op.access <> CS_AC_INVALID then
      WriteLn(#9#9#9'access: ', s_access[op.access]);
  end;

  print_read_write_regs(handle, detail);

  if detail.groups_count > 0 then
    WriteLn(#9'groups_count: ', detail.groups_count);

  WriteLn;
end;

procedure Test;
const
  M6800_CODE: array[0..15] of Byte = (
    $01, $09, $36, $64, $7F, $74, $10, $00, $90, $10, $A4, $10, $B6, $10, $00, $39
  );
  M6801_CODE: array[0..11] of Byte = (
    $04, $05, $3C, $3D, $38, $93, $10, $EC, $10, $ED, $10, $39
  );
  M6805_CODE: array[0..28] of Byte = (
    $04, $7F, $00, $17, $22, $28, $00, $2E, $00, $40, $42, $5A, $70, $8E, $97, $9C,
    $A0, $15, $AD, $00, $C3, $10, $00, $DA, $12, $34, $E5, $7F, $FE
  );
  M6808_CODE: array[0..46] of Byte = (
    $31, $22, $00, $35, $22, $45, $10, $00, $4B, $00, $51, $10, $52, $5E, $22, $62,
    $65, $12, $34, $72, $84, $85, $86, $87, $8A, $8B, $8C, $94, $95, $A7, $10, $AF,
    $10, $9E, $60, $7F, $9E, $6B, $7F, $00, $9E, $D6, $10, $00, $9E, $E6, $7F
  );
  HCS08_CODE: array[0..27] of Byte = (
    $32, $10, $00, $9E, $AE, $9E, $CE, $7F, $9E, $BE, $10, $00, $9E, $FE, $7F,
    $3E, $10, $00, $9E, $F3, $7F, $96, $10, $00, $9E, $FF, $7F, $82
  );
  M6811_CODE: array[0..57] of Byte = (
    $02, $03, $12, $7F, $10, $00, $13, $99, $08, $00, $14, $7F, $02, $15, $7F, $01,
    $1E, $7F, $20, $00, $8F, $CF, $18, $08, $18, $30, $18, $3C, $18, $67, $18, $8C,
    $10, $00, $18, $8F, $18, $CE, $10, $00, $18, $FF, $10, $00, $1A, $A3, $7F, $1A,
    $AC, $1A, $EE, $7F, $1A, $EF, $7F, $CD, $AC, $7F
  );
  CPU12_CODE: array[0..72] of Byte = (
    $00, $04, $01, $00, $0C, $00, $80, $0E, $00, $80, $00, $11, $1E, $10, $00, $80,
    $00, $3B, $4A, $10, $00, $04, $4B, $01, $04, $4F, $7F, $80, $00, $8F, $10, $00,
    $B7, $52, $B7, $B1, $A6, $67, $A6, $FE, $A6, $F7, $18, $02, $E2, $30, $39, $E2,
    $10, $00, $18, $0C, $30, $39, $10, $00, $18, $11, $18, $12, $10, $00, $18, $19,
    $00, $18, $1E, $00, $18, $3E, $18, $3F, $00
  );
  HD6301_CODE: array[0..9] of Byte = (
    $6B, $10, $00, $71, $10, $00, $72, $10, $10, $39
  );
  M6809_CODE: array[0..120] of Byte = (
    $06, $10, $19, $1A, $55, $1E, $01, $23, $E9, $31, $06, $34, $55, $A6, $81, $A7,
    $89, $7F, $FF, $A6, $9D, $10, $00, $A7, $91, $A6, $9F, $10, $00, $11, $AC, $99,
    $10, $00, $39, $A6, $07, $A6, $27, $A6, $47, $A6, $67, $A6, $0F, $A6, $10, $A6,
    $80, $A6, $81, $A6, $82, $A6, $83, $A6, $84, $A6, $85, $A6, $86, $A6, $88, $7F,
    $A6, $88, $80, $A6, $89, $7F, $FF, $A6, $89, $80, $00, $A6, $8B, $A6, $8C, $10,
    $A6, $8D, $10, $00, $A6, $91, $A6, $93, $A6, $94, $A6, $95, $A6, $96, $A6, $98,
    $7F, $A6, $98, $80, $A6, $99, $7F, $FF, $A6, $99, $80, $00, $A6, $9B, $A6, $9C,
    $10, $A6, $9D, $10, $00, $A6, $9F, $10, $00
  );
  HD6309_CODE: array[0..56] of Byte = (
    $01, $10, $10, $62, $10, $10, $7B, $10, $10, $00, $CD, $49, $96, $02, $D2, $10,
    $30, $23, $10, $38, $10, $3B, $10, $53, $10, $5D, $11, $30, $43, $10, $11, $37,
    $25, $10, $11, $38, $12, $11, $39, $23, $11, $3B, $34, $11, $8E, $10, $00, $11,
    $AF, $10, $11, $AB, $10, $11, $F6, $80, $00
  );
const
  Platforms: array[0..9] of TPlatform = (
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6301; code: @HD6301_CODE; size: SizeOf(HD6301_CODE); comment: 'M680X_HD6301'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6309; code: @HD6309_CODE; size: SizeOf(HD6309_CODE); comment: 'M680X_HD6309'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6800; code: @M6800_CODE; size: SizeOf(M6800_CODE); comment: 'M680X_M6800'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6801; code: @M6801_CODE; size: SizeOf(M6801_CODE); comment: 'M680X_M6801'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6805; code: @M6805_CODE; size: SizeOf(M6805_CODE); comment: 'M680X_M68HC05'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6808; code: @M6808_CODE; size: SizeOf(M6808_CODE); comment: 'M680X_M68HC08'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6809; code: @M6809_CODE; size: SizeOf(M6809_CODE); comment: 'M680X_M6809'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6811; code: @M6811_CODE; size: SizeOf(M6811_CODE); comment: 'M680X_M68HC11'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_CPU12; code: @CPU12_CODE; size: SizeOf(CPU12_CODE); comment: 'M680X_CPU12'),
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_HCS08; code: @HCS08_CODE; size: SizeOf(HCS08_CODE); comment: 'M680X_HCS08')
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
        l := '0x' + format_string_hex(item.address) + ': ';
        l := l + format_buffer_short(@item.bytes, item.size);
        l := l + format_nine_spaces(nine_spaces, 1 + ((5 - item.size) * 2));
        l := l + string(item.mnemonic);
        l := l + format_nine_spaces(nine_spaces, 1 + (5 - strlen(item.mnemonic)));
        l := l + string(item.op_str);
        WriteLn(l);
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
