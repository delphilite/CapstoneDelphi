{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_m68k                                 }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_m68k.c                         }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_m68k;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.M68K, test_utils;

procedure print_read_write_regs(handle: csh; detail: pcs_detail);
var
  i: Integer;
  reg_id: Word;
  reg_name: PAnsiChar;
begin
  for i := 0 to detail.regs_read_count - 1 do
  begin
    reg_id := detail.regs_read[i];
    reg_name := cs_reg_name(handle, reg_id);
    WriteLn(#9'reading from reg: ', reg_name);
  end;

  for i := 0 to detail.regs_write_count - 1 do
  begin
    reg_id := detail.regs_write[i];
    reg_name := cs_reg_name(handle, reg_id);
    WriteLn(#9'writing to reg:   ', reg_name);
  end;
end;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
const
  s_addressing_modes: array[0..18] of PAnsiChar = (
    '<invalid mode>',
    'Register Direct - Data',
    'Register Direct - Address',
    'Register Indirect - Address',
    'Register Indirect - Address with Postincrement',
    'Register Indirect - Address with Predecrement',
    'Register Indirect - Address with Displacement',
    'Address Register Indirect With Index - 8-bit displacement',
    'Address Register Indirect With Index - Base displacement',
    'Memory indirect - Postindex',
    'Memory indirect - Preindex',
    'Program Counter Indirect - with Displacement',
    'Program Counter Indirect with Index - with 8-Bit Displacement',
    'Program Counter Indirect with Index - with Base Displacement',
    'Program Counter Memory Indirect - Postindexed',
    'Program Counter Memory Indirect - Preindexed',
    'Absolute Data Addressing  - Short',
    'Absolute Data Addressing  - Long',
    'Immediate value'
  );
  s_index_size: array[Boolean] of string = (
    'w', 'l'
  );
var
  detail: pcs_detail;
  i: Integer;
  m68k: pcs_m68k;
  op: pcs_m68k_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  detail := ins.detail;
  m68k := @detail.m68k;
  if (m68k.op_count > 0) then
    WriteLn(#9'op_count: ', m68k.op_count);

  print_read_write_regs(handle, detail);

  WriteLn(#9'groups_count: ', detail.groups_count);

  for i := 0 to m68k.op_count - 1 do
  begin
    op := @m68k.operands[i];

    case op.type_ of
      M68K_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      M68K_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(Integer(op.detail.imm), '%4x'));
      M68K_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if (op.mem.base_reg <> M68K_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.mem.base_reg));
        if (op.mem.index_reg <> M68K_REG_INVALID) then
        begin
          WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op.mem.index_reg));
          WriteLn(#9#9#9'operands[', i, '].mem.index: size = ', s_index_size[op.mem.index_size <> 0]);
        end;
        if (op.mem.disp <> 0) then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.mem.disp, '%x'));
        if (op.mem.scale <> 0) then
          WriteLn(#9#9#9'operands[', i, '].mem.scale: ', op.mem.scale);

        WriteLn(#9#9'address mode: ', s_addressing_modes[op.address_mode]);
      end;
      M68K_OP_FP_SINGLE:
      begin
        WriteLn(#9#9'operands[', i, '].type: FP_SINGLE');
        WriteLn(#9#9#9'operands[', i, '].simm: ', Format('%.6f', [op.detail.simm]));
      end;
      M68K_OP_FP_DOUBLE:
      begin
        WriteLn(#9#9'operands[', i, '].type: FP_DOUBLE');
        WriteLn(#9#9#9'operands[', i, '].dimm: ', Format('%.6f', [op.detail.dimm]));
      end;
      M68K_OP_REG_BITS:
        WriteLn(#9#9'operands[', i, '].type: REG_BITS = $', format_string_hex(op.register_bits, '%x'));
      M68K_OP_REG_PAIR:
        WriteLn(#9#9'operands[', i, '].type: REG_PAIR = (', cs_reg_name(handle, op.detail.reg_pair.reg_0), ', ', cs_reg_name(handle, op.detail.reg_pair.reg_1), ')');
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  M68K_CODE: array[0..93] of Byte = (
    $f0, $10, $f0, $00, $48, $af, $ff, $ff, $7f, $ff, $11, $b0, $01, $37, $7f, $ff,
    $ff, $ff, $12, $34, $56, $78, $01, $33, $10, $10, $10, $10, $32, $32, $32, $32,
    $4c, $00, $54, $04, $48, $e7, $e0, $30, $4c, $df, $0c, $07, $d4, $40, $87, $5a,
    $4e, $71, $02, $b4, $c0, $de, $c0, $de, $5c, $00, $1d, $80, $71, $12, $01, $23,
    $f2, $3c, $44, $22, $40, $49, $0e, $56, $54, $c5, $f2, $3c, $44, $00, $44, $7a,
    $00, $00, $f2, $00, $0a, $28, $4e, $b9, $00, $00, $00, $12, $4e, $75
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_M68K; mode: CS_MODE_BIG_ENDIAN or CS_MODE_M68K_040; code: @M68K_CODE; size: SizeOf(M68K_CODE); comment: 'M68K')
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
