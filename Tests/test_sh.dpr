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

program test_sh;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.SH, test_utils;

procedure print_read_write_regs(handle: csh; detail: pcs_detail);
var
  i: Integer;
begin
  if (detail.regs_read_count > 0) then
  begin
    Write(#9'Registers read:');
    for i := 0 to detail.regs_read_count - 1 do
      Write(' ', cs_reg_name(handle, detail.regs_read[i]));
    WriteLn;
  end;

  if (detail.regs_write_count > 0) then
  begin
    Write(#9'Registers modified:');
    for i := 0 to detail.regs_write_count - 1 do
      Write(' ', cs_reg_name(handle, detail.regs_write[i]));
    WriteLn;
  end;
end;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
const
  reg_address_msg: array[0..2] of string = (
    'Register indirect',
    'Register indirect with predecrement',
    'Register indirect with postincrement'
  );
var
  i: Integer;
  l: string;
  sh: Pcs_sh;
  op: Pcs_sh_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  sh := @ins.detail.sh;

  if (sh.op_count <> 0) then
    WriteLn(#9'op_count: ', sh.op_count);

  for i := 0 to sh.op_count - 1 do
  begin
    op := @sh.operands[i];
    case op.type_ of
      SH_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REGISTER = ', cs_reg_name(handle, op.detail.reg));
      SH_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMMEDIATE = #', op.detail.imm);
      SH_OP_MEM_:
      begin
        Write(#9#9'operands[', i, '].type: MEM ');
        case op.detail.mem.address of
          SH_OP_MEM_REG_IND, SH_OP_MEM_REG_POST, SH_OP_MEM_REG_PRE:
          begin
            l := reg_address_msg[op.detail.mem.address - SH_OP_MEM_REG_IND];
            WriteLn(l, ' REG ', cs_reg_name(handle, op.detail.mem.reg));
          end;
          SH_OP_MEM_REG_DISP:
            WriteLn('Register indirect with displacement REG ', cs_reg_name(handle, op.detail.mem.reg), ', DISP ', op.detail.mem.disp);
          SH_OP_MEM_REG_R0:
            WriteLn('R0 indexed');
          SH_OP_MEM_GBR_DISP:
            WriteLn('GBR base with displacement DISP ', op.detail.mem.disp);
          SH_OP_MEM_GBR_R0:
            WriteLn('GBR base with R0 indexed');
          SH_OP_MEM_PCR:
            WriteLn('PC relative Address=0x', format_string_hex(op.detail.mem.disp, '%x'));
          SH_OP_MEM_TBR_DISP:
            WriteLn('TBR base with displacement DISP ', op.detail.mem.disp);
          SH_OP_MEM_INVALID:
            ;
        end;
      end;
    end;
    if (sh.size <> 0) then
      WriteLn(#9#9#9'size: ', sh.size);
  end;

  print_read_write_regs(handle, ins.detail);

  if (ins.detail.groups_count <> 0) then
    WriteLn(#9'groups_count: ', ins.detail.groups_count);

  WriteLn('');
end;

procedure Test;
const
  SH4A_CODE: array[0..39] of Byte = (
    $0c, $31, $10, $20, $22, $21, $36, $64, $46, $25, $12, $12, $1c, $02, $08, $c1,
    $05, $c7, $0c, $71, $1f, $02, $22, $cf, $06, $89, $23, $00, $2b, $41, $0b, $00, $0e,
    $40, $32, $00, $0a, $f1, $09, $00
  );
  SH2A_CODE: array[0..7] of Byte = (
    $32, $11, $92, $00, $32, $49, $31, $00
  );
const
  Platforms: array[0..1] of TPlatform = (
    (arch: CS_ARCH_SH; mode: CS_MODE_SH4A or CS_MODE_SHFPU; code: @SH4A_CODE; size: SizeOf(SH4A_CODE); comment: 'SH_SH4A'),
    (arch: CS_ARCH_SH; mode: CS_MODE_SH2A or CS_MODE_SHFPU or CS_MODE_BIG_ENDIAN; code: @SH2A_CODE; size: SizeOf(SH2A_CODE); comment: 'SH_SH2A')
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
    address := $80000000;
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
