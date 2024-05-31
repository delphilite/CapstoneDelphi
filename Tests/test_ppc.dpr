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

program test_ppc;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.Ppc, test_utils;

function get_bc_name(bc: Integer): string;
begin
  case bc of
    PPC_BC_LT: Result := 'lt';
    PPC_BC_LE: Result := 'le';
    PPC_BC_EQ: Result := 'eq';
    PPC_BC_GE: Result := 'ge';
    PPC_BC_GT: Result := 'gt';
    PPC_BC_NE: Result := 'ne';
    PPC_BC_UN: Result := 'un';
    PPC_BC_NU: Result := 'nu';
    PPC_BC_SO: Result := 'so';
    PPC_BC_NS: Result := 'ns';
  else
    Result := 'invalid';
  end;
end;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  ppc: Pcs_ppc;
begin
  if ins^.detail = nil then
    Exit;

  ppc := @ins^.detail^.ppc;
  if ppc^.op_count > 0 then
    WriteLn(#9'op_count: ', ppc^.op_count);

  for i := 0 to ppc^.op_count - 1 do
  begin
    case ppc^.operands[i].&type of
      PPC_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, ppc^.operands[i].detail.reg));
      PPC_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(ppc^.operands[i].detail.imm, '%x'));
      PPC_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if ppc^.operands[i].detail.mem.base <> PPC_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, ppc^.operands[i].detail.mem.base));
        if ppc^.operands[i].detail.mem.disp <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(ppc^.operands[i].detail.mem.disp, '%x'));
      end;
      PPC_OP_CRX_:
      begin
        WriteLn(#9#9'operands[', i, '].type: CRX');
        WriteLn(#9#9#9'operands[', i, '].crx.scale: ', ppc^.operands[i].detail.crx.scale);
        WriteLn(#9#9#9'operands[', i, '].crx.reg: ', cs_reg_name(handle, ppc^.operands[i].detail.crx.reg));
        WriteLn(#9#9#9'operands[', i, '].crx.cond: ', get_bc_name(ppc^.operands[i].detail.crx.cond));
      end;
    end;
  end;

  if ppc^.bc <> 0 then
    WriteLn(#9'Branch code: ', ppc^.bc);

  if ppc^.bh <> 0 then
    WriteLn(#9'Branch hint: ', ppc^.bh);

  if ppc^.update_cr0 then
    WriteLn(#9'Update-CR0: True');

  WriteLn('');
end;

procedure Test;
const
  PPC_CODE: array[0..51] of Byte = (
    $43, $20, $0c, $07, $41, $56, $ff, $17, $80, $20, $00, $00, $80, $3f, $00, $00,
    $10, $43, $23, $0e, $d0, $44, $00, $80, $4c, $43, $22, $02, $2d, $03, $00, $80,
    $7c, $43, $20, $14, $7c, $43, $20, $93, $4f, $20, $00, $21, $4c, $c8, $00, $21,
    $40, $82, $00, $14
  );
  PPC_CODE2: array[0..11] of Byte = (
    $10, $60, $2a, $10, $10, $64, $28, $88, $7c, $4a, $5d, $0f
  );
const
  Platforms: array[0..1] of TPlatform = (
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE; size: SizeOf(PPC_CODE); comment: 'PPC-64'),
    (arch: CS_ARCH_PPC; mode: cs_mode(CS_MODE_BIG_ENDIAN or CS_MODE_QPX); code: @PPC_CODE2; size: SizeOf(PPC_CODE2); comment: 'PPC-64 + QPX')
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
