{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_tms320c64x                           }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_tms320c64x.c                   }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_tms320c64x;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.Tms320c64x, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
const
  s_condition_zero: array[Boolean] of string = (
    ' ', '!'
  );
  s_parallel: array[Boolean] of string = (
    'false', 'true'
  );
var
  i: Integer;
  tms320c64x: Pcs_tms320c64x;
  op: Pcs_tms320c64x_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  tms320c64x := @(ins.detail.tms320c64x);
  if tms320c64x.op_count > 0 then
    WriteLn(#9'op_count: ', tms320c64x.op_count);

  for i := 0 to tms320c64x.op_count - 1 do
  begin
    op := @(tms320c64x.operands[i]);
    case op.&type of
      TMS320C64X_OP_REG:
        WriteLn(#9#9, 'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      TMS320C64X_OP_IMM:
        WriteLn(#9#9, 'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm));
      TMS320C64X_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if op.detail.mem.base <> TMS320C64X_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        Write(#9#9#9'operands[', i, '].mem.disptype: ');
        case op.detail.mem.disptype of
          TMS320C64X_MEM_DISP_INVALID:
          begin
            WriteLn('Invalid');
            WriteLn(#9#9#9, 'operands[', i, '].mem.disp: ', op.detail.mem.disp);
          end;
          TMS320C64X_MEM_DISP_CONSTANT:
          begin
            WriteLn('Constant');
            WriteLn(#9#9#9, 'operands[', i, '].mem.disp: ', op.detail.mem.disp);
          end;
          TMS320C64X_MEM_DISP_REGISTER:
          begin
            WriteLn('Register');
            WriteLn(#9#9#9, 'operands[', i, '].mem.disp: ', cs_reg_name(handle, op.detail.mem.disp));
          end;
        end;
        WriteLn(#9#9#9, 'operands[', i, '].mem.unit: ', op.detail.mem.&unit);
        Write(#9#9#9'operands[', i, '].mem.direction: ');
        case op.detail.mem.direction of
          TMS320C64X_MEM_DIR_INVALID: WriteLn('Invalid');
          TMS320C64X_MEM_DIR_FW: WriteLn('Forward');
          TMS320C64X_MEM_DIR_BW: WriteLn('Backward');
        end;
        Write(#9#9#9'operands[', i, '].mem.modify: ');
        case op.detail.mem.modify of
          TMS320C64X_MEM_MOD_INVALID: WriteLn('Invalid');
          TMS320C64X_MEM_MOD_NO: WriteLn('No');
          TMS320C64X_MEM_MOD_PRE: WriteLn('Pre');
          TMS320C64X_MEM_MOD_POST: WriteLn('Post');
        end;
        WriteLn(#9#9#9, 'operands[', i, '].mem.scaled: ', op.detail.mem.scaled);
      end;
      TMS320C64X_OP_REGPAIR:
        WriteLn(#9#9, 'operands[', i, '].type: REGPAIR = ',
          cs_reg_name(handle, op.detail.reg + 1), ':', cs_reg_name(handle, op.detail.reg));
    end;
  end;

  Write(#9'Functional unit: ');
  case tms320c64x.funit.&unit of
    TMS320C64X_FUNIT_D: WriteLn('D', tms320c64x.funit.side);
    TMS320C64X_FUNIT_L: WriteLn('L', tms320c64x.funit.side);
    TMS320C64X_FUNIT_M: WriteLn('M', tms320c64x.funit.side);
    TMS320C64X_FUNIT_S: WriteLn('S', tms320c64x.funit.side);
    TMS320C64X_FUNIT_NO: WriteLn('No Functional Unit');
  else
    WriteLn('Unknown (Unit ', tms320c64x.funit.&unit, ', Side ', tms320c64x.funit.side, ')');
  end;
  if tms320c64x.funit.crosspath = 1 then
    WriteLn(#9'Crosspath: 1');

  if tms320c64x.condition.reg <> TMS320C64X_REG_INVALID then
    WriteLn(#9'Condition: [', s_condition_zero[tms320c64x.condition.zero = 1], cs_reg_name(handle, tms320c64x.condition.reg), ']');
  WriteLn(#9'Parallel: ', s_parallel[tms320c64x.parallel = 1]);

  WriteLn('');
end;

procedure Test;
const
  TMS320C64X_CODE: array[0..27] of Byte = (
    $01, $AC, $88, $40, $81, $AC, $88, $43, $00, $00, $00, $00, $02, $90, $32, $96,
    $02, $80, $46, $9E, $05, $3C, $83, $E6, $0B, $0C, $8B, $24
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_TMS320C64X; mode: CS_MODE_BIG_ENDIAN; code: @TMS320C64X_CODE; size: SizeOf(TMS320C64X_CODE); comment: 'TMS320C64x')
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
