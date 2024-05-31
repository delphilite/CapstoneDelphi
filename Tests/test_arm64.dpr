{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_arm64                                }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_arm64.c                        }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_arm64;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.Arm64, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  arm64: Pcs_arm64;
  i: Integer;
  l: string;
  regs_read, regs_write: cs_regs;
  regs_read_count, regs_write_count: Byte;
  access: Byte;
begin
  // detail can be NULL if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  arm64 := @(ins.detail.arm64);
  if (arm64.op_count <> 0) then
    WriteLn(#9'op_count: ', arm64.op_count);

  for i := 0 to arm64.op_count - 1 do
  begin
    case arm64.operands[i].&type of
      ARM64_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, arm64.operands[i].detail.reg));
      ARM64_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(arm64.operands[i].detail.imm, '%x'));
      ARM64_OP_FP:
{$IFDEF _KERNEL_MODE}
        // Issue #681: Windows kernel does not support formatting float point
        WriteLn(#9#9'operands[', i, '].type: FP = <float_point_unsupported>');
{$ELSE}
        WriteLn(#9#9'operands[', i, '].type: FP = ', arm64.operands[i].detail.fp);
{$ENDIF}
      ARM64_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if (arm64.operands[i].detail.mem.base <> ARM64_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, arm64.operands[i].detail.mem.base));
        if (arm64.operands[i].detail.mem.index <> ARM64_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, arm64.operands[i].detail.mem.index));
        if (arm64.operands[i].detail.mem.disp <> 0) then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(arm64.operands[i].detail.mem.disp, '%x'));
      end;
      ARM64_OP_CIMM:
        WriteLn(#9#9'operands[', i, '].type: C-IMM = ', arm64.operands[i].detail.imm);
      ARM64_OP_REG_MRS:
        WriteLn(#9#9'operands[', i, '].type: REG_MRS = 0x', format_string_hex(arm64.operands[i].detail.reg, '%x'));
      ARM64_OP_REG_MSR:
        WriteLn(#9#9'operands[', i, '].type: REG_MSR = 0x', format_string_hex(arm64.operands[i].detail.reg, '%x'));
      ARM64_OP_PSTATE:
        WriteLn(#9#9'operands[', i, '].type: PSTATE = 0x', format_string_hex(arm64.operands[i].detail.pstate, '%x'));
      ARM64_OP_SYS:
        WriteLn(#9#9'operands[', i, '].type: SYS = 0x', format_string_hex(arm64.operands[i].detail.sys, '%x'));
      ARM64_OP_PREFETCH:
        WriteLn(#9#9'operands[', i, '].type: PREFETCH = 0x', format_string_hex(arm64.operands[i].detail.prefetch, '%x'));
      ARM64_OP_BARRIER:
        WriteLn(#9#9'operands[', i, '].type: BARRIER = 0x', format_string_hex(arm64.operands[i].detail.barrier, '%x'));
    end;

    access := arm64.operands[i].access;
    case access of
      CS_AC_READ:
        WriteLn(#9#9'operands[', i, '].access: READ');
      CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: WRITE');
      CS_AC_READ or CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: READ | WRITE');
    end;

    if (arm64.operands[i].shift.&type <> ARM64_SFT_INVALID) and (arm64.operands[i].shift.value <> 0) then
      WriteLn(#9#9#9'Shift: type = ', arm64.operands[i].shift.&type, ', value = ', arm64.operands[i].shift.value);

    if (arm64.operands[i].ext <> ARM64_EXT_INVALID) then
      WriteLn(#9#9#9'Ext: ', arm64.operands[i].ext);

    if (arm64.operands[i].vas <> ARM64_VAS_INVALID) then
      WriteLn(#9#9#9'Vector Arrangement Specifier: 0x', format_string_hex(arm64.operands[i].vas, '%x'));

    if (arm64.operands[i].vess <> ARM64_VESS_INVALID) then
      WriteLn(#9#9#9'Vector Element Size Specifier: ', arm64.operands[i].vess);

    if (arm64.operands[i].vector_index <> -1) then
      WriteLn(#9#9#9'Vector Index: ', arm64.operands[i].vector_index);
  end;

  if (arm64.update_flags) then
    WriteLn(#9'Update-flags: True');

  if (arm64.writeback) then
    WriteLn(#9'Write-back: True');

  if (arm64.cc <> 0) then
    WriteLn(#9'Code-condition: ', arm64.cc);

  // Print out all registers accessed by this instruction (either implicit or explicit)
  if cs_regs_access(handle, ins, regs_read, @regs_read_count, regs_write, @regs_write_count) = CS_ERR_OK then
  begin
    if (regs_read_count <> 0) then
    begin
      l := #9'Registers read:';
      for i := 0 to regs_read_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_read[i]));
      WriteLn(l);
    end;

    if (regs_write_count <> 0) then
    begin
      l := #9'Registers modified:';
      for i := 0 to regs_write_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_write[i]));
      WriteLn(l);
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  ARM64_CODE: array[0..67] of Byte = (
    $09, $00, $38, $D5, $BF, $40, $00, $D5, $0C, $05, $13, $D5, $20, $50, $02, $0E,
    $20, $E4, $3D, $0F, $00, $18, $A0, $5F, $A2, $00, $AE, $9E, $9F, $37, $03, $D5,
    $BF, $33, $03, $D5, $DF, $3F, $03, $D5, $21, $7C, $02, $9B, $21, $7C, $00, $53,
    $00, $40, $21, $4B, $E1, $0B, $40, $B9, $20, $04, $81, $DA, $20, $08, $02, $8B,
    $10, $5B, $E8, $3C
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_ARM64; mode: CS_MODE_ARM; code: @ARM64_CODE; size: SizeOf(ARM64_CODE); comment: 'ARM-64')
  );
var
  handle: csh;
  address: UInt64;
  insn, item: Pcs_insn;
  i, j: Integer;
  count: Integer;
  err: cs_err;
begin
  for i := Low(Platforms) to High(Platforms) do
  begin
    address := $2c;
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
        WriteLn('0x', format_string_hex(item.address), ':'#9, item.mnemonic, #9, item.op_str);
        print_insn_detail(handle, item);
        if j < count - 1 then
          Inc(item);
      end;
      WriteLn('0x', format_string_hex(item.address + item.size, '%.2x'), ':');
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
