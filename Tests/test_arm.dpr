{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_arm                                  }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_arm.c                          }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_arm;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Arm, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  arm: Pcs_arm;
  i: Integer;
  l: string;
  regs_read, regs_write: cs_regs;
  regs_read_count, regs_write_count: Byte;
  op: Pcs_arm_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins.detail = nil then
    Exit;

  arm := @ins.detail.arm;

  if arm.op_count > 0 then
    WriteLn(#9'op_count: ', arm.op_count);

  for i := 0 to arm.op_count - 1 do
  begin
    op := @arm.operands[i];
    case op.type_ of
      ARM_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op.detail.reg));
      ARM_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      ARM_OP_FP:
{$IFDEF _KERNEL_MODE}
        // Issue #681: Windows kernel does not support formatting float point
        WriteLn(#9#9'operands[', i, '].type: FP = <float_point_unsupported>');
{$ELSE}
        WriteLn(#9#9'operands[', i, '].type: FP = ', op.detail.fp);
{$ENDIF}
      ARM_OP_MEM_:
        begin
          WriteLn(#9#9'operands[', i, '].type: MEM');
          if op.detail.mem.base <> ARM_REG_INVALID then
            WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
          if op.detail.mem.index <> ARM_REG_INVALID then
            WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op.detail.mem.index));
          if op.detail.mem.scale <> 1 then
            WriteLn(#9#9#9'operands[', i, '].mem.scale: ', op.detail.mem.scale);
          if op.detail.mem.disp <> 0 then
            WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp, '%x'));
          if op.detail.mem.lshift <> 0 then
            WriteLn(#9#9#9'operands[', i, '].mem.lshift: 0x', format_string_hex(op.detail.mem.lshift, '%x'));
        end;
      ARM_OP_PIMM:
        WriteLn(#9#9'operands[', i, '].type: P-IMM = ', op.detail.imm);
      ARM_OP_CIMM:
        WriteLn(#9#9'operands[', i, '].type: C-IMM = ', op.detail.imm);
      ARM_OP_SETEND:
        if op.detail.setend = ARM_SETEND_BE then
          WriteLn(#9#9'operands[', i, '].type: SETEND = be')
        else WriteLn(#9#9'operands[', i, '].type: SETEND = le');
      ARM_OP_SYSREG:
        WriteLn(#9#9'operands[', i, '].type: SYSREG = ', op.detail.reg);
    end;

    if op.neon_lane <> -1 then
      WriteLn(#9#9'operands[', i, '].neon_lane = ', op.neon_lane);

    case op.access of
      CS_AC_READ:
        WriteLn(#9#9'operands[', i, '].access: READ');
      CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: WRITE');
      CS_AC_READ or CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: READ | WRITE');
    end;

    if (op.shift.type_ <> ARM_SFT_INVALID) and (op.shift.value <> 0) then
    begin
      if op.shift.type_ < ARM_SFT_ASR_REG then
        // shift with constant value
        WriteLn(#9#9#9'Shift: ', op.shift.type_, ' = ', op.shift.value)
      else
        // shift with register
        WriteLn(#9#9#9'Shift: ', op.shift.type_, ' = ', cs_reg_name(handle, op.shift.value));
    end;

    if op.vector_index <> -1 then
      WriteLn(#9#9'operands[', i, '].vector_index = ', op.vector_index);

    if op.subtracted then
      WriteLn(#9#9'Subtracted: True');
  end;

  if (arm.cc <> ARM_CC_AL) and (arm.cc <> ARM_CC_INVALID) then
    WriteLn(#9'Code condition: ', arm.cc);

  if arm.update_flags then
    WriteLn(#9'Update-flags: True');

  if arm.writeback then
    WriteLn(#9'Write-back: True');

  if arm.cps_mode <> 0 then
    WriteLn(#9'CPSI-mode: ', arm.cps_mode);

  if arm.cps_flag <> 0 then
    WriteLn(#9'CPSI-flag: ', arm.cps_flag);

  if arm.vector_data <> 0 then
    WriteLn(#9'Vector-data: ', arm.vector_data);

  if arm.vector_size <> 0 then
    WriteLn(#9'Vector-size: ', arm.vector_size);

  if arm.usermode then
    WriteLn(#9'User-mode: True');

  if arm.mem_barrier <> 0 then
    WriteLn(#9'Memory-barrier: ', arm.mem_barrier);

  // Print out all registers accessed by this instruction (either implicit or explicit)
  if cs_regs_access(handle, ins, regs_read, regs_read_count, regs_write, regs_write_count) = 0 then
  begin
    if regs_read_count > 0 then
    begin
      l := #9'Registers read:';
      for i := 0 to regs_read_count - 1 do
      begin
        l := l + ' ' + string(cs_reg_name(handle, regs_read[i]));
      end;
      WriteLn(l);
    end;

    if regs_write_count > 0 then
    begin
      l := #9'Registers modified:';
      for i := 0 to regs_write_count - 1 do
      begin
        l := l + ' ' + string(cs_reg_name(handle, regs_write[i]));
      end;
      WriteLn(l);
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  ARM_CODE: array[0..51] of Byte = (
    $86, $48, $60, $F4, $4D, $0F, $E2, $F4, $ED, $FF, $FF, $EB, $04, $E0, $2D, $E5,
    $00, $00, $00, $00, $E0, $83, $22, $E5, $F1, $02, $03, $0E, $00, $00, $A0, $E3,
    $02, $30, $C1, $E7, $00, $00, $53, $E3, $00, $02, $01, $F1, $05, $40, $D0, $E8,
    $F4, $80, $00, $00
  );
  ARM_CODE2: array[0..19] of Byte = (
    $D1, $E8, $00, $F0, $F0, $24, $04, $07, $1F, $3C, $F2, $C0, $00, $00, $4F, $F0,
    $00, $01, $46, $6C
  );
  THUMB_CODE: array[0..31] of Byte = (
    $60, $F9, $1F, $04, $E0, $F9, $4F, $07, $70, $47, $00, $F0, $10, $E8, $EB, $46,
    $83, $B0, $C9, $68, $1F, $B1, $30, $BF, $AF, $F3, $20, $84, $52, $F8, $23, $F0
  );
  THUMB_CODE2: array[0..35] of Byte = (
    $4F, $F0, $00, $01, $BD, $E8, $00, $88, $D1, $E8, $00, $F0, $18, $BF, $AD, $BF,
    $F3, $FF, $0B, $0C, $86, $F3, $00, $89, $80, $F3, $00, $8C, $4F, $FA, $99, $F6,
    $D0, $FF, $A2, $01
  );
  THUMB_MCLASS: array[0..3] of Byte = (
    $EF, $F3, $02, $80
  );
  ARMV8: array[0..11] of Byte = (
    $E0, $3B, $B2, $EE, $42, $00, $01, $E1, $51, $F0, $7F, $F5
  );
const
  Platforms: array[0..5] of TPlatform = (
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE; size: SizeOf(ARM_CODE); comment: 'ARM'; syntax: 0),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE; size: SizeOf(THUMB_CODE); comment: 'Thumb'; syntax: 0),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @ARM_CODE2; size: SizeOf(ARM_CODE2); comment: 'Thumb-mixed'; syntax: 0),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE2; size: SizeOf(THUMB_CODE2); comment: 'Thumb-2 & register named with numbers'; syntax: CS_OPT_SYNTAX_NOREGNAME),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB + CS_MODE_MCLASS; code: @THUMB_MCLASS; size: SizeOf(THUMB_MCLASS); comment: 'Thumb-MClass'; syntax: 0),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM + CS_MODE_V8; code: @ARMV8; size: SizeOf(ARMV8); comment: 'Arm-V8'; syntax: 0)
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
    address := $80001000;
    err := cs_open(Platforms[i].arch, Platforms[i].mode, handle);
    if err <> CS_ERR_OK then
    begin
      WriteLn('Failed on cs_open() with error returned: ', err);
      Abort;
    end;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    if Platforms[i].syntax <> 0 then
      cs_option(handle, CS_OPT_SYNTAX, Platforms[i].syntax);

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
