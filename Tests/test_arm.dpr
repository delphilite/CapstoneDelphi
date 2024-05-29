program test_arm;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, test_utils, Capstone.Api, Capstone.Arm;

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
    WriteLnFormat(#9'op_count: %u', [arm.op_count]);

  for i := 0 to arm.op_count - 1 do
  begin
    op := @arm.operands[i];
    case Integer(op.&type) of
      ARM_OP_REG:
        WriteLnFormat(#9#9'operands[%d].type: REG = %s', [i, cs_reg_name(handle, op.detail.reg)]);
      ARM_OP_IMM:
        WriteLnFormat(#9#9'operands[%d].type: IMM = 0x%s', [i, format_string_hex(op.detail.imm, '%x')]);
      ARM_OP_FP:
{$IFDEF _KERNEL_MODE}
        // Issue #681: Windows kernel does not support formatting float point
        WriteLnFormat(#9#9'operands[%d].type: FP = <float_point_unsupported>', [i]);
{$ELSE}
        WriteLnFormat(#9#9'operands[%d].type: FP = %f', [i, op.detail.fp]);
{$ENDIF}
      ARM_OP_MEM_:
        begin
          WriteLnFormat(#9#9'operands[%d].type: MEM', [i]);
          if op.detail.mem.base <> ARM_REG_INVALID then
            WriteLnFormat(#9#9#9'operands[%d].mem.base: REG = %s', [i, cs_reg_name(handle, op.detail.mem.base)]);
          if op.detail.mem.index <> ARM_REG_INVALID then
            WriteLnFormat(#9#9#9'operands[%d].mem.index: REG = %s', [i, cs_reg_name(handle, op.detail.mem.index)]);
          if op.detail.mem.scale <> 1 then
            WriteLnFormat(#9#9#9'operands[%d].mem.scale: %u', [i, op.detail.mem.scale]);
          if op.detail.mem.disp <> 0 then
            WriteLnFormat(#9#9#9'operands[%d].mem.disp: 0x%s', [i, format_string_hex(op.detail.mem.disp, '%x')]);
          if op.detail.mem.lshift <> 0 then
            WriteLnFormat(#9#9#9'operands[%d].mem.lshift: 0x%s', [i, format_string_hex(op.detail.mem.lshift, '%x')]);
        end;
      ARM_OP_PIMM:
        WriteLnFormat(#9#9'operands[%d].type: P-IMM = %u', [i, op.detail.imm]);
      ARM_OP_CIMM:
        WriteLnFormat(#9#9'operands[%d].type: C-IMM = %u', [i, op.detail.imm]);
      ARM_OP_SETEND:
        if op.detail.setend = ARM_SETEND_BE then
          WriteLnFormat(#9#9'operands[%d].type: SETEND = %s', [i, 'be'])
        else WriteLnFormat(#9#9'operands[%d].type: SETEND = %s', [i, 'le']);
      ARM_OP_SYSREG:
        WriteLnFormat(#9#9'operands[%d].type: SYSREG = %u', [i, op.detail.reg]);
    end;

    if op.neon_lane <> -1 then
      WriteLnFormat(#9#9'operands[%d].neon_lane = %u', [i, op.neon_lane]);

    case op.access of
      CS_AC_READ:
        WriteLnFormat(#9#9'operands[%d].access: READ', [i]);
      CS_AC_WRITE:
        WriteLnFormat(#9#9'operands[%d].access: WRITE', [i]);
      CS_AC_READ or CS_AC_WRITE:
        WriteLnFormat(#9#9'operands[%d].access: READ | WRITE', [i]);
    end;

    if (op.shift.&type <> ARM_SFT_INVALID) and (op.shift.value <> 0) then
    begin
      if op.shift.&type < ARM_SFT_ASR_REG then
        // shift with constant value
        WriteLnFormat(#9#9#9'Shift: %u = %u', [op.shift.&type, op.shift.value])
      else
        // shift with register
        WriteLnFormat(#9#9#9'Shift: %u = %s', [op.shift.&type, cs_reg_name(handle, op.shift.value)]);
    end;

    if op.vector_index <> -1 then
      WriteLnFormat(#9#9'operands[%d].vector_index = %u', [i, op.vector_index]);

    if op.subtracted then
      WriteLn(#9#9'Subtracted: True');
  end;

  if (arm.cc <> ARM_CC_AL) and (arm.cc <> ARM_CC_INVALID) then
    WriteLnFormat(#9'Code condition: %u', [arm.cc]);

  if arm.update_flags then
    WriteLn(#9'Update-flags: True');

  if arm.writeback then
    WriteLn(#9'Write-back: True');

  if arm.cps_mode <> 0 then
    WriteLnFormat(#9'CPSI-mode: %u', [arm.cps_mode]);

  if arm.cps_flag <> 0 then
    WriteLnFormat(#9'CPSI-flag: %u', [arm.cps_flag]);

  if arm.vector_data <> 0 then
    WriteLnFormat(#9'Vector-data: %u', [arm.vector_data]);

  if arm.vector_size <> 0 then
    WriteLnFormat(#9'Vector-size: %u', [arm.vector_size]);

  if arm.usermode then
    WriteLn(#9'User-mode: True');

  if arm.mem_barrier <> 0 then
    WriteLnFormat(#9'Memory-barrier: %u', [arm.mem_barrier]);

  // Print out all registers accessed by this instruction (either implicit or explicit)
  if cs_regs_access(handle, ins, regs_read, @regs_read_count, regs_write, @regs_write_count) = 0 then
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

procedure test;
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
  Platforms: array [0..5] of TPlatform = (
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
      WriteLn('Failed on cs_open() with error returned: ', Ord(err));
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
        l := '0x' + format_string_hex(item.address);
        WriteLnFormat('%s:'#9'%s'#9'%s', [l, item.mnemonic, item.op_str]);
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

