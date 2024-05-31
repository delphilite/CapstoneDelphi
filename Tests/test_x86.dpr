{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_x86                                  }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_x86.c                          }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_x86;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, Capstone.Api, Capstone.X86, test_utils;

function get_eflag_name(const flag: UInt64): string;
type
  TFlagName = record
    Flag: UInt64;
    Name: string;
  end;
const
  EFlagNames: array[0..45] of TFlagName = (
    (Flag: X86_EFLAGS_UNDEFINED_OF; Name: 'UNDEF_OF'),
    (Flag: X86_EFLAGS_UNDEFINED_SF; Name: 'UNDEF_SF'),
    (Flag: X86_EFLAGS_UNDEFINED_ZF; Name: 'UNDEF_ZF'),
    (Flag: X86_EFLAGS_MODIFY_AF; Name: 'MOD_AF'),
    (Flag: X86_EFLAGS_UNDEFINED_PF; Name: 'UNDEF_PF'),
    (Flag: X86_EFLAGS_MODIFY_CF; Name: 'MOD_CF'),
    (Flag: X86_EFLAGS_MODIFY_SF; Name: 'MOD_SF'),
    (Flag: X86_EFLAGS_MODIFY_ZF; Name: 'MOD_ZF'),
    (Flag: X86_EFLAGS_UNDEFINED_AF; Name: 'UNDEF_AF'),
    (Flag: X86_EFLAGS_MODIFY_PF; Name: 'MOD_PF'),
    (Flag: X86_EFLAGS_UNDEFINED_CF; Name: 'UNDEF_CF'),
    (Flag: X86_EFLAGS_MODIFY_OF; Name: 'MOD_OF'),
    (Flag: X86_EFLAGS_RESET_OF; Name: 'RESET_OF'),
    (Flag: X86_EFLAGS_RESET_CF; Name: 'RESET_CF'),
    (Flag: X86_EFLAGS_RESET_DF; Name: 'RESET_DF'),
    (Flag: X86_EFLAGS_RESET_IF; Name: 'RESET_IF'),
    (Flag: X86_EFLAGS_TEST_OF; Name: 'TEST_OF'),
    (Flag: X86_EFLAGS_TEST_SF; Name: 'TEST_SF'),
    (Flag: X86_EFLAGS_TEST_ZF; Name: 'TEST_ZF'),
    (Flag: X86_EFLAGS_TEST_PF; Name: 'TEST_PF'),
    (Flag: X86_EFLAGS_TEST_CF; Name: 'TEST_CF'),
    (Flag: X86_EFLAGS_RESET_SF; Name: 'RESET_SF'),
    (Flag: X86_EFLAGS_RESET_AF; Name: 'RESET_AF'),
    (Flag: X86_EFLAGS_RESET_TF; Name: 'RESET_TF'),
    (Flag: X86_EFLAGS_RESET_NT; Name: 'RESET_NT'),
    (Flag: X86_EFLAGS_PRIOR_OF; Name: 'PRIOR_OF'),
    (Flag: X86_EFLAGS_PRIOR_SF; Name: 'PRIOR_SF'),
    (Flag: X86_EFLAGS_PRIOR_ZF; Name: 'PRIOR_ZF'),
    (Flag: X86_EFLAGS_PRIOR_AF; Name: 'PRIOR_AF'),
    (Flag: X86_EFLAGS_PRIOR_PF; Name: 'PRIOR_PF'),
    (Flag: X86_EFLAGS_PRIOR_CF; Name: 'PRIOR_CF'),
    (Flag: X86_EFLAGS_PRIOR_TF; Name: 'PRIOR_TF'),
    (Flag: X86_EFLAGS_PRIOR_IF; Name: 'PRIOR_IF'),
    (Flag: X86_EFLAGS_PRIOR_DF; Name: 'PRIOR_DF'),
    (Flag: X86_EFLAGS_TEST_NT; Name: 'TEST_NT'),
    (Flag: X86_EFLAGS_TEST_DF; Name: 'TEST_DF'),
    (Flag: X86_EFLAGS_RESET_PF; Name: 'RESET_PF'),
    (Flag: X86_EFLAGS_PRIOR_NT; Name: 'PRIOR_NT'),
    (Flag: X86_EFLAGS_MODIFY_TF; Name: 'MOD_TF'),
    (Flag: X86_EFLAGS_MODIFY_IF; Name: 'MOD_IF'),
    (Flag: X86_EFLAGS_MODIFY_DF; Name: 'MOD_DF'),
    (Flag: X86_EFLAGS_MODIFY_NT; Name: 'MOD_NT'),
    (Flag: X86_EFLAGS_MODIFY_RF; Name: 'MOD_RF'),
    (Flag: X86_EFLAGS_SET_CF; Name: 'SET_CF'),
    (Flag: X86_EFLAGS_SET_DF; Name: 'SET_DF'),
    (Flag: X86_EFLAGS_SET_IF; Name: 'SET_IF')
  );
var
  i: Integer;
begin
  for i := Low(EFlagNames) to High(EFlagNames) do
  begin
    if EFlagNames[i].Flag = flag then
    begin
      Result := EFlagNames[i].Name;
      Exit;
    end;
  end;
  Result := '';
end;

function get_eflag_names(const flags: UInt64): string;
var
  i: Integer;
  f: UInt64;
begin
  Result := '';
  f := 1;
  for i := 0 to 63 do
  begin
    if flags and f <> 0 then
      Result := Result + ' ' + get_eflag_name(f);
    f := f shl 1;
  end;
end;

function get_fpu_flag_name(const flag: UInt64): string;
type
  TFlagName = record
    Flag: UInt64;
    Name: string;
  end;
const
  EFlagNames: array[0..19] of TFlagName = (
    (Flag: X86_FPU_FLAGS_MODIFY_C0; Name: 'MOD_C0'),
    (Flag: X86_FPU_FLAGS_MODIFY_C1; Name: 'MOD_C1'),
    (Flag: X86_FPU_FLAGS_MODIFY_C2; Name: 'MOD_C2'),
    (Flag: X86_FPU_FLAGS_MODIFY_C3; Name: 'MOD_C3'),
    (Flag: X86_FPU_FLAGS_RESET_C0; Name: 'RESET_C0'),
    (Flag: X86_FPU_FLAGS_RESET_C1; Name: 'RESET_C1'),
    (Flag: X86_FPU_FLAGS_RESET_C2; Name: 'RESET_C2'),
    (Flag: X86_FPU_FLAGS_RESET_C3; Name: 'RESET_C3'),
    (Flag: X86_FPU_FLAGS_SET_C0; Name: 'SET_C0'),
    (Flag: X86_FPU_FLAGS_SET_C1; Name: 'SET_C1'),
    (Flag: X86_FPU_FLAGS_SET_C2; Name: 'SET_C2'),
    (Flag: X86_FPU_FLAGS_SET_C3; Name: 'SET_C3'),
    (Flag: X86_FPU_FLAGS_UNDEFINED_C0; Name: 'UNDEF_C0'),
    (Flag: X86_FPU_FLAGS_UNDEFINED_C1; Name: 'UNDEF_C1'),
    (Flag: X86_FPU_FLAGS_UNDEFINED_C2; Name: 'UNDEF_C2'),
    (Flag: X86_FPU_FLAGS_UNDEFINED_C3; Name: 'UNDEF_C3'),
    (Flag: X86_FPU_FLAGS_TEST_C0; Name: 'TEST_C0'),
    (Flag: X86_FPU_FLAGS_TEST_C1; Name: 'TEST_C1'),
    (Flag: X86_FPU_FLAGS_TEST_C2; Name: 'TEST_C2'),
    (Flag: X86_FPU_FLAGS_TEST_C3; Name: 'TEST_C3')
  );
var
  i: Integer;
begin
  for i := Low(EFlagNames) to High(EFlagNames) do
  begin
    if EFlagNames[i].Flag = flag then
    begin
      Result := EFlagNames[i].Name;
      Exit;
    end;
  end;
  Result := '';
end;

function get_fpu_flag_names(const flags: UInt64): string;
var
  i: Integer;
  f: UInt64;
begin
  Result := '';
  f := 1;
  for i := 0 to 63 do
  begin
    if flags and f <> 0 then
      Result := Result + ' ' + get_fpu_flag_name(f);
    f := f shl 1;
  end;
end;

procedure print_insn_detail(handle: csh; mode: cs_mode; ins: Pcs_insn);
var
  count, index,
  i: Integer;
  l: string;
  x86: Pcs_x86;
  regs_read, regs_write: cs_regs;
  regs_read_count, regs_write_count: UInt8;
  op: Pcs_x86_op;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if ins^.detail = nil then
    Exit;

  x86 := @ins^.detail^.x86;

  print_string_hex(#9'Prefix:', @x86^.prefix, 4);

  print_string_hex(#9'Opcode:', @x86^.opcode, 4);

  WriteLn(#9'rex: 0x', format_string_hex(x86^.rex, '%x'));

  WriteLn(#9'addr_size: ', x86^.addr_size);
  WriteLn(#9'modrm: 0x', format_string_hex(x86^.modrm, '%x'));
  if x86^.encoding.modrm_offset <> 0 then
    WriteLn(#9'modrm_offset: 0x', format_string_hex(x86^.encoding.modrm_offset, '%x'));

  WriteLn(#9'disp: 0x', format_string_hex(x86^.disp, '%x'));
  if x86^.encoding.disp_offset <> 0 then
    WriteLn(#9'disp_offset: 0x', format_string_hex(x86^.encoding.disp_offset, '%x'));

  if x86^.encoding.disp_size <> 0 then
    WriteLn(#9'disp_size: 0x', format_string_hex(x86^.encoding.disp_size, '%x'));

  // SIB is not available in 16-bit mode
  if (mode and CS_MODE_16) = 0 then
  begin
    WriteLn(#9'sib: 0x', format_string_hex(x86^.sib, '%x'));
    if x86^.sib_base <> X86_REG_INVALID then
      WriteLn(#9#9'sib_base: ', cs_reg_name(handle, x86^.sib_base));
    if x86^.sib_index <> X86_REG_INVALID then
      WriteLn(#9#9'sib_index: ', cs_reg_name(handle, x86^.sib_index));
    if x86^.sib_scale <> 0 then
      WriteLn(#9#9'sib_scale: ', x86^.sib_scale);
  end;

  // XOP code condition
  if x86^.xop_cc <> X86_XOP_CC_INVALID then
    WriteLn(#9'xop_cc: ', x86^.xop_cc);

  // SSE code condition
  if x86^.sse_cc <> X86_SSE_CC_INVALID then
    WriteLn(#9'sse_cc: ', x86^.sse_cc);

  // AVX code condition
  if x86^.avx_cc <> X86_AVX_CC_INVALID then
    WriteLn(#9'avx_cc: ', x86^.avx_cc);

  // AVX Suppress All Exception
  if x86^.avx_sae <> False then
    WriteLn(#9'avx_sae: ', x86^.avx_sae);

  // AVX Rounding Mode
  if x86^.avx_rm <> X86_AVX_RM_INVALID then
    WriteLn(#9'avx_rm: ', x86^.avx_rm);

  // Print out all immediate operands
  count := cs_op_count(handle, ins, X86_OP_IMM);
  if count <> 0 then
  begin
    WriteLn(#9'imm_count: ', count);
    for i := 1 to count do
    begin
      // Due to Delphi's 1-based indexing, adjust the index accordingly
      index := cs_op_index(handle, ins, X86_OP_IMM, i);
      WriteLn(#9#9'imms[', i, ']: 0x', format_string_hex(x86^.operands[index].detail.imm, '%x'));
      if x86^.encoding.imm_offset <> 0 then
        WriteLn(#9'imm_offset: 0x', format_string_hex(x86^.encoding.imm_offset, '%x'));
      if x86^.encoding.imm_size <> 0 then
        WriteLn(#9'imm_size: 0x', format_string_hex(x86^.encoding.imm_size, '%x'));
    end;
  end;

  if x86^.op_count <> 0 then
    WriteLn(#9'op_count: ', x86^.op_count);

  // Print out all operands
  for i := 0 to x86^.op_count - 1 do
  begin
    op := @(x86^.operands[i]);

    case op^.&type of
      X86_OP_REG:
        WriteLn(#9#9'operands[', i, '].type: REG = ', cs_reg_name(handle, op^.detail.reg));
      X86_OP_IMM:
        WriteLn(#9#9'operands[', i, '].type: IMM = 0x', LowerCase(format_string_hex(op^.detail.imm, '%x')));
      X86_OP_MEM_:
      begin
        WriteLn(#9#9'operands[', i, '].type: MEM');
        if op^.detail.mem.segment <> X86_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.segment: REG = ', cs_reg_name(handle, op^.detail.mem.segment));
        if op^.detail.mem.base <> X86_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op^.detail.mem.base));
        if op^.detail.mem.index <> X86_REG_INVALID then
          WriteLn(#9#9#9'operands[', i, '].mem.index: REG = ', cs_reg_name(handle, op^.detail.mem.index));
        if op^.detail.mem.scale <> 1 then
          WriteLn(#9#9#9'operands[', i, '].mem.scale: ', op^.detail.mem.scale);
        if op^.detail.mem.disp <> 0 then
          WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op^.detail.mem.disp, '%x'));
      end;
    end;

    // AVX broadcast type
    if op^.avx_bcast <> X86_AVX_BCAST_INVALID then
      WriteLn(#9#9'operands[', i, '].avx_bcast: ', op^.avx_bcast);

    // AVX zero opmask {z}
    if op^.avx_zero_opmask then
      WriteLn(#9#9'operands[', i, '].avx_zero_opmask: TRUE');

    WriteLn(#9#9'operands[', i, '].size: ', op^.size);

    case op^.access of
      CS_AC_READ:
        WriteLn(#9#9'operands[', i, '].access: READ');
      CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: WRITE');
      CS_AC_READ or CS_AC_WRITE:
        WriteLn(#9#9'operands[', i, '].access: READ | WRITE');
    end;
  end;

  // Print out all registers accessed by this instruction (either implicit or explicit)
  if cs_regs_access(handle, ins, regs_read, @regs_read_count, regs_write, @regs_write_count) = CS_ERR_OK then
  begin
    if regs_read_count <> 0 then
    begin
      l := #9'Registers read:';
      for i := 0 to regs_read_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_read[i]));
      WriteLn(l);
    end;

    if regs_write_count <> 0 then
    begin
      l := #9'Registers modified:';
      for i := 0 to regs_write_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_write[i]));
      WriteLn(l);
    end;
  end;

  if (x86^.detail.eflags <> 0) or (x86^.detail.fpu_flags <> 0) then
  begin
    for i := 0 to ins^.detail^.groups_count - 1 do
    begin
      if ins^.detail^.groups[i] = X86_GRP_FPU then
      begin
        l := #9'FPU_FLAGS:' + get_fpu_flag_names(x86^.detail.eflags);
        WriteLn(l);
        WriteLn('');
        Exit;
      end;
    end;

    l := #9'EFLAGS:' + get_eflag_names(x86^.detail.eflags);
    WriteLn(l);
  end;

  WriteLn('');
end;

procedure Test;
const
  X86_CODE64: array[0..25] of Byte = (
    $55, $48, $8B, $05, $B8, $13, $00, $00, $E9, $EA, $BE, $AD, $DE, $FF, $25, $23,
    $01, $00, $00, $E8, $DF, $BE, $AD, $DE, $74, $FF
  );
  X86_CODE16: array[0..61] of Byte = (
    $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00, $00, $05, $23, $01, $00,
    $00, $36, $8B, $84, $91, $23, $01, $00, $00, $41, $8D, $84, $39, $89, $67, $00,
    $00, $8D, $87, $89, $67, $00, $00, $B4, $C6, $66, $E9, $B8, $00, $00, $00, $67,
    $FF, $A0, $23, $01, $00, $00, $66, $E8, $CB, $00, $00, $00, $74, $FC
  );
  X86_CODE32: array[0..58] of Byte = (
    $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00, $00, $05, $23, $01, $00,
    $00, $36, $8B, $84, $91, $23, $01, $00, $00, $41, $8D, $84, $39, $89, $67, $00,
    $00, $8D, $87, $89, $67, $00, $00, $B4, $C6, $E9, $EA, $BE, $AD, $DE, $FF, $A0,
    $23, $01, $00, $00, $E8, $DF, $BE, $AD, $DE, $74, $FF
  );
const
  Platforms: array[0..3] of TPlatform = (
    (arch: CS_ARCH_X86; mode: CS_MODE_16; code: @X86_CODE16; size: SizeOf(X86_CODE16); comment: 'X86 16bit (Intel syntax)'; opt_type: CS_OPT_INVALID; opt_value: 0),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32 (AT&T syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_ATT),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32 (Intel syntax)'; opt_type: CS_OPT_INVALID; opt_value: 0),
    (arch: CS_ARCH_X86; mode: CS_MODE_64; code: @X86_CODE64; size: SizeOf(X86_CODE64); comment: 'X86 64 (Intel syntax)'; opt_type: CS_OPT_INVALID; opt_value: 0)
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

    if Platforms[i].opt_type <> 0 then
      cs_option(handle, Platforms[i].opt_type, Platforms[i].opt_value);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count := cs_disasm(handle, Platforms[i].code, Platforms[i].size, address, 0, insn);
    if count > 0 then
    try
      WriteLn('****************');
      WriteLn('Platform: ', Platforms[i].comment);
      print_string_hex('Code:', Platforms[i].code, Platforms[i].size);
      WriteLn('Disasm:');

      item := insn;
      for j := 0 to count - 1 do
      begin
        l := '0x' + format_string_hex(item.address, '%.4x');
        l := Format('%s:'#9'%s'#9'%s', [l, item.mnemonic, item.op_str]);
        WriteLn(l);
        print_insn_detail(handle, Platforms[i].mode, item);
        if j < count - 1 then
          Inc(item);
      end;
      l := '0x' + format_string_hex(item.address + item.size, '%.4x:');
      WriteLn(l);
    finally
      // free memory allocated by cs_disasm()
      cs_free(insn, count);
    end
    else begin
      WriteLn('****************');
      WriteLn('Platform: ', Platforms[i].comment);
      WriteLn('Code:');
      print_string_hex('Code:', Platforms[i].code, Platforms[i].size);
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
