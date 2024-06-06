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

program test_bpf;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Bpf, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
const
  ext_name: array[Boolean] of string = (
    '', '#len'
  );
var
  i: Integer;
  l: string;
  bpf: Pcs_bpf;
  op: Pcs_bpf_op;
  regs_read, regs_write: cs_regs;
  regs_read_count, regs_write_count: Byte;
begin
  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins.detail = nil) then
    Exit;

  if (ins.detail.groups_count <> 0) then
  begin
    l := #9'Groups:';
    for i := 0 to ins.detail.groups_count - 1 do
      l := l + ' ' + string(cs_group_name(handle, ins.detail.groups[i]));
    Writeln(l);
  end;

  bpf := @ins.detail.bpf;
  WriteLn(#9'Operand count: ', bpf.op_count);
  for i := 0 to bpf.op_count - 1 do
  begin
    op := @bpf.operands[i];
    Write(#9#9'operands[', i, '].type: ');
    case op.type_ of
      BPF_OP_INVALID:
        WriteLn('INVALID');
      BPF_OP_REG:
        WriteLn('REG = ', cs_reg_name(handle, op.detail.reg));
      BPF_OP_IMM:
        WriteLn('IMM = 0x', format_string_hex(op.detail.imm, '%x'));
      BPF_OP_OFF:
        WriteLn('OFF = +0x', format_string_hex(op.detail.off, '%x'));
      BPF_OP_MEM_:
      begin
        WriteLn('MEM');
        if (op.detail.mem.base <> BPF_REG_INVALID) then
          WriteLn(#9#9#9'operands[', i, '].mem.base: REG = ', cs_reg_name(handle, op.detail.mem.base));
        WriteLn(#9#9#9'operands[', i, '].mem.disp: 0x', format_string_hex(op.detail.mem.disp, '%x'));
      end;
      BPF_OP_MMEM:
        WriteLn('MMEM = M[0x', format_string_hex(op.detail.mmem, '%x'), ']');
      BPF_OP_MSH:
        WriteLn('MSH = 4*([0x', format_string_hex(op.detail.msh, '%x'), ']&0xf)');
      BPF_OP_EXT:
        WriteLn('EXT = ', ext_name[op.detail.ext <> 0]);
    end;
  end;

  { print all registers that are involved in this instruction }
  if cs_regs_access(handle, ins, regs_read, regs_read_count, regs_write, regs_write_count) = CS_ERR_OK then
  begin
    if (regs_read_count <> 0) then
    begin
      l := #9'Registers read:';
      for i := 0 to regs_read_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_read[i]));
      Writeln(l);
    end;

    if (regs_write_count <> 0) then
    begin
      l := #9'Registers modified:';
      for i := 0 to regs_write_count - 1 do
        l := l + ' ' + string(cs_reg_name(handle, regs_write[i]));
      Writeln(l);
    end;
  end;

  WriteLn('');
end;

procedure Test;
const
  CBPF_CODE: array[0..39] of Byte = (
    $94, $09, $00, $00, $37, $13, $03, $00, $87, $00, $00, $00, $00, $00, $00, $00,
    $07, $00, $00, $00, $00, $00, $00, $00, $16, $00, $00, $00, $00, $00, $00, $00,
    $80, $00, $00, $00, $00, $00, $00, $00
  );
  EBPF_CODE: array[0..47] of Byte = (
    $97, $09, $00, $00, $37, $13, $03, $00, $dc, $02, $00, $00, $20, $00, $00, $00,
    $30, $00, $00, $00, $00, $00, $00, $00, $db, $3a, $00, $01, $00, $00, $00, $00,
    $84, $02, $00, $00, $00, $00, $00, $00, $6d, $33, $17, $02, $00, $00, $00, $00
  );
const
  Platforms: array[0..1] of TPlatform = (
    (arch: CS_ARCH_BPF; mode: CS_MODE_LITTLE_ENDIAN or CS_MODE_BPF_CLASSIC; code: @CBPF_CODE; size: SizeOf(CBPF_CODE); comment: 'cBPF Le'),
    (arch: CS_ARCH_BPF; mode: CS_MODE_LITTLE_ENDIAN or CS_MODE_BPF_EXTENDED; code: @EBPF_CODE; size: SizeOf(EBPF_CODE); comment: 'eBPF Le')
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
    address := $0;
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
        l := '0x' + format_string_hex(item.address, '%x');
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
