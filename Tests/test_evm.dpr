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

program test_evm;

{$APPTYPE CONSOLE}

uses
  SysUtils, Capstone.Api, Capstone.Evm, test_utils;

procedure print_insn_detail(handle: csh; ins: Pcs_insn);
var
  i: Integer;
  l: string;
  evm: Pcs_evm;
begin
  if ins.detail = nil then
    Exit;

  evm := @ins.detail.evm;

  if evm.pop > 0 then
    WriteLn(#9'Pop:     ', evm.pop);

  if evm.push > 0 then
    WriteLn(#9'Push:    ', evm.push);

  if evm.fee > 0 then
    WriteLn(#9'Gas fee: ', evm.fee);

  if ins.detail.groups_count > 0 then
  begin
    l := #9'Groups: ';
    for i := 0 to ins.detail.groups_count - 1 do
      l := l + string(cs_group_name(handle, ins.detail.groups[i])) + ' ';
    WriteLn(l);
  end;

  WriteLn('');
end;

procedure Test;
const
  EVM_CODE: array[0..2] of Byte = (
    $60, $61, $50
  );
const
  Platforms: array[0..0] of TPlatform = (
    (arch: CS_ARCH_EVM; mode: 0; code: @EVM_CODE; size: SizeOf(EVM_CODE); comment: 'EVM')
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
