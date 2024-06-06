{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_customized_mnem                      }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_customized_mnem.c              }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_customized_mnem;

{$APPTYPE CONSOLE}

{$I test.inc}

uses
  SysUtils, Capstone.Api, Capstone.X86, test_utils;

procedure print_insn_detail(handle: csh);
const
  X86_CODE32: array[0..1] of Byte = (
    $75, $01
  );
var
  count: Integer;
  insn: Pcs_insn;
begin
  count := cs_disasm(handle, @X86_CODE32, SizeOf(X86_CODE32), $1000, 1, insn);
  if count > 0 then
  begin
    print_string_hex('', @X86_CODE32[0], SizeOf(X86_CODE32));
    Writeln(#9#9, insn.mnemonic, #9, insn.op_str);
    // Free memory allocated by cs_disasm()
    cs_free(insn, count);
  end
  else begin
    Writeln('ERROR: Failed to disasm given code!');
    Abort;
  end;
end;

procedure Test;
var
  handle: csh;
  err: cs_err;
  my_mnem, default_mnem: cs_opt_mnem;
begin
  // Customize mnemonic JNE to "jnz"
  my_mnem.id := X86_INS_JNE;
  my_mnem.mnemonic := 'jnz';

  // Set .mnemonic to NULL to reset to default mnemonic
  default_mnem.id := X86_INS_JNE;
  default_mnem.mnemonic := nil;

  err := cs_open(CS_ARCH_X86, CS_MODE_32, handle);
  if err <> CS_ERR_OK then
  begin
    if cs_support(CS_ARCH_X86) then
    begin
      Writeln('Failed on cs_open() with error returned: ', err);
      Abort;
    end
    else Exit;
  end;

  // 1. Print out the instruction in default setup.
  Writeln('Disassemble X86 code with default instruction mnemonic');
  print_insn_detail(handle);

  // Customized mnemonic JNE to JNZ using CS_OPT_MNEMONIC option
  Writeln('Now customize engine to change mnemonic from ''JNE'' to ''JNZ''');
  cs_option(handle, CS_OPT_MNEMONIC, NativeUInt(@my_mnem));

  // 2. Now print out the instruction in newly customized setup.
  print_insn_detail(handle);

  // Reset engine to use the default mnemonic of JNE
  Writeln('Reset engine to use the default mnemonic');
  cs_option(handle, CS_OPT_MNEMONIC, NativeUInt(@default_mnem));

  // 3. Now print out the instruction in default setup.
  print_insn_detail(handle);

  // Done
  cs_close(handle);
end;

begin
  try
    Test;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
