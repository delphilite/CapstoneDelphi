{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_basic                                }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_basic.c                        }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_basic;

{$APPTYPE CONSOLE}

{$I test.inc}

uses
  SysUtils, Capstone.Api, test_utils;

procedure Test;
const
{$IFDEF CAPSTONE_HAS_X86}
  X86_CODE16: array[0..11] of Byte = (
    $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00, $00
  );
  X86_CODE32: array[0..16] of Byte = (
    $BA, $CD, $AB, $00, $00, $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00,
    $00
  );
  X86_CODE64: array[0..7] of Byte = (
    $55, $48, $8B, $05, $B8, $13, $00, $00
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
  ARM_CODE: array[0..31] of Byte = (
    $ED, $FF, $FF, $EB, $04, $E0, $2D, $E5, $00, $00, $00, $00, $E0, $83, $22, $E5,
    $F1, $02, $03, $0E, $00, $00, $A0, $E3, $02, $30, $C1, $E7, $00, $00, $53, $E3
  );
  ARM_CODE2: array[0..15] of Byte = (
    $10, $F1, $10, $E7, $11, $F2, $31, $E7, $DC, $A1, $2E, $F3, $E8, $4E, $62, $F3
  );
  ARMV8: array[0..11] of Byte = (
    $E0, $3B, $B2, $EE, $42, $00, $01, $E1, $51, $F0, $7F, $F5
  );
  THUMB_MCLASS: array[0..3] of Byte = (
    $EF, $F3, $02, $80
  );
  THUMB_CODE: array[0..7] of Byte = (
    $70, $47, $EB, $46, $83, $B0, $C9, $68
  );
  THUMB_CODE2: array[0..11] of Byte = (
    $4F, $F0, $00, $01, $BD, $E8, $00, $88, $D1, $E8, $00, $F0
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
  MIPS_CODE: array[0..19] of Byte = (
    $0C, $10, $00, $97, $00, $00, $00, $00, $24, $02, $00, $0C, $8F, $A2, $00, $00,
    $34, $21, $34, $56
  );
  MIPS_CODE2: array[0..7] of Byte = (
    $56, $34, $21, $34, $C2, $17, $01, $00
  );
  MIPS_32R6M: array[0..15] of Byte = (
    $00, $07, $00, $07, $00, $11, $93, $7C, $01, $8C, $8B, $7C, $00, $C7, $48, $D0
  );
  MIPS_32R6: array[0..7] of Byte = (
    $EC, $80, $00, $19, $7C, $43, $22, $A0
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
  ARM64_CODE: array[0..15] of Byte = (
    $21, $7C, $02, $9B, $21, $7C, $00, $53, $00, $40, $21, $4B, $E1, $0B, $40, $B9
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
  PPC_CODE: array[0..39] of Byte = (
    $80, $20, $00, $00, $80, $3F, $00, $00, $10, $43, $23, $0E, $D0, $44, $00, $80,
    $4C, $43, $22, $02, $2D, $03, $00, $80, $7C, $43, $20, $14, $7C, $43, $20, $93,
    $4F, $20, $00, $21, $4C, $C8, $00, $21
  );
  PPC_CODE2: array[0..11] of Byte = (
    $10, $60, $2A, $10, $10, $64, $28, $88, $7C, $4A, $5D, $0F
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SPARC}
  SPARC_CODE: array[0..63] of Byte = (
    $80, $A0, $40, $02, $85, $C2, $60, $08, $85, $E8, $20, $01, $81, $E8, $00, $00,
    $90, $10, $20, $01, $D5, $F6, $10, $16, $21, $00, $00, $0A, $86, $00, $40, $02,
    $01, $00, $00, $00, $12, $BF, $FF, $FF, $10, $BF, $FF, $FF, $A0, $02, $00, $09,
    $0D, $BF, $FF, $FF, $D4, $20, $60, $00, $D4, $4E, $00, $16, $2A, $C2, $80, $03
  );
  SPARCV9_CODE: array[0..15] of Byte = (
    $81, $A8, $0A, $24, $89, $A0, $10, $20, $89, $A0, $1A, $60, $89, $A0, $00, $E0
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SYSZ}
  SYSZ_CODE: array[0..39] of Byte = (
    $ED, $00, $00, $00, $00, $1A, $5A, $0F, $1F, $FF, $C2, $09, $80, $00, $00, $00,
    $07, $F7, $EB, $2A, $FF, $FF, $7F, $57, $E3, $01, $FF, $FF, $7F, $57, $EB, $00,
    $F0, $00, $00, $24, $B2, $4F, $00, $78
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_XCORE}
  XCORE_CODE: array[0..27] of Byte = (
    $FE, $0F, $FE, $17, $13, $17, $C6, $FE, $EC, $17, $97, $F8, $EC, $4F, $1F, $FD,
    $EC, $37, $07, $F2, $45, $5B, $F9, $FA, $02, $06, $1B, $10
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M68K}
  M68K_CODE: array[0..41] of Byte = (
    $D4, $40, $87, $5A, $4E, $71, $02, $B4, $C0, $DE, $C0, $DE, $5C, $00, $1D, $80,
    $71, $12, $01, $23, $F2, $3C, $44, $22, $40, $49, $0E, $56, $54, $C5, $F2, $3C,
    $44, $00, $44, $7A, $00, $00, $F2, $00, $0A, $28
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TMS320C64X}
  TMS320C64X_CODE: array[0..27] of Byte = (
    $01, $AC, $88, $40, $81, $AC, $88, $43, $00, $00, $00, $00, $02, $90, $32, $96,
    $02, $80, $46, $9E, $05, $3C, $83, $E6, $0B, $0C, $8B, $24
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M680X}
  M680X_CODE: array[0..34] of Byte = (
    $06, $10, $19, $1A, $55, $1E, $01, $23, $E9, $31, $06, $34, $55, $A6, $81, $A7,
    $89, $7F, $FF, $A6, $9D, $10, $00, $A7, $91, $A6, $9F, $10, $00, $11, $AC, $99,
    $10, $00, $39
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_EVM}
  EVM_CODE: array[0..1] of Byte = (
    $60, $61
  );
{$ENDIF}
const
  Platforms: array[0..26] of TPlatform = (
{$IFDEF CAPSTONE_HAS_X86}
    (arch: CS_ARCH_X86; mode: CS_MODE_16; code: @X86_CODE16; size: SizeOf(X86_CODE16); comment: 'X86 16bit (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32bit (ATT syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_ATT),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32 (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32 (MASM syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_MASM),
    (arch: CS_ARCH_X86; mode: CS_MODE_64; code: @X86_CODE64; size: SizeOf(X86_CODE64); comment: 'X86 64 (Intel syntax)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE; size: SizeOf(ARM_CODE); comment: 'ARM'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE2; size: SizeOf(THUMB_CODE2); comment: 'THUMB-2'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE2; size: SizeOf(ARM_CODE2); comment: 'ARM: Cortex-A15 + NEON'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE; size: SizeOf(THUMB_CODE); comment: 'THUMB'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB or CS_MODE_MCLASS; code: @THUMB_MCLASS; size: SizeOf(THUMB_MCLASS); comment: 'Thumb-MClass'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM or CS_MODE_V8; code: @ARMV8; size: SizeOf(ARMV8); comment: 'Arm-V8'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32 or CS_MODE_BIG_ENDIAN; code: @MIPS_CODE; size: SizeOf(MIPS_CODE); comment: 'MIPS-32 (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS64 or CS_MODE_LITTLE_ENDIAN; code: @MIPS_CODE2; size: SizeOf(MIPS_CODE2); comment: 'MIPS-64-EL (Little-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32R6 or CS_MODE_MICRO or CS_MODE_BIG_ENDIAN; code: @MIPS_32R6M; size: SizeOf(MIPS_32R6M); comment: 'MIPS-32R6 | Micro (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32R6 or CS_MODE_BIG_ENDIAN; code: @MIPS_32R6; size: SizeOf(MIPS_32R6); comment: 'MIPS-32R6 (Big-endian)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
    (arch: CS_ARCH_ARM64; mode: CS_MODE_ARM; code: @ARM64_CODE; size: SizeOf(ARM64_CODE); comment: 'ARM-64'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE; size: SizeOf(PPC_CODE); comment: 'PPC-64'),
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE; size: SizeOf(PPC_CODE); comment: 'PPC-64, print register with number only'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_NOREGNAME),
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN or CS_MODE_QPX; code: @PPC_CODE2; size: SizeOf(PPC_CODE2); comment: 'PPC-64 + QPX'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SPARC}
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN; code: @SPARC_CODE; size: SizeOf(SPARC_CODE); comment: 'Sparc'),
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN or CS_MODE_V9; code: @SPARCV9_CODE; size: SizeOf(SPARCV9_CODE); comment: 'SparcV9'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SYSZ}
    (arch: CS_ARCH_SYSZ; mode: 0; code: @SYSZ_CODE; size: SizeOf(SYSZ_CODE); comment: 'SystemZ'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_XCORE}
    (arch: CS_ARCH_XCORE; mode: 0; code: @XCORE_CODE; size: SizeOf(XCORE_CODE); comment: 'XCore'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M68K}
    (arch: CS_ARCH_M68K; mode: CS_MODE_BIG_ENDIAN or CS_MODE_M68K_040; code: @M68K_CODE; size: SizeOf(M68K_CODE); comment: 'M68K'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TMS320C64X}
    (arch: CS_ARCH_TMS320C64X; mode: 0; code: @TMS320C64X_CODE; size: SizeOf(TMS320C64X_CODE); comment: 'TMS320C64x'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M680X}
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6809; code: @M680X_CODE; size: SizeOf(M680X_CODE); comment: 'M680X_M6809'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_EVM}
    (arch: CS_ARCH_EVM; mode: 0; code: @EVM_CODE; size: SizeOf(EVM_CODE); comment: 'EVM')
{$ENDIF}
  );
var
  handle: csh;
  address: UInt64;
  insn, item: Pcs_insn;
  i, j: Integer;
  l: string;
  count: Integer;
  err: cs_err;
begin
  for i := Low(Platforms) to High(Platforms) do
  begin
    Writeln('****************');
    Writeln('Platform: ', Platforms[i].comment);

    err := cs_open(Platforms[i].arch, Platforms[i].mode, handle);
    if err <> CS_ERR_OK then
    begin
      Writeln('Failed on cs_open() with error returned: ', err);
      Continue;
    end;

    if Platforms[i].opt_type <> 0 then
      cs_option(handle, Platforms[i].opt_type, Platforms[i].opt_value);

    address := $1000;
    count := cs_disasm(handle, Platforms[i].code, Platforms[i].size, address, 0, insn);
    if count > 0 then
    begin
      print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);
      Writeln('Disasm:');
      item := insn;
      for j := 0 to count - 1 do
      begin
        l := '0x' + format_string_hex(item.address, '%.4x');
        l := Format('%s:'#9'%s'#9#9'%s', [l, item.mnemonic, item.op_str]);
        WriteLn(l);
        if j < count - 1 then
          Inc(item);
      end;

      // print out the next offset, after the last insn
      l := '0x' + format_string_hex(item.address + item.size, '%.4x') + ':';
      Writeln(l);

      // free memory allocated by cs_disasm()
      cs_free(insn, count);
    end
    else begin
      Writeln('****************');
      Writeln('Platform: ', Platforms[i].Comment);
      print_string_hex('Code: ', Platforms[i].Code, Platforms[i].Size);
      Writeln('ERROR: Failed to disasm given code!');
      Continue;
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
