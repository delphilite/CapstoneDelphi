program test_basic;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows, test_utils, Capstone.Api;

procedure Test;
const
{$IFDEF CAPSTONE_HAS_X86}
  X86_CODE16: array[0..11] of Byte = ($8d, $4c, $32, $08, $01, $d8, $81, $c6, $34, $12, $00, $00);
  X86_CODE32: array[0..16] of Byte = ($ba, $cd, $ab, $00, $00, $8d, $4c, $32, $08, $01, $d8, $81, $c6, $34, $12, $00, $00);
  X86_CODE64: array[0..7] of Byte = ($55, $48, $8b, $05, $b8, $13, $00, $00);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
  ARM_CODE: array[0..31] of Byte = ($ed, $ff, $ff, $eb, $04, $e0, $2d, $e5, $00, $00, $00, $00, $e0, $83, $22, $e5, $f1, $02, $03, $0e, $00, $00, $a0, $e3, $02, $30, $c1, $e7, $00, $00, $53, $e3);
  ARM_CODE2: array[0..15] of Byte = ($10, $f1, $10, $e7, $11, $f2, $31, $e7, $dc, $a1, $2e, $f3, $e8, $4e, $62, $f3);
  ARMV8: array[0..11] of Byte = ($e0, $3b, $b2, $ee, $42, $00, $01, $e1, $51, $f0, $7f, $f5);
  THUMB_MCLASS: array[0..3] of Byte = ($ef, $f3, $02, $80);
  THUMB_CODE: array[0..7] of Byte = ($70, $47, $eb, $46, $83, $b0, $c9, $68);
  THUMB_CODE2: array[0..11] of Byte = ($4f, $f0, $00, $01, $bd, $e8, $00, $88, $d1, $e8, $00, $f0);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
  MIPS_CODE: array[0..19] of Byte = ($0c, $10, $00, $97, $00, $00, $00, $00, $24, $02, $00, $0c, $8f, $a2, $00, $00, $34, $21, $34, $56);
  MIPS_CODE2: array[0..7] of Byte = ($56, $34, $21, $34, $c2, $17, $01, $00);
  MIPS_32R6M: array[0..15] of Byte = ($00, $07, $00, $07, $00, $11, $93, $7c, $01, $8c, $8b, $7c, $00, $c7, $48, $d0);
  MIPS_32R6: array[0..7] of Byte = ($ec, $80, $00, $19, $7c, $43, $22, $a0);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
  ARM64_CODE: array[0..15] of Byte = ($21, $7c, $02, $9b, $21, $7c, $00, $53, $00, $40, $21, $4b, $e1, $0b, $40, $b9);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
  PPC_CODE: array[0..39] of Byte = ($80, $20, $00, $00, $80, $3f, $00, $00, $10, $43, $23, $0e, $d0, $44, $00, $80, $4c, $43, $22, $02, $2d, $03, $00, $80, $7c, $43, $20, $14, $7c, $43, $20, $93, $4f, $20, $00, $21, $4c, $c8, $00, $21);
  PPC_CODE2: array[0..11] of Byte = ($10, $60, $2a, $10, $10, $64, $28, $88, $7c, $4a, $5d, $0f);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SPARC}
  SPARC_CODE: array[0..63] of Byte = ($80, $a0, $40, $02, $85, $c2, $60, $08, $85, $e8, $20, $01, $81, $e8, $00, $00, $90, $10, $20, $01, $d5, $f6, $10, $16, $21, $00, $00, $0a, $86, $00, $40, $02, $01, $00, $00, $00, $12, $bf, $ff, $ff, $10, $bf, $ff, $ff, $a0, $02, $00, $09, $0d, $bf, $ff, $ff, $d4, $20, $60, $00, $d4, $4e, $00, $16, $2a, $c2, $80, $03);
  SPARCV9_CODE: array[0..15] of Byte = ($81, $a8, $0a, $24, $89, $a0, $10, $20, $89, $a0, $1a, $60, $89, $a0, $00, $e0);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SYSZ}
  SYSZ_CODE: array[0..39] of Byte = ($ed, $00, $00, $00, $00, $1a, $5a, $0f, $1f, $ff, $c2, $09, $80, $00, $00, $00, $07, $f7, $eb, $2a, $ff, $ff, $7f, $57, $e3, $01, $ff, $ff, $7f, $57, $eb, $00, $f0, $00, $00, $24, $b2, $4f, $00, $78);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_XCORE}
  XCORE_CODE: array[0..27] of Byte = ($fe, $0f, $fe, $17, $13, $17, $c6, $fe, $ec, $17, $97, $f8, $ec, $4f, $1f, $fd, $ec, $37, $07, $f2, $45, $5b, $f9, $fa, $02, $06, $1b, $10);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M68K}
  M68K_CODE: array[0..41] of Byte = ($d4, $40, $87, $5a, $4e, $71, $02, $b4, $c0, $de, $c0, $de, $5c, $00, $1d, $80, $71, $12, $01, $23, $f2, $3c, $44, $22, $40, $49, $0e, $56, $54, $c5, $f2, $3c, $44, $00, $44, $7a, $00, $00, $f2, $00, $0a, $28);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TMS320C64X}
  TMS320C64X_CODE: array[0..27] of Byte = ($01, $ac, $88, $40, $81, $ac, $88, $43, $00, $00, $00, $00, $02, $90, $32, $96, $02, $80, $46, $9e, $05, $3c, $83, $e6, $0b, $0c, $8b, $24);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M680X}
  M680X_CODE: array[0..34] of Byte = ($06, $10, $19, $1a, $55, $1e, $01, $23, $e9, $31, $06, $34, $55, $a6, $81, $a7, $89, $7f, $ff, $a6, $9d, $10, $00, $a7, $91, $a6, $9f, $10, $00, $11, $ac, $99, $10, $00, $39);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_EVM}
  EVM_CODE: array[0..1] of Byte = ($60, $61);
{$ENDIF}
const
  Platforms: array[0..26] of TPlatform = (
{$IFDEF CAPSTONE_HAS_X86}
    (arch: CS_ARCH_X86; mode: CS_MODE_16; code: @X86_CODE16[0]; size: SizeOf(X86_CODE16); comment: 'X86 16bit (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32[0]; size: SizeOf(X86_CODE32); comment: 'X86 32bit (ATT syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_ATT),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32[0]; size: SizeOf(X86_CODE32); comment: 'X86 32 (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32[0]; size: SizeOf(X86_CODE32); comment: 'X86 32 (MASM syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_MASM),
    (arch: CS_ARCH_X86; mode: CS_MODE_64; code: @X86_CODE64[0]; size: SizeOf(X86_CODE64); comment: 'X86 64 (Intel syntax)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE[0]; size: SizeOf(ARM_CODE); comment: 'ARM'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE2[0]; size: SizeOf(THUMB_CODE2); comment: 'THUMB-2'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE2[0]; size: SizeOf(ARM_CODE2); comment: 'ARM: Cortex-A15 + NEON'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE[0]; size: SizeOf(THUMB_CODE); comment: 'THUMB'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB or CS_MODE_MCLASS; code: @THUMB_MCLASS[0]; size: SizeOf(THUMB_MCLASS); comment: 'Thumb-MClass'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM or CS_MODE_V8; code: @ARMV8[0]; size: SizeOf(ARMV8); comment: 'Arm-V8'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32 or CS_MODE_BIG_ENDIAN; code: @MIPS_CODE[0]; size: SizeOf(MIPS_CODE); comment: 'MIPS-32 (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS64 or CS_MODE_LITTLE_ENDIAN; code: @MIPS_CODE2[0]; size: SizeOf(MIPS_CODE2); comment: 'MIPS-64-EL (Little-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32R6 or CS_MODE_MICRO or CS_MODE_BIG_ENDIAN; code: @MIPS_32R6M[0]; size: SizeOf(MIPS_32R6M); comment: 'MIPS-32R6 | Micro (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32R6 or CS_MODE_BIG_ENDIAN; code: @MIPS_32R6[0]; size: SizeOf(MIPS_32R6); comment: 'MIPS-32R6 (Big-endian)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
    (arch: CS_ARCH_ARM64; mode: CS_MODE_ARM; code: @ARM64_CODE[0]; size: SizeOf(ARM64_CODE); comment: 'ARM-64'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE[0]; size: SizeOf(PPC_CODE); comment: 'PPC-64'),
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE[0]; size: SizeOf(PPC_CODE); comment: 'PPC-64, print register with number only'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_NOREGNAME),
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN or CS_MODE_QPX; code: @PPC_CODE2[0]; size: SizeOf(PPC_CODE2); comment: 'PPC-64 + QPX'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SPARC}
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN; code: @SPARC_CODE[0]; size: SizeOf(SPARC_CODE); comment: 'Sparc'),
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN or CS_MODE_V9; code: @SPARCV9_CODE[0]; size: SizeOf(SPARCV9_CODE); comment: 'SparcV9'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SYSZ}
    (arch: CS_ARCH_SYSZ; mode: 0; code: @SYSZ_CODE[0]; size: SizeOf(SYSZ_CODE); comment: 'SystemZ'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_XCORE}
    (arch: CS_ARCH_XCORE; mode: 0; code: @XCORE_CODE[0]; size: SizeOf(XCORE_CODE); comment: 'XCore'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M68K}
    (arch: CS_ARCH_M68K; mode: CS_MODE_BIG_ENDIAN or CS_MODE_M68K_040; code: @M68K_CODE[0]; size: SizeOf(M68K_CODE); comment: 'M68K'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TMS320C64X}
    (arch: CS_ARCH_TMS320C64X; mode: 0; code: @TMS320C64X_CODE[0]; size: SizeOf(TMS320C64X_CODE); comment: 'TMS320C64x'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M680X}
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6809; code: @M680X_CODE[0]; size: SizeOf(M680X_CODE); comment: 'M680X_M6809'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_EVM}
    (arch: CS_ARCH_EVM; mode: 0; code: @EVM_CODE[0]; size: SizeOf(EVM_CODE); comment: 'EVM')
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
  for i := Low(platforms) to High(platforms) do
  begin
    Writeln('****************');
    Writeln('Platform: ', Platforms[i].comment);

    err := cs_open(platforms[i].arch, platforms[i].mode, handle);
    if err <> CS_ERR_OK then
    begin
      Writeln('Failed on cs_open() with error returned: ', Err);
      Continue;
    end;

    if Platforms[I].opt_type <> 0 then
      cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

    address := $1000;
    count := cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, insn);
    if count > 0 then
    begin
      print_string_hex('Code: ', platforms[i].code, platforms[i].size);
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
      l := '0x' + format_string_hex(item.address + item.size, '%.4x') + ':';
      Writeln(l);
      cs_free(insn, count);
    end
    else begin
      Writeln('****************');
      Writeln('Platform: ', Platforms[I].Comment);
      print_string_hex('Code: ', Platforms[I].Code, Platforms[I].Size);
      Writeln('ERROR: Failed to disasm given code!');
      Continue;
    end;

    WriteLn('');
    cs_close(Handle);
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
