{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: test_iter                                 }
{     Author: Lsuper 2024.05.01                         }
{    Purpose: tests\test_iter.c                         }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

program test_iter;

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
  X86_CODE32: array[0..11] of Byte = (
    $8D, $4C, $32, $08, $01, $D8, $81, $C6, $34, $12, $00, $00
  );
  X86_CODE64: array[0..7] of Byte = (
    $55, $48, $8B, $05, $B8, $13, $00, $00);
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
  ARM_CODE: array[0..31] of Byte = (
    $ED, $FF, $FF, $EB, $04, $E0, $2D, $E5, $00, $00, $00, $00, $E0, $83, $22, $E5,
    $F1, $02, $03, $0E, $00, $00, $A0, $E3, $02, $30, $C1, $E7, $00, $00, $53, $E3
  );
  ARM_CODE2: array[0..15] of Byte = (
    $10, $F1, $10, $E7, $11, $F2, $31, $E7, $DC, $A1, $2E, $F3, $E8, $4E, $62, $F3
  );
  THUMB_CODE: array[0..7] of Byte = (
    $70, $47, $EB, $46, $83, $B0, $C9, $68
  );
  THUMB_CODE2: array[0..11] of Byte = (
    $4F, $F0, $00, $01, $BD, $E8, $00, $88, $D1, $E8, $00, $F0
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
  MIPS_CODE: array[0..23] of Byte = (
    $0C, $10, $00, $97, $00, $00, $00, $00, $24, $02, $00, $0C, $8F, $A2, $00, $00,
    $34, $21, $34, $56, $00, $80, $04, $08
  );
  MIPS_CODE2: array[0..7] of Byte = (
    $56, $34, $21, $34, $C2, $17, $01, $00
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
  ARM64_CODE: array[0..67] of Byte = (
    $09, $00, $38, $D5, $BF, $40, $00, $D5, $0C, $05, $13, $D5, $20, $50, $02, $0E,
    $20, $E4, $3D, $0F, $00, $18, $A0, $5F, $A2, $00, $AE, $9E, $9F, $37, $03, $D5,
    $BF, $33, $03, $D5, $DF, $3F, $03, $D5, $21, $7C, $02, $9B, $21, $7C, $00, $53,
    $00, $40, $21, $4B, $E1, $0B, $40, $B9, $20, $04, $81, $DA, $20, $08, $02, $8B,
    $10, $5B, $E8, $3C
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
  PPC_CODE: array[0..43] of Byte = (
    $80, $20, $00, $00, $80, $3F, $00, $00, $10, $43, $23, $0E, $D0, $44, $00, $80,
    $4C, $43, $22, $02, $2D, $03, $00, $80, $7C, $43, $20, $14, $7C, $43, $20, $93,
    $4F, $20, $00, $21, $4C, $C8, $00, $21, $40, $82, $00, $14
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
{$IFDEF CAPSTONE_HAS_M680X}
  M680X_CODE: array[0..34] of Byte = (
    $06, $10, $19, $1A, $55, $1E, $01, $23, $E9, $31, $06, $34, $55, $A6, $81, $A7,
    $89, $7F, $FF, $A6, $9D, $10, $00, $A7, $91, $A6, $9F, $10, $00, $11, $AC, $99,
    $10, $00, $39
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MOS65XX}
  MOS65XX_CODE: array[0..11] of Byte = (
    $0d, $34, $12, $08, $09, $ff, $10, $80, $20, $00, $00, $98
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_BPF}
  EBPF_CODE: array[0..47] of Byte = (
    $97, $09, $00, $00, $37, $13, $03, $00, $dc, $02, $00, $00, $20, $00, $00, $00,
    $30, $00, $00, $00, $00, $00, $00, $00, $db, $3a, $00, $01, $00, $00, $00, $00,
    $84, $02, $00, $00, $00, $00, $00, $00, $6d, $33, $17, $02, $00, $00, $00, $00
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_RISCV}
  RISCV_CODE32: array[0..159] of Byte = (
    $37, $34, $00, $00, $97, $82, $00, $00, $ef, $00, $80, $00, $ef, $f0, $1f, $ff,
    $e7, $00, $45, $00, $e7, $00, $c0, $ff, $63, $05, $41, $00, $e3, $9d, $61, $fe,
    $63, $ca, $93, $00, $63, $53, $b5, $00, $63, $65, $d6, $00, $63, $76, $f7, $00,
    $03, $88, $18, $00, $03, $99, $49, $00, $03, $aa, $6a, $00, $03, $cb, $2b, $01,
    $03, $dc, $8c, $01, $23, $86, $ad, $03, $23, $9a, $ce, $03, $23, $8f, $ef, $01,
    $93, $00, $e0, $00, $13, $a1, $01, $01, $13, $b2, $02, $7d, $13, $c3, $03, $dd,
    $13, $e4, $c4, $12, $13, $f5, $85, $0c, $13, $96, $e6, $01, $13, $d7, $97, $01,
    $13, $d8, $f8, $40, $33, $89, $49, $01, $b3, $0a, $7b, $41, $33, $ac, $ac, $01,
    $b3, $3d, $de, $01, $33, $d2, $62, $40, $b3, $43, $94, $00, $33, $e5, $c5, $00,
    $b3, $76, $f7, $00, $b3, $54, $39, $01, $b3, $50, $31, $00, $33, $9f, $0f, $00
  );
  RISCV_CODE64: array[0..3] of Byte = (
    $13, $04, $a8, $7a
  );
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TRICORE}
  TRICORE_CODE: array[0..31] of Byte = (
    $16, $01, $20, $01, $1d, $00, $02, $00, $8f, $70, $00, $11, $40, $ae, $89, $ee,
    $04, $09, $42, $f2, $e2, $f2, $c2, $11, $19, $ff, $c0, $70, $19, $ff, $20, $10
  );
{$ENDIF}
const
  Platforms: array[0..21] of TPlatform = (
{$IFDEF CAPSTONE_HAS_X86}
    (arch: CS_ARCH_X86; mode: CS_MODE_16; code: @X86_CODE16; size: SizeOf(X86_CODE16); comment: 'X86 16bit (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32bit (ATT syntax)'; opt_type: CS_OPT_SYNTAX; opt_value: CS_OPT_SYNTAX_ATT),
    (arch: CS_ARCH_X86; mode: CS_MODE_32; code: @X86_CODE32; size: SizeOf(X86_CODE32); comment: 'X86 32 (Intel syntax)'),
    (arch: CS_ARCH_X86; mode: CS_MODE_64; code: @X86_CODE64; size: SizeOf(X86_CODE64); comment: 'X86 64 (Intel syntax)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM}
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE; size: SizeOf(ARM_CODE); comment: 'ARM'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE2; size: SizeOf(THUMB_CODE2); comment: 'THUMB-2'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_ARM; code: @ARM_CODE2; size: SizeOf(ARM_CODE2); comment: 'ARM: Cortex-A15 + NEON'),
    (arch: CS_ARCH_ARM; mode: CS_MODE_THUMB; code: @THUMB_CODE; size: SizeOf(THUMB_CODE); comment: 'THUMB'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MIPS}
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN; code: @MIPS_CODE; size: SizeOf(MIPS_CODE); comment: 'MIPS-32 (Big-endian)'),
    (arch: CS_ARCH_MIPS; mode: CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN; code: @MIPS_CODE2; size: SizeOf(MIPS_CODE2); comment: 'MIPS-64-EL (Little-endian)'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_ARM64}
    (arch: CS_ARCH_ARM64; mode: CS_MODE_ARM; code: @ARM64_CODE; size: SizeOf(ARM64_CODE); comment: 'ARM-64'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_POWERPC}
    (arch: CS_ARCH_PPC; mode: CS_MODE_BIG_ENDIAN; code: @PPC_CODE; size: SizeOf(PPC_CODE); comment: 'PPC-64'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SPARC}
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN; code: @SPARC_CODE; size: SizeOf(SPARC_CODE); comment: 'Sparc'),
    (arch: CS_ARCH_SPARC; mode: CS_MODE_BIG_ENDIAN + CS_MODE_V9; code: @SPARCV9_CODE; size: SizeOf(SPARCV9_CODE); comment: 'SparcV9'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_SYSZ}
    (arch: CS_ARCH_SYSZ; mode: cs_mode(0); code: @SYSZ_CODE; size: SizeOf(SYSZ_CODE); comment: 'SystemZ'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_XCORE}
    (arch: CS_ARCH_XCORE; mode: cs_mode(0); code: @XCORE_CODE; size: SizeOf(XCORE_CODE); comment: 'XCore'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_M680X}
    (arch: CS_ARCH_M680X; mode: CS_MODE_M680X_6809; code: @M680X_CODE; size: SizeOf(M680X_CODE); comment: 'M680X_6809'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_MOS65XX}
    (arch: CS_ARCH_MOS65XX; mode: CS_MODE_LITTLE_ENDIAN; code: @MOS65XX_CODE; size: SizeOf(MOS65XX_CODE); comment: 'MOS65XX'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_BPF}
    (arch: CS_ARCH_BPF; mode: CS_MODE_LITTLE_ENDIAN or CS_MODE_BPF_EXTENDED; code: @EBPF_CODE; size: SizeOf(EBPF_CODE); comment: 'eBPF'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_RISCV}
    (arch: CS_ARCH_RISCV; mode: CS_MODE_RISCV32; code: @RISCV_CODE32; size: SizeOf(RISCV_CODE32); comment: 'RISCV32'),
    (arch: CS_ARCH_RISCV; mode: CS_MODE_RISCV64; code: @RISCV_CODE64; size: SizeOf(RISCV_CODE64); comment: 'RISCV64'),
{$ENDIF}
{$IFDEF CAPSTONE_HAS_TRICORE}
    (arch: CS_ARCH_TRICORE; mode: CS_MODE_TRICORE_162; code: @TRICORE_CODE; size: SizeOf(TRICORE_CODE); comment: 'TriCore')
{$ENDIF}
  );
var
  handle: csh;
  address: UInt64;
  insn: Pcs_insn;
  detail: Pcs_detail;
  i: Integer;
  l: string;
  err: cs_err;
  code: PByte;
  size: NativeUInt;
  n: Integer;
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

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    insn := cs_malloc(handle);

    print_string_hex('Code: ', Platforms[i].code, Platforms[i].size);

    Writeln('Disasm:');
    address := $1000;
    code := Platforms[i].code;
    size := Platforms[i].size;
    while cs_disasm_iter(handle, code, size, address, insn) do
    begin
      l := '0x' + format_string_hex(insn.address, '%.4x');
      l := Format('%s:'#9'%s'#9#9'%s // insn-ID: %d, insn-mnem: %s', [
        l, insn.mnemonic, insn.op_str, insn.id, cs_insn_name(handle, insn.id)]);
      WriteLn(l);

      detail := insn.detail;

      if detail.regs_read_count > 0 then
      begin
        l := #9'Implicit registers read: ';
        for n := 0 to detail.regs_read_count - 1 do
          l := l + string(cs_reg_name(handle, detail.regs_read[n])) + ' ';
        Writeln(l);
      end;

      if detail.regs_write_count > 0 then
      begin
        l := #9'Implicit registers modified: ';
        for n := 0 to detail.regs_write_count - 1 do
          l := l + string(cs_reg_name(handle, detail.regs_write[n])) + ' ';
        Writeln(l);
      end;

      if detail.groups_count > 0 then
      begin
        l := #9'This instruction belongs to groups: ';
        for n := 0 to detail.groups_count - 1 do
          l := l + string(cs_group_name(handle, detail.groups[n])) + ' ';
        Writeln(l);
      end;
    end;

    Writeln('');
    cs_free(insn, 1);
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
