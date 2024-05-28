unit test_utils;

interface

uses
  SysUtils, Windows, Capstone.Api;

type
  TPlatform = record
    arch: cs_arch;
    mode: cs_mode;
    code: PUInt8;
    size: size_t;
    comment: PAnsiChar;
    opt_type: cs_opt_type;
    opt_value: cs_opt_value;
  end;

  function format_string_hex(const c: Int64; const fmt: string = ''): string;

  procedure print_string_hex(const comment: string; str: PUInt8; len: size_t);

implementation

function format_string_hex(const c: Int64; const fmt: string): string;
begin
  if fmt = '' then
    Result := IntToHex(c, 2)
  else Result := Format(fmt, [c]);
  Result := LowerCase(Result);
end;

procedure print_string_hex(const comment: string; str: PUInt8; len: size_t);
var
  i: Integer;
  l, s: string;
  p: PByte;
begin
  l := comment;
  p := PByte(str);
  for i := 0 to len - 1 do
  begin
    s := '0x' + format_string_hex(p[i]) + ' ';
    l := l + s;
  end;
  Writeln(l);
end;

end.
