unit test_utils;

interface

uses
  SysUtils;

type
  TPlatform = record
    arch: Cardinal;
    mode: Integer;
    code: PByte;
    size: NativeUInt;
    comment: PAnsiChar;
    opt_type: Integer;
    opt_value: Integer;
    syntax: Integer;
  end;

  function  format_string_hex(const c: Integer;
    const fmt: string = ''): string; overload;
  function  format_string_hex(const c: Int64;
    const fmt: string = ''): string; overload;

  procedure print_string_hex(const comment: string; str: PByte; len: Integer);

  procedure WriteLnFormat(const fmt: string; const args: array of const);

implementation

function format_string_hex(const c: Integer; const fmt: string): string;
begin
  if fmt = '' then
    Result := IntToHex(c, 2)
  else Result := Format(fmt, [c]);
  Result := LowerCase(Result);
end;

function format_string_hex(const c: Int64; const fmt: string): string;
begin
  if fmt = '' then
    Result := IntToHex(c, 2)
  else Result := Format(fmt, [c]);
  Result := LowerCase(Result);
end;

procedure print_string_hex(const comment: string; str: PByte; len: Integer);
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

procedure WriteLnFormat(const fmt: string; const args: array of const);
var
  S: string;
begin
  S := Format(fmt, args);
  Writeln(S);
end;

end.
