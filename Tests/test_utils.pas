{ ***************************************************** }
{                                                       }
{  Pascal language binding for the Capstone engine      }
{                                                       }
{  Unit Name: common test utils                         }
{     Author: Lsuper 2024.05.01                         }
{    Purpose:                                           }
{                                                       }
{  Copyright (c) 1998-2024 Super Studio                 }
{                                                       }
{ ***************************************************** }

unit test_utils;

interface

uses
  SysUtils;

const
  nine_spaces = '         ';

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

    opt_skipdata: Integer;
    skipdata: NativeUInt;
  end;

  function  format_buffer_short(str: PByte; len: Integer): string;

  function  format_nine_spaces(const defspace: string; size: Integer): string;

  function  format_string_hex(const c: Integer;
    const fmt: string = ''): string; overload;
  function  format_string_hex(const c: Int64;
    const fmt: string = ''): string; overload;

  procedure print_string_hex(const comment: string; str: PByte; len: Integer);

implementation

function format_buffer_short(str: PByte; len: Integer): string;
var
  i: Integer;
  p: PByte;
begin
  Result := '';
  p := PByte(str);
  for i := 0 to len - 1 do
  begin
    Result := Result + format_string_hex(p[i]);
  end;
end;

function format_nine_spaces(const defspace: string; size: Integer): string;
begin
  // If size is negative, output the specified length of the string and left-align it
  if size < 0 then
    Result := defspace
  else begin
    // Ensure size does not exceed the length of defspace
    if size > Length(defspace) then
      size := Length(defspace);
    // Use the Copy function to get the specified length of the string
    Result := Copy(defspace, 1, size);
  end;
end;

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

end.
