# CapstoneDelphi
![Version](https://img.shields.io/badge/version-v5.0.6-yellow.svg)
![License](https://img.shields.io/github/license/delphilite/CapstoneDelphi)
![Lang](https://img.shields.io/github/languages/top/delphilite/CapstoneDelphi.svg)
![stars](https://img.shields.io/github/stars/delphilite/CapstoneDelphi.svg)

CapstoneDelphi is a [Delphi](http://www.embarcadero.com/products/delphi) and [Free Pascal](https://www.freepascal.org/) binding for the [Capstone Disassembler Library](http://www.capstone-engine.org/). It supports Capstone 5 and provides a friendly and simple type-safe API that is ridiculously easy to learn and quick to pick up.

Capstone is a disassembly framework with the target of becoming the ultimate disasm engine for binary analysis and reversing in the security community.

## Features
* **Supports** Capstone 5 multiple hardware architectures: ARM, AArch64, Alpha, BPF, Ethereum VM, HP PA-RISC (HPPA), M68K, M680X, Mips, MOS65XX, PPC, RISC-V(rv32G/rv64G), SH, Sparc, SystemZ, TMS320C64X, TriCore, Webassembly, XCore and X86 (16, 32, 64).
* **Supports** Delphi XE2 and greater, and FPC 3 and greater.
* **Provides** a friendly, type-safe, and easy-to-learn API.

## Installation: Manual
To install the CapstoneDelphi binding, follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/delphilite/CapstoneDelphi.git
    ```

2. Add the CapstoneDelphi\Source directory to the project or IDE's search path.

3. Ensure you have the Capstone 5 library installed on your system. You can update precompiled Capstone 5 binary libraries from [PyPI](https://pypi.org/project/capstone/), [Anaconda](https://anaconda.org/conda-forge/capstone), [ArchLinuxARM](https://archlinuxarm.org/packages), etc.

## Installation: Delphinus-Support
CapstoneDelphi should now be listed in [Delphinus package manager](https://github.com/Memnarch/Delphinus/wiki/Installing-Delphinus).

Be sure to restart Delphi after installing via Delphinus otherwise the units may not be found in your test projects.

## Usage
Included is the wrapper class `TCapstone` in `Capstone.pas`. The example bellow is incomplete, but it may give you an impression how to use it.

```pas
uses
  SysUtils, Capstone;

procedure DisAsmFunctionCode(const AFunc: Pointer; ASize: Integer = -1);
var
  aInsn: TCsInsn;
  disasm: TCapstone;
  nAddr: UInt64;
  nSize: NativeUInt;
begin
  if ASize < 0 then
    nSize := MaxInt
  else nSize := ASize;
  disasm := TCapstone.Create;
  with disasm do
  try
{$IFDEF CPUX64}
    Mode := [csm64];
{$ELSE}
    Mode := [csm32];
{$ENDIF}
    Arch := csaX86;
    nAddr := UInt64(AFunc);
    if Open(AFunc, nSize) then
      while GetNext(nAddr, aInsn) do
    begin
      WriteLn(aInsn.ToString);
      if (ASize < 0) and (aInsn.mnemonic = 'ret') then
        Break;
    end;
  finally
    Free;
  end;
end;

begin
  try
    WriteLn(Format('Capstone Engine: v%s(%s), DisAsm ExpandFileNameCase ...', [TCapstone.LibraryVersion, TCapstone.EngineVersion]));
    WriteLn('');
    DisAsmFunctionCode(@SysUtils.ExpandFileNameCase);
    WriteLn('');
    WriteLn('Done.');
    ReadLn;
  except
    on E: Exception do
      WriteLn(Format('Error Decompiler: %s', [E.Message]));
  end;
end.
```

For more examples based on low-level API, refer to the test cases under the tests directory.

## Documentation
For more detailed information, refer to the [Capstone documentation](https://www.capstone-engine.org/documentation.html).

## Contributing
Contributions are welcome! Please fork this repository and submit pull requests with your improvements.

## License
This project is licensed under the Mozilla Public License 2.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgements
Special thanks to the Capstone development team for creating and maintaining the Capstone disassembly framework.
