# ARM Base64 Base64 Decoder [![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
A Tool For Converting any ARM Shellcode to Equivalent Shellcode, But Where Every Byte is a Valid Base64 Character

It converts the payload to Base64, and generates a program containing a polymorphic Base64 decoder. This effectively removes any invalid characters, including null bytes and whitespace, from any ARM shellcode.
This allows the shellcode to bypass common input validation techniques

## Usage

  Run:
  
      python3 generate.py [payload source]

  Two demonstration payloads are included

  It outputs the generated ARM source to arm.s, the outputted shellcode to arm.bin, and generates an ELF executable for testing

## Dependencies

	Requires Python 3. Built with Python 3.6.8
	This requires the "arm-linux-gnueabihf" GNU toolchain, as the script makes system calls to arm-linux-gnueabihf-as, ld and objcopy
	Optionally requires qemu-arm or a physical ARM processor to run the executable or shellcode
  
## Notes

  The Base64 alphabet this uses is 0-9,a-z,A-Z,+,/ and =

  While the shellcode only contains valid Base64, the executable does not as there is no valid binary executable file format available
  
  All of the shellcode in the payload must be in the .text section
  
  In addition to this, the execution of the payload starts in ARM mode, not Thumb mode