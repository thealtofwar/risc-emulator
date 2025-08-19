# risc-emulator

RISC-V emulator that emulates user-level Linux binaries.

## Usage
```
risc-emulator <binary>
```
Configure logging using `RUST_LOG` like so

```
RUST_LOG=trace risc-emulator <binary>
```


## Features
- I extension implemented and tested with [riscv-tests](https://github.com/riscv-software-src/riscv-tests)
- Writing to STDOUT

## Roadmap

- [ ] C extension
- [ ] Running a binary compiled with gcc
- [ ] GDB integration