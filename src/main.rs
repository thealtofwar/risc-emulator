mod register;
mod utils;

use core::panic;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::u64;

use clap::Parser;
use elf::ElfBytes;
use elf::abi::ELFOSABI_LINUX;
use elf::abi::ELFOSABI_NONE;
use elf::abi::EM_RISCV;
use elf::abi::ET_EXEC;
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use elf::file::Class::ELF64;
use elf::parse::ParseAt;
use elf::segment::ProgramHeader;
use log::debug;
use log::info;
use log::trace;
use raki::Decode;
use utils::*;

use crate::register::Register;

type MemoryTable = Vec<(MemorySegment, i64)>;

#[derive(Clone)]
struct MemorySegment {
    memory: Vec<u8>,
}

fn map_address(segments: &MemoryTable, addr: i64) -> Option<(&Vec<u8>, usize)> {
    for segment in segments {
        if addr >= segment.1 && addr < segment.1 + segment.0.memory.len() as i64 {
            // guaranteed to succeed, since the length of a segment must be less than usize
            return Some((&segment.0.memory, (addr - segment.1).try_into().unwrap()));
        }
    }
    None
}

fn map_address_mut(segments: &mut MemoryTable, addr: i64) -> Option<(&mut MemorySegment, usize)> {
    for segment in segments {
        if addr >= segment.1 && addr < segment.1 + segment.0.memory.len() as i64 {
            // guaranteed to succeed, since the length of a segment must be less than usize
            return Some((&mut segment.0, (addr - segment.1).try_into().unwrap()));
        }
    }
    None
}

fn dumpregs(registers: &[Register], instruction_pointer: &Register) {
    let mut result = String::new();
    for register in registers {
        result.push_str(&format!("0x{:x} ", register));
    }
    debug!("{result} {:x}", instruction_pointer);
}

fn push_to_stack(stack_ptr: &mut usize, stack: &mut MemorySegment, value: u64) {
    stack.memory[*stack_ptr - 8..*stack_ptr].copy_from_slice(&value.to_le_bytes());
    *stack_ptr -= 8;
}

fn push_auxv(stack_ptr: &mut usize, stack: &mut MemorySegment, key: u64, value: u64) {
    push_to_stack(stack_ptr, stack, value);
    push_to_stack(stack_ptr, stack, key);
}

fn setup_auxv(stack_ptr: &mut usize, stack: &mut MemorySegment) {
    push_auxv(stack_ptr, stack, 0, 0); // AT_NULL = 0
    push_auxv(stack_ptr, stack, 11, 1000); // AT_UID(11) = 1000 
    push_auxv(stack_ptr, stack, 12, 1000); // AT_EUID(11) = 1000
    push_auxv(stack_ptr, stack, 13, 1000); // AT_GID(13) = 1000 
    push_auxv(stack_ptr, stack, 14, 1000); // AT_EGID(14) = 1000
}

fn run_elf(path: PathBuf) {
    let file_data = std::fs::read(&path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    if file.ehdr.osabi != ELFOSABI_LINUX && file.ehdr.osabi != ELFOSABI_NONE {
        panic!(
            "ELF file must be Linux ABI, is actually {}",
            file.ehdr.osabi
        );
    }
    if file.ehdr.e_machine != EM_RISCV {
        panic!("ELF file must be RISC-V");
    }
    if file.ehdr.class != ELF64 {
        panic!("ELF file must be 64-bit");
    }
    if file.ehdr.e_type != ET_EXEC {
        panic!(
            "ELF file must be an executable, is actually {}",
            file.ehdr.e_type
        );
    }
    let ph_count = file.ehdr.e_phnum;
    let ph_table = file.ehdr.e_phoff;
    let ph_entry_size = file.ehdr.e_phentsize;
    let mut segments: MemoryTable = Vec::new();

    debug!("Reading program headers");
    for i in 0..ph_count {
        let mut offset = (ph_table as usize) + (i as usize) * (ph_entry_size as usize);
        let ph = ProgramHeader::parse_at(AnyEndian::Little, ELF64, &mut offset, slice)
            .expect("Could not parse program header entry");
        if ph.p_type == PT_LOAD {
            debug!(
                "Found loadable segment, loads from 0x{:x} ({} bytes) into memory at 0x{:x} ({} bytes)",
                ph.p_offset, ph.p_filesz, ph.p_vaddr, ph.p_memsz
            );
            let mut segment = MemorySegment {
                memory: vec![0; ph.p_memsz as usize],
            };
            segment.memory[..ph.p_filesz as usize].copy_from_slice(
                &slice[ph.p_offset as usize..ph.p_offset as usize + ph.p_filesz as usize],
            );
            segments.push((segment, ph.p_vaddr as i64));
        }
    }
    debug!("Allocating stack");
    segments.push((
        MemorySegment {
            memory: vec![0; 1024 * 1024],
        },
        0xFFFFFFFF,
    ));
    let mut stack_ptr: usize = 1024 * 1024;
    let stack = &mut segments.last_mut().unwrap().0;
    setup_auxv(&mut stack_ptr, stack);
    push_to_stack(&mut stack_ptr, stack, 0); // null pointer for end of envp
    push_to_stack(&mut stack_ptr, stack, 0); // null pointer for end of argv
    push_to_stack(&mut stack_ptr, stack, 0); // argc = 0

    for segment in &segments {
        debug!(
            "Segment of length {}, starting at 0x{:x}",
            segment.0.memory.len(),
            segment.1
        );
    }

    debug!("Setting up registers");
    let mut registers = [Register::default(); 32];

    registers[2].put_i64(0xFFFFFFFF + stack_ptr as i64); // set stack pointer

    debug!("Found entrypoint {:x}", file.ehdr.e_entry);
    let mut instruction_pointer = Register {
        value: file.ehdr.e_entry.to_le_bytes(),
    };
    loop {
        let addr = map_address(&segments, instruction_pointer.get_i64()).unwrap_or_else(|| {
            panic!(
                "Tried to access {:x}, but no value exists!",
                instruction_pointer.get_i64()
            )
        });
        let slc = &addr.0[addr.1 as usize..addr.1 as usize + 4_usize];
        let val = u32::from_slice(slc);
        let insn = match val.decode(raki::Isa::Rv64) {
            Ok(insn) => {
                trace!("hex: {:x} ", val);
                io::stdout().flush().unwrap();
                insn
            }
            Err(_) => {
                let short_slc = &addr.0[addr.1 as usize..addr.1 as usize + 2_usize];
                let short_val = u16::from_le_bytes(<[u8; 2]>::try_from(short_slc).unwrap());
                trace!("hex: {:x} ", short_val);
                io::stdout().flush().unwrap();
                short_val.decode(raki::Isa::Rv64).unwrap_or_else(|_| {
                    panic!(
                        "Invalid or unsupported instruction at {:x}!",
                        instruction_pointer.get_i64()
                    )
                })
            }
        };
        debug!("{}", insn);
        match insn.opc {
            raki::OpcodeKind::BaseI(base_iopcode) => {
                match base_iopcode {
                    raki::BaseIOpcode::LUI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(insn.imm.unwrap() as i64);
                        }
                    }
                    raki::BaseIOpcode::AUIPC => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()]
                                .put_i64(instruction_pointer.get_i64() + insn.imm.unwrap() as i64);
                        }
                    }
                    raki::BaseIOpcode::JAL => {
                        let return_addr = instruction_pointer.get_i64() + 4;
                        instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(return_addr);
                        }
                        dumpregs(&registers, &instruction_pointer);
                        continue;
                    }
                    raki::BaseIOpcode::JALR => {
                        let return_addr = instruction_pointer.get_i64() + 4;
                        instruction_pointer.put_i64(
                            (registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64)
                                & !1,
                        );
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(return_addr);
                        }
                        dumpregs(&registers, &instruction_pointer);
                        continue;
                    }
                    // above is last verified operation
                    raki::BaseIOpcode::BEQ => {
                        if registers[insn.rs1.unwrap()] == registers[insn.rs2.unwrap()] {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    raki::BaseIOpcode::BNE => {
                        if registers[insn.rs1.unwrap()].value != registers[insn.rs2.unwrap()].value
                        {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    raki::BaseIOpcode::BLT => {
                        if registers[insn.rs1.unwrap()].get_i64()
                            < registers[insn.rs2.unwrap()].get_i64()
                        {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    raki::BaseIOpcode::BGE => {
                        if registers[insn.rs1.unwrap()].get_i64()
                            >= registers[insn.rs2.unwrap()].get_i64()
                        {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    raki::BaseIOpcode::BLTU => {
                        if registers[insn.rs1.unwrap()].get_u64()
                            < registers[insn.rs2.unwrap()].get_u64()
                        {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    raki::BaseIOpcode::BGEU => {
                        if registers[insn.rs1.unwrap()].get_u64()
                            >= registers[insn.rs2.unwrap()].get_u64()
                        {
                            instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                            dumpregs(&registers, &instruction_pointer);
                            continue;
                        }
                    }
                    // bottom few are verified
                    raki::BaseIOpcode::LB => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_i64((i8::from_le_bytes([segment[addr]])).sign_ext(8));
                        }
                    }
                    raki::BaseIOpcode::LH => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_i64((i16::from_slice(&segment[addr..addr + 2])).sign_ext(16));
                        }
                    }
                    raki::BaseIOpcode::LW => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_i64((i32::from_slice(&segment[addr..addr + 4])).sign_ext(32));
                        }
                    }
                    raki::BaseIOpcode::LD => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_i64(i64::from_slice(&segment[addr..addr + 8]));
                        }
                    }
                    raki::BaseIOpcode::LBU => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()].put_u64(segment[addr] as u64);
                        }
                    }
                    raki::BaseIOpcode::LHU => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_u64(u16::from_slice(&segment[addr..addr + 2]) as u64);
                        }
                    }
                    raki::BaseIOpcode::LWU => {
                        if insn.rd.unwrap() != 0 {
                            let virtual_address =
                                registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                            let (segment, addr) = map_address(&segments, virtual_address)
                                .unwrap_or_else(|| {
                                    panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                                });
                            registers[insn.rd.unwrap()]
                                .put_u64(u32::from_slice(&segment[addr..addr + 4]) as u64);
                        }
                    }
                    raki::BaseIOpcode::SB => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = map_address_mut(&mut segments, virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment.memory[addr] = registers[insn.rs2.unwrap()].value[0];
                    }
                    raki::BaseIOpcode::SH => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = map_address_mut(&mut segments, virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment.memory[addr..addr + 2]
                            .copy_from_slice(&registers[insn.rs2.unwrap()].value[0..2]);
                    }
                    raki::BaseIOpcode::SW => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = map_address_mut(&mut segments, virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment.memory[addr..addr + 4]
                            .copy_from_slice(&registers[insn.rs2.unwrap()].value[0..4]);
                    }
                    raki::BaseIOpcode::SD => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = map_address_mut(&mut segments, virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment.memory[addr..addr + 8]
                            .copy_from_slice(&registers[insn.rs2.unwrap()].value);
                    }
                    raki::BaseIOpcode::ADDI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()]
                                    .get_i64()
                                    .wrapping_add(insn.imm.unwrap() as i64),
                            );
                        }
                    }
                    raki::BaseIOpcode::SLTI => {
                        if insn.rd.unwrap() != 0 {
                            let less_than =
                                registers[insn.rs1.unwrap()].get_i64() < insn.imm.unwrap() as i64;
                            registers[insn.rd.unwrap()].put_i64(if less_than { 1 } else { 0 });
                        }
                    }
                    raki::BaseIOpcode::SLTIU => {
                        if insn.rd.unwrap() != 0 {
                            let sign_extended_unsigned =
                                u64::from_ne_bytes(insn.imm.unwrap().sign_ext(12).to_ne_bytes());
                            let less_than =
                                registers[insn.rs1.unwrap()].get_u64() < sign_extended_unsigned;
                            registers[insn.rd.unwrap()].put_i64(if less_than { 1 } else { 0 });
                        }
                    }
                    raki::BaseIOpcode::XORI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()].get_i64() ^ insn.imm.unwrap() as i64,
                            );
                        }
                    }
                    raki::BaseIOpcode::ORI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()].get_i64() | insn.imm.unwrap() as i64,
                            );
                        }
                    }
                    raki::BaseIOpcode::ANDI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()].get_i64() & insn.imm.unwrap() as i64,
                            );
                        }
                    }
                    raki::BaseIOpcode::SLLI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64() << insn.imm.unwrap() as u64,
                            );
                        }
                    }
                    raki::BaseIOpcode::SRLI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64() >> insn.imm.unwrap() as u64,
                            );
                        }
                    }
                    raki::BaseIOpcode::SRAI => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()].get_i64() >> insn.imm.unwrap() as i64,
                            );
                        }
                    }
                    raki::BaseIOpcode::ADD => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()]
                                    .get_i64()
                                    .wrapping_add(registers[insn.rs2.unwrap()].get_i64()),
                            );
                        }
                    }
                    raki::BaseIOpcode::SUB => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()]
                                    .get_i64()
                                    .wrapping_sub(registers[insn.rs2.unwrap()].get_i64()),
                            );
                        }
                    }
                    raki::BaseIOpcode::SLL => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    << (registers[insn.rs2.unwrap()].get_u64() & ((1 << 6) - 1)),
                            );
                        }
                    }
                    raki::BaseIOpcode::SLT => {
                        if insn.rd.unwrap() != 0 {
                            let less_than = registers[insn.rs1.unwrap()].get_i64()
                                < registers[insn.rs2.unwrap()].get_i64();
                            registers[insn.rd.unwrap()].put_i64(if less_than { 1 } else { 0 });
                        }
                    }
                    raki::BaseIOpcode::SLTU => {
                        if insn.rd.unwrap() != 0 {
                            let less_than = registers[insn.rs1.unwrap()].get_u64()
                                < registers[insn.rs2.unwrap()].get_u64();
                            registers[insn.rd.unwrap()].put_i64(if less_than { 1 } else { 0 });
                        }
                    }
                    raki::BaseIOpcode::XOR => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    ^ registers[insn.rs2.unwrap()].get_u64(),
                            );
                        }
                    }
                    raki::BaseIOpcode::SRL => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    >> (registers[insn.rs2.unwrap()].get_u64() & ((1 << 6) - 1)),
                            );
                        }
                    }
                    raki::BaseIOpcode::SRA => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(
                                registers[insn.rs1.unwrap()].get_i64()
                                    >> (registers[insn.rs2.unwrap()].get_u64() & ((1 << 6) - 1)),
                            );
                        }
                    }
                    raki::BaseIOpcode::OR => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    | registers[insn.rs2.unwrap()].get_u64(),
                            );
                        }
                    }
                    raki::BaseIOpcode::AND => {
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    & registers[insn.rs2.unwrap()].get_u64(),
                            );
                        }
                    }
                    raki::BaseIOpcode::ECALL => {
                        debug!("syscall with {}", registers[17].get_i64());
                        match registers[17].get_i64() {
                            48 => {
                                let addr = registers[11].get_i64();
                                let mut mem = map_address(&segments, addr).unwrap_or_else(|| {
                                    panic!("Tried to read {addr}, but it was not mapped!")
                                });
                                let mut chars: Vec<u8> = vec![];
                                while mem.0[mem.1] != 0 {
                                    chars.push(mem.0[mem.1]);
                                    mem.1 += 1;
                                }
                                info!(
                                    "Tried to access {}",
                                    str::from_utf8(chars.as_slice()).unwrap()
                                );
                                registers[10].put_i64(-2); // ENOENT
                            }
                            64 => {
                                // write syscall
                                if registers[10].get_u64() == 1 {
                                    // stdout
                                    let mut stdout = io::stdout().lock();
                                    let mem = map_address(&segments, registers[11].get_i64()).unwrap_or_else(|| panic!("Tried to output memory from non-existant address {}", registers[11].get_i64()));
                                    let len = registers[12].get_u64() as usize;
                                    match stdout.write(&mem.0[mem.1..mem.1 + len]) {
                                        Ok(written) => {
                                            registers[10].put_i64(written as i64);
                                        }
                                        Err(_) => {
                                            registers[10].put_i64(-1);
                                        }
                                    }
                                }
                            }
                            93 => {
                                exit(registers[10].get_i64() as i32);
                            }
                            174 | 175 | 176 | 177 => {
                                // checking uid, euid, gid, egid
                                registers[10].put_i64(1000);
                            }
                            214 => {
                                // BRK
                                let value = registers[11].get_u64();
                                debug!("Tried expanding memory to {value:x}");
                                todo!();
                            }
                            _ => todo!(),
                        }
                    }
                    raki::BaseIOpcode::EBREAK => todo!(),
                    raki::BaseIOpcode::ADDIW => {
                        if insn.rd.unwrap() != 0 {
                            let sum =
                                insn.imm.unwrap() as i64 + registers[insn.rs1.unwrap()].get_i64();
                            registers[insn.rd.unwrap()].put_i64(sum.sign_ext(32));
                        }
                    }
                    raki::BaseIOpcode::SLLIW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted =
                                registers[insn.rs1.unwrap()].get_u64() << insn.imm.unwrap();
                            registers[insn.rd.unwrap()].put_i64(shifted as i32 as i64)
                        }
                    }
                    raki::BaseIOpcode::SRLIW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted =
                                registers[insn.rs1.unwrap()].get_u64() as u32 >> insn.imm.unwrap();
                            registers[insn.rd.unwrap()].put_i64(shifted as i32 as i64);
                        }
                    }
                    raki::BaseIOpcode::SRAIW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted =
                                registers[insn.rs1.unwrap()].get_i64() as i32 >> insn.imm.unwrap();
                            registers[insn.rd.unwrap()].put_i64(shifted as i64);
                        }
                    }
                    raki::BaseIOpcode::ADDW => {
                        if insn.rd.unwrap() != 0 {
                            let sum = (registers[insn.rs1.unwrap()].get_i64() as i32)
                                .wrapping_add(registers[insn.rs2.unwrap()].get_i64() as i32);
                            registers[insn.rd.unwrap()].put_i64(sum as i64);
                        }
                    }
                    raki::BaseIOpcode::SUBW => {
                        if insn.rd.unwrap() != 0 {
                            let sum = (registers[insn.rs1.unwrap()].get_i64() as i32)
                                .wrapping_sub(registers[insn.rs2.unwrap()].get_i64() as i32);
                            registers[insn.rd.unwrap()].put_i64(sum as i64);
                        }
                    }
                    raki::BaseIOpcode::SLLW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted = registers[insn.rs1.unwrap()].get_u64()
                                << (registers[insn.rs2.unwrap()].get_u64() & ((1 << 5) - 1));
                            registers[insn.rd.unwrap()].put_i64(shifted as i32 as i64)
                        }
                    }
                    raki::BaseIOpcode::SRLW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted = registers[insn.rs1.unwrap()].get_u64() as u32
                                >> (registers[insn.rs2.unwrap()].get_u64() & ((1 << 5) - 1));
                            registers[insn.rd.unwrap()].put_i64(shifted as i32 as i64);
                        }
                    }
                    raki::BaseIOpcode::SRAW => {
                        if insn.rd.unwrap() != 0 {
                            let shifted = registers[insn.rs1.unwrap()].get_i64() as i32
                                >> (registers[insn.rs2.unwrap()].get_u64() & ((1 << 5) - 1));
                            registers[insn.rd.unwrap()].put_i64(shifted as i64);
                        }
                    }
                }
            }
            raki::OpcodeKind::M(mopcode) => todo!(),
            raki::OpcodeKind::A(aopcode) => todo!(),
            raki::OpcodeKind::C(copcode) => match copcode {
                raki::COpcode::ADDI4SPN => todo!(),
                raki::COpcode::LW => todo!(),
                raki::COpcode::SW => todo!(),
                raki::COpcode::NOP => todo!(),
                raki::COpcode::ADDI => todo!(),
                raki::COpcode::JAL => todo!(),
                raki::COpcode::LI => todo!(),
                raki::COpcode::ADDI16SP => todo!(),
                raki::COpcode::LUI => todo!(),
                raki::COpcode::SRLI => todo!(),
                raki::COpcode::SRAI => todo!(),
                raki::COpcode::ANDI => todo!(),
                raki::COpcode::SUB => todo!(),
                raki::COpcode::XOR => todo!(),
                raki::COpcode::OR => todo!(),
                raki::COpcode::AND => todo!(),
                raki::COpcode::J => todo!(),
                raki::COpcode::BEQZ => todo!(),
                raki::COpcode::BNEZ => todo!(),
                raki::COpcode::SLLI => todo!(),
                raki::COpcode::LWSP => todo!(),
                raki::COpcode::JR => {
                    instruction_pointer.put_i64(registers[insn.rs1.unwrap()].get_i64());
                    dumpregs(&registers, &instruction_pointer);
                    continue;
                }
                raki::COpcode::MV => {
                    registers[insn.rd.unwrap()].value = registers[insn.rs2.unwrap()].value;
                }
                raki::COpcode::EBREAK => todo!(),
                raki::COpcode::JALR => todo!(),
                raki::COpcode::ADD => todo!(),
                raki::COpcode::SWSP => todo!(),
                raki::COpcode::LD => todo!(),
                raki::COpcode::SD => todo!(),
                raki::COpcode::ADDIW => todo!(),
                raki::COpcode::SUBW => todo!(),
                raki::COpcode::ADDW => todo!(),
                raki::COpcode::LDSP => todo!(),
                raki::COpcode::SDSP => todo!(),
            },
            raki::OpcodeKind::Zifencei(zifencei_opcode) => todo!(),
            raki::OpcodeKind::Zicboz(zicboz_opcode) => todo!(),
            raki::OpcodeKind::Zicsr(zicsr_opcode) => todo!(),
            raki::OpcodeKind::Zicfiss(zicfiss_opcode) => todo!(),
            raki::OpcodeKind::Zicntr(zicntr_opcode) => todo!(),
            raki::OpcodeKind::Priv(priv_opcode) => todo!(),
        }
        dumpregs(&registers, &instruction_pointer);
        let insn_size = if insn.is_compressed { 2 } else { 4 };
        instruction_pointer.incr_i64(insn_size);
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    file_name: String,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    run_elf(Path::new(&args.file_name).to_path_buf());
}
