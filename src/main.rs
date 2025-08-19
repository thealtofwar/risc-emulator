mod kernel_io;
mod memory;
mod register;
mod time;
mod user;
mod utils;

use core::panic;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

use bytemuck::bytes_of;
use bytemuck::cast_slice;
use bytemuck::from_bytes;
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
use rand::TryRngCore;
use rand::rngs::OsRng;
use utils::*;

use crate::kernel_io::iovec;
use crate::memory::MemorySegment;
use crate::memory::MemoryTable;
use crate::register::Register;
use crate::time::timespec;
use crate::user::new_utsname;

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

fn setup_random(host_stack_ptr: &mut usize, stack: &mut MemorySegment) -> usize {
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .expect("Could not fill 16 bytes using OS rng");
    stack.memory[*host_stack_ptr - 16..*host_stack_ptr].copy_from_slice(&random);
    *host_stack_ptr -= 16;
    *host_stack_ptr
}

fn push_auxv(host_stack_ptr: &mut usize, stack: &mut MemorySegment, key: u64, value: u64) {
    push_to_stack(host_stack_ptr, stack, value);
    push_to_stack(host_stack_ptr, stack, key);
}

fn setup_auxv(host_stack_ptr: &mut usize, stack: &mut MemorySegment, guest_start_of_stack: usize) {
    let host_random_addr = setup_random(host_stack_ptr, stack);
    push_auxv(host_stack_ptr, stack, 0, 0); // AT_NULL = 0
    push_auxv(host_stack_ptr, stack, 11, 1000); // AT_UID(11) = 1000 
    push_auxv(host_stack_ptr, stack, 12, 1000); // AT_EUID(11) = 1000
    push_auxv(host_stack_ptr, stack, 13, 1000); // AT_GID(13) = 1000 
    push_auxv(host_stack_ptr, stack, 14, 1000); // AT_EGID(14) = 1000
    push_auxv(
        host_stack_ptr,
        stack,
        25,
        (host_random_addr + guest_start_of_stack)
            .try_into()
            .unwrap(),
    );
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
    let mut memory_table: MemoryTable = MemoryTable::new();

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
            memory_table.push((segment, ph.p_vaddr as i64));
        }
    }
    debug!("Allocating stack");
    let guest_start_of_stack = 0x7FFFFFFF00000000i64; // Use a more standard initial stack address
    memory_table.push((
        MemorySegment {
            memory: vec![0; 2 * 1024 * 1024], // Use a larger stack (2MB)
        },
        guest_start_of_stack,
    ));
    let mut stack_ptr: usize = 2 * 1024 * 1024;
    let stack = &mut memory_table.last_mut().unwrap().0;
    setup_auxv(
        &mut stack_ptr,
        stack,
        guest_start_of_stack.try_into().unwrap(),
    );
    push_to_stack(&mut stack_ptr, stack, 0); // null pointer for end of envp
    push_to_stack(&mut stack_ptr, stack, 0); // null pointer for end of argv
    push_to_stack(&mut stack_ptr, stack, 0); // argc = 0

    for segment in &memory_table {
        debug!(
            "Segment of length {}, starting at 0x{:x}",
            segment.0.memory.len(),
            segment.1
        );
    }

    debug!("Setting up registers");
    let mut registers = [Register::default(); 32];

    registers[2].put_i64(guest_start_of_stack + stack_ptr as i64); // set stack pointer
    registers[3].put_i64(0);

    debug!("Found entrypoint {:x}", file.ehdr.e_entry);
    let mut instruction_pointer = Register {
        value: file.ehdr.e_entry.to_le_bytes(),
    };
    let start = Instant::now();
    loop {
        let addr = memory_table
            .map_address(instruction_pointer.get_i64())
            .unwrap_or_else(|| {
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                            let (segment, addr) = memory_table
                                .map_address(virtual_address)
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
                        let (segment, addr) = memory_table
                            .map_address_mut(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment[addr] = registers[insn.rs2.unwrap()].value[0];
                    }
                    raki::BaseIOpcode::SH => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address_mut(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment[addr..addr + 2]
                            .copy_from_slice(&registers[insn.rs2.unwrap()].value[0..2]);
                    }
                    raki::BaseIOpcode::SW => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address_mut(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment[addr..addr + 4]
                            .copy_from_slice(&registers[insn.rs2.unwrap()].value[0..4]);
                    }
                    raki::BaseIOpcode::SD => {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address_mut(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment[addr..addr + 8]
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
                            48 | 78 => {
                                let addr = registers[11].get_i64();
                                let mut mem = memory_table.map_address(addr).unwrap_or_else(|| {
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
                                    let mem = memory_table.map_address(registers[11].get_i64()).unwrap_or_else(|| panic!("Tried to output memory from non-existant address {}", registers[11].get_i64()));
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
                            66 => {
                                // writev syscall
                                let mut stdout = io::stdout().lock();
                                println!("Tried to write to fd {}", registers[10].get_u64());
                                println!("Writing {} messages", registers[12].get_u64());
                                let addr = registers[11].get_i64();
                                let (mem, index) =
                                    memory_table.map_address(addr).unwrap_or_else(|| {
                                        panic!("Tried to read {addr}, but it was not mapped")
                                    });
                                for i in 0..registers[12].get_u64() as usize {
                                    let io_vec: &iovec = from_bytes(&mem[index + i * size_of::<iovec>()..index + (i + 1) * size_of::<iovec>()]);
                                    let mem = memory_table.map_address(io_vec.iov_base as i64).unwrap_or_else(|| panic!("Tried to output memory from non-existant address {}", registers[11].get_i64()));
                                    let len = io_vec.iov_len as usize;
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
                            96 => {
                                registers[10].put_i64(0);
                                // set_tid_address
                                // no-op, new threads cannot be created
                            }
                            99 => {
                                registers[10].put_i64(0);
                                // set_robust_list
                                // no-op, futexes will not notify other threads because new threads cannot be created
                            }
                            113 => {
                                // clock_gettime
                                if registers[10].get_u64() == 1 {
                                    // monotonic
                                    let addr = registers[11].get_u64();
                                    let (mem, addr) = memory_table
                                        .map_address_mut(addr as i64)
                                        .unwrap_or_else(|| {
                                            panic!(
                                                "Tried to write to {addr}, but it was not mapped!"
                                            )
                                        });
                                    let now = Instant::now();
                                    let diff = now - start;
                                    let time = timespec {
                                        tv_sec: diff.as_secs() as i64,
                                        tv_nsec: (diff.as_nanos() % 1_000_000_000) as i64,
                                    };
                                    mem[addr..addr + size_of::<timespec>()]
                                        .copy_from_slice(bytes_of(&time));
                                } else {
                                    todo!();
                                }
                            }
                            160 => {
                                let addr = registers[10].get_u64();
                                let (mem, addr) = memory_table
                                    .map_address_mut(addr as i64)
                                    .unwrap_or_else(|| {
                                        panic!("Tried to write to {addr}, but it was not mapped!")
                                    });
                                mem[addr..addr + size_of::<new_utsname>()]
                                    .copy_from_slice(bytes_of(&new_utsname::default()));
                                registers[10].put_i64(0);
                            }
                            174 | 175 | 176 | 177 => {
                                // checking uid, euid, gid, egid
                                registers[10].put_i64(1000);
                            }
                            214 => {
                                // BRK
                                let value = registers[10].get_i64();
                                let num_segments = memory_table.len();
                                let cur_heap = &mut memory_table[num_segments - 2];
                                let new_len = cur_heap.0.memory.len() + value as usize;
                                cur_heap.0.memory.resize(new_len, 0u8);
                                registers[10].put_i64(cur_heap.1 + cur_heap.0.memory.len() as i64);
                            }
                            261 => 'call: {
                                // prlimit64
                                let pid = registers[10].get_i64();
                                let resource = registers[11].get_u64();
                                let new_rlim = registers[12].get_u64();
                                let old_rlim = registers[13].get_u64();
                                if pid != 0 {
                                    registers[10].put_i64(-1); // EPERM
                                    break 'call;
                                }
                                if new_rlim != 0 {
                                    // no-op, this kernel does not enforce resource limits anyways
                                }
                                if old_rlim != 0 {
                                    // write RLIM_INFINITY to old_rlim
                                    let (mem, addr) = memory_table.map_address_mut(old_rlim as i64).unwrap_or_else(|| {
                                        panic!("Tried to write to {old_rlim}, but it was not mapped!")
                                    });
                                    mem[addr..addr + 16].copy_from_slice(cast_slice(&[0u128]));
                                }
                            }
                            278 => {
                                let buf = registers[10].get_i64();
                                let count = registers[11].get_u64();
                                let (mem, addr) =
                                    memory_table.map_address_mut(buf as i64).unwrap_or_else(|| {
                                        panic!("Tried to write to {buf}, but it was not mapped!")
                                    });
                                OsRng
                                    .try_fill_bytes(&mut mem[addr..addr + count as usize])
                                    .expect("Couldn't use OS rng");
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
            raki::OpcodeKind::M(mopcode) => match mopcode {
                raki::MOpcode::MUL => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[insn.rd.unwrap()]
                                .get_i64()
                                .wrapping_mul(registers[insn.rs2.unwrap()].get_i64()),
                        );
                    }
                }
                raki::MOpcode::MULH => todo!(),
                raki::MOpcode::MULHSU => todo!(),
                raki::MOpcode::MULHU => todo!(),
                raki::MOpcode::DIV => todo!(),
                raki::MOpcode::DIVU => {
                    if insn.rd.unwrap() != 0 {
                        if registers[insn.rs2.unwrap()].get_u64() == 0 {
                            registers[insn.rd.unwrap()].put_u64(u64::MAX);
                        } else {
                            registers[insn.rd.unwrap()].put_u64(
                                registers[insn.rs1.unwrap()].get_u64()
                                    / registers[insn.rs2.unwrap()].get_u64(),
                            );
                        }
                    }
                }
                raki::MOpcode::REM => todo!(),
                raki::MOpcode::REMU => todo!(),
                raki::MOpcode::MULW => todo!(),
                raki::MOpcode::DIVW => todo!(),
                raki::MOpcode::DIVUW => todo!(),
                raki::MOpcode::REMW => todo!(),
                raki::MOpcode::REMUW => todo!(),
            },
            raki::OpcodeKind::A(aopcode) => match aopcode {
                raki::AOpcode::LR_W => {
                    // safe to copy LR implementation here, single threaded
                    let virtual_address = registers[insn.rs1.unwrap()].get_i64();
                    if insn.rd.unwrap() != 0 {
                        let (segment, addr) = memory_table
                            .map_address(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        registers[insn.rd.unwrap()]
                            .put_i64((i32::from_slice(&segment[addr..addr + 4])).sign_ext(32));
                    }
                    memory_table.reserve(virtual_address, 4);
                }
                raki::AOpcode::SC_W => {
                    let virtual_address = registers[insn.rs1.unwrap()].get_i64();
                    if !memory_table.check_reservation(virtual_address, 4) {
                        memory_table.invalidate_reservation();
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(1);
                        }
                    } else {
                        let (segment, addr) = memory_table
                            .map_address_mut(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        segment[addr..addr + 4].copy_from_slice(&registers[insn.rs2.unwrap()].value[0..4]);
                        if insn.rd.unwrap() != 0 {
                            registers[insn.rd.unwrap()].put_i64(0);
                        }
                    }
                }
                raki::AOpcode::AMOSWAP_W => {
                    let virtual_address = registers[insn.rs1.unwrap()].get_i64();
                    let (mem, addr) = memory_table
                        .map_address_mut(virtual_address)
                        .unwrap_or_else(|| {
                            panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                        });
                    let m_word = i32::from_slice(&mem[addr..addr + 4]);
                    let r_word = registers[insn.rs2.unwrap()].get_u64() as u32;
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(m_word.sign_ext(32));
                    }
                    mem[addr..addr + 4].copy_from_slice(&r_word.to_le_bytes());
                }
                raki::AOpcode::AMOADD_W => todo!(),
                raki::AOpcode::AMOXOR_W => todo!(),
                raki::AOpcode::AMOAND_W => todo!(),
                raki::AOpcode::AMOOR_W => todo!(),
                raki::AOpcode::AMOMIN_W => todo!(),
                raki::AOpcode::AMOMAX_W => todo!(),
                raki::AOpcode::AMOMINU_W => todo!(),
                raki::AOpcode::AMOMAXU_W => todo!(),
                raki::AOpcode::LR_D => todo!(),
                raki::AOpcode::SC_D => todo!(),
                raki::AOpcode::AMOSWAP_D => todo!(),
                raki::AOpcode::AMOADD_D => todo!(),
                raki::AOpcode::AMOXOR_D => todo!(),
                raki::AOpcode::AMOAND_D => todo!(),
                raki::AOpcode::AMOOR_D => todo!(),
                raki::AOpcode::AMOMIN_D => todo!(),
                raki::AOpcode::AMOMAX_D => todo!(),
                raki::AOpcode::AMOMINU_D => todo!(),
                raki::AOpcode::AMOMAXU_D => todo!(),
            },
            raki::OpcodeKind::C(copcode) => match copcode {
                raki::COpcode::ADDI4SPN => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[2]
                                .get_i64()
                                .wrapping_add(insn.imm.unwrap() as i64),
                        );
                    }
                }
                raki::COpcode::LW => {
                    if insn.rd.unwrap() != 0 {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        registers[insn.rd.unwrap()]
                            .put_i64((i32::from_slice(&segment[addr..addr + 4])).sign_ext(32));
                    }
                }
                raki::COpcode::SW => {
                    let virtual_address =
                        registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                    let (segment, addr) = memory_table
                        .map_address_mut(virtual_address)
                        .unwrap_or_else(|| {
                            panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                        });
                    segment[addr..addr + 4]
                        .copy_from_slice(&registers[insn.rs2.unwrap()].value[0..4]);
                }
                raki::COpcode::NOP => {}
                raki::COpcode::ADDI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[insn.rd.unwrap()]
                                .get_i64()
                                .wrapping_add(insn.imm.unwrap() as i64),
                        );
                    }
                }
                raki::COpcode::JAL => todo!(),
                raki::COpcode::LI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(insn.imm.unwrap() as i64);
                    }
                }
                raki::COpcode::ADDI16SP => {
                    registers[2].incr_i64(insn.imm.unwrap() as i64);
                }
                raki::COpcode::LUI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(insn.imm.unwrap() as i64);
                    }
                }
                raki::COpcode::SRLI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_u64(
                            registers[insn.rd.unwrap()].get_u64() >> insn.imm.unwrap() as u64,
                        );
                    }
                }
                raki::COpcode::SRAI => todo!(),
                raki::COpcode::ANDI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[insn.rd.unwrap()].get_i64() & insn.imm.unwrap() as i64,
                        );
                    }
                }
                raki::COpcode::SUB => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[insn.rd.unwrap()]
                                .get_i64()
                                .wrapping_sub(registers[insn.rs2.unwrap()].get_i64()),
                        );
                    }
                }
                raki::COpcode::XOR => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_u64(
                            registers[insn.rd.unwrap()].get_u64()
                                ^ registers[insn.rs2.unwrap()].get_u64(),
                        );
                    }
                }
                raki::COpcode::OR => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_u64(
                            registers[insn.rd.unwrap()].get_u64()
                                | registers[insn.rs2.unwrap()].get_u64(),
                        );
                    }
                }
                raki::COpcode::AND => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_u64(
                            registers[insn.rd.unwrap()].get_u64()
                                & registers[insn.rs2.unwrap()].get_u64(),
                        );
                    }
                }
                raki::COpcode::J => {
                    instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                    dumpregs(&registers, &instruction_pointer);
                    continue;
                }
                raki::COpcode::BEQZ => {
                    if registers[insn.rs1.unwrap()].get_i64() == 0 {
                        instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                        dumpregs(&registers, &instruction_pointer);
                        continue;
                    }
                }
                raki::COpcode::BNEZ => {
                    if registers[insn.rs1.unwrap()].get_i64() != 0 {
                        instruction_pointer.incr_i64(insn.imm.unwrap() as i64);
                        dumpregs(&registers, &instruction_pointer);
                        continue;
                    }
                }
                raki::COpcode::SLLI => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_u64(
                            registers[insn.rd.unwrap()].get_u64() << insn.imm.unwrap() as u64,
                        );
                    }
                }
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
                raki::COpcode::ADD => {
                    if insn.rd.unwrap() != 0 {
                        registers[insn.rd.unwrap()].put_i64(
                            registers[insn.rd.unwrap()]
                                .get_i64()
                                .wrapping_add(registers[insn.rs2.unwrap()].get_i64()),
                        );
                    }
                }
                raki::COpcode::SWSP => todo!(),
                raki::COpcode::LD => {
                    if insn.rd.unwrap() != 0 {
                        let virtual_address =
                            registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        registers[insn.rd.unwrap()]
                            .put_i64(i64::from_slice(&segment[addr..addr + 8]));
                    }
                }
                raki::COpcode::SD => {
                    let virtual_address =
                        registers[insn.rs1.unwrap()].get_i64() + insn.imm.unwrap() as i64;
                    let (segment, addr) = memory_table
                        .map_address_mut(virtual_address)
                        .unwrap_or_else(|| {
                            panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                        });
                    segment[addr..addr + 8].copy_from_slice(&registers[insn.rs2.unwrap()].value);
                }
                raki::COpcode::ADDIW => {
                    if insn.rd.unwrap() != 0 {
                        let sum = insn.imm.unwrap() as i64 + registers[insn.rd.unwrap()].get_i64();
                        registers[insn.rd.unwrap()].put_i64(sum.sign_ext(32));
                    }
                }
                raki::COpcode::SUBW => todo!(),
                raki::COpcode::ADDW => {
                    if insn.rd.unwrap() != 0 {
                        let sum = (registers[insn.rd.unwrap()].get_i64() as i32)
                            .wrapping_add(registers[insn.rs2.unwrap()].get_i64() as i32);
                        registers[insn.rd.unwrap()].put_i64(sum as i64);
                    }
                }
                raki::COpcode::LDSP => {
                    if insn.rd.unwrap() != 0 {
                        let virtual_address = registers[2].get_i64() + insn.imm.unwrap() as i64;
                        let (segment, addr) = memory_table
                            .map_address(virtual_address)
                            .unwrap_or_else(|| {
                                panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                            });
                        registers[insn.rd.unwrap()]
                            .put_i64(i64::from_slice(&segment[addr..addr + 8]));
                    }
                }
                raki::COpcode::SDSP => {
                    let virtual_address = registers[2].get_i64() + insn.imm.unwrap() as i64;
                    let (segment, addr) = memory_table
                        .map_address_mut(virtual_address)
                        .unwrap_or_else(|| {
                            panic!("Tried to map {virtual_address}, but it wasn't mapped!")
                        });
                    segment[addr..addr + 8].copy_from_slice(&registers[insn.rs2.unwrap()].value);
                }
            },
            raki::OpcodeKind::Zifencei(zifencei_opcode) => {
                match zifencei_opcode {
                    raki::ZifenceiOpcode::FENCE => {
                        // emulation of single threaded machine, fence is noop
                    }
                }
            }
            raki::OpcodeKind::Zicboz(zicboz_opcode) => todo!(),
            raki::OpcodeKind::Zicsr(zicsr_opcode) => todo!(),
            raki::OpcodeKind::Zicfiss(zicfiss_opcode) => todo!(),
            raki::OpcodeKind::Zicntr(zicntr_opcode) => todo!(),
            raki::OpcodeKind::Priv(priv_opcode) => todo!(),
        }
        assert!(registers[0].get_i64() == 0);
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
