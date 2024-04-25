//! Support for parsing Mach-O format

#[cfg(feature = "alloc")]
use core::iter::FusedIterator;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(feature = "alloc")]
use crate::{string::ArrayCString, Error};
use crate::{Address, PointerSize, Process};

// Magic mach-o header constants from:
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
const MH_MAGIC_32: u32 = 0xfeedface;
const MH_CIGAM_32: u32 = 0xcefaedfe;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe;

/// Checks if a given Mach-O module is 64-bit or 32-bit
pub fn pointer_size(process: &Process, range: (Address, u64)) -> Option<PointerSize> {
    match process.read::<u32>(scan_macho_page(process, range)?).ok()? {
        MH_MAGIC_64 | MH_CIGAM_64 => Some(PointerSize::Bit64),
        MH_MAGIC_32 | MH_CIGAM_32 => Some(PointerSize::Bit32),
        _ => None,
    }
}

/// Scans the range for a page that begins with Mach-O Magic
fn scan_macho_page(process: &Process, range: (Address, u64)) -> Option<Address> {
    const PAGE_SIZE: u64 = 0x1000;
    let (addr, len) = range;
    // negation mod PAGE_SIZE
    let distance_to_page = (PAGE_SIZE - (addr.value() % PAGE_SIZE)) % PAGE_SIZE;
    // round up to the next multiple of PAGE_SIZE
    let first_page = addr + distance_to_page;
    for i in 0..((len - distance_to_page) / PAGE_SIZE) {
        let a = first_page + (i * PAGE_SIZE);
        match process.read::<u32>(a) {
            Ok(MH_MAGIC_64 | MH_CIGAM_64 | MH_MAGIC_32 | MH_CIGAM_32) => {
                return Some(a);
            }
            _ => (),
        }
    }
    None
}

// Constants for the cmd field of load commands, the type
// https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
/// link-edit stab symbol table info
#[cfg(feature = "alloc")]
const LC_SYMTAB: u32 = 0x2;
/// 64-bit segment of this file to be mapped
#[cfg(feature = "alloc")]
const LC_SEGMENT_64: u32 = 0x19;

#[cfg(feature = "alloc")]
struct MachOFormatOffsets {
    number_of_commands: u32,
    load_commands: u32,
    command_size: u32,
    symtab_offset: u32,
    number_of_symbols: u32,
    strtab_offset: u32,
    nlist_value: u32,
    size_of_nlist_item: u32,
    segcmd64_vmaddr: u32,
    segcmd64_fileoff: u32,
    segcmd64_nsects: u32,
    sizeof_segcmd64: u32,
    sect64_vmaddr: u32,
    sect64_fileoff: u32,
    sizeof_sect64: u32,
}

#[cfg(feature = "alloc")]
impl MachOFormatOffsets {
    const fn new() -> Self {
        // offsets taken from:
        //  - https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MachOFormatOffsets.cs
        //  - https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
        //  - https://en.wikipedia.org/wiki/Mach-O
        MachOFormatOffsets {
            number_of_commands: 0x10,
            load_commands: 0x20,
            command_size: 0x04,
            symtab_offset: 0x08,
            number_of_symbols: 0x0c,
            strtab_offset: 0x10,
            nlist_value: 0x08,
            size_of_nlist_item: 0x10,
            segcmd64_vmaddr: 0x18,
            segcmd64_fileoff: 0x28,
            // sizeof(vm_prot_t) = 4
            // segcmd64_maxprot: 0x38
            // segcmd64_initprot: 0x38 + sizeof(vm_prot_t)
            segcmd64_nsects: 0x40, // 0x38 + sizeof(vm_prot_t) + sizeof(vm_prot_t)
            sizeof_segcmd64: 0x48, // 0x40 + sizeof(uint32_t) + sizeof(uint32_t)
            sect64_vmaddr: 0x20,
            sect64_fileoff: 0x30,
            sizeof_sect64: 0x50,
        }
    }
}

/// A symbol exported into the current module.
#[cfg(feature = "alloc")]
pub struct Symbol {
    /// The address associated with the current function
    pub address: Address,
    /// The address storing the name of the current function
    name_addr: Address,
}

#[cfg(feature = "alloc")]
impl Symbol {
    /// Tries to retrieve the name of the current function
    pub fn get_name<const CAP: usize>(
        &self,
        process: &Process,
    ) -> Result<ArrayCString<CAP>, Error> {
        process.read(self.name_addr)
    }
}

/// Iterates over the exported symbols for a given module.
/// Only 64-bit Mach-O format is supported
#[cfg(feature = "alloc")]
pub fn symbols(
    process: &Process,
    range: (Address, u64),
) -> Option<impl FusedIterator<Item = Symbol> + '_> {
    use crate::{print_limited, print_message};

    let page = scan_macho_page(process, range)?;
    print_message("macho.rs symbols 123: page found.");
    let offsets = MachOFormatOffsets::new();
    let number_of_commands: u32 = process.read(page + offsets.number_of_commands).ok()?;
    print_limited::<128>(&format_args!("macho.rs symbols 126: number_of_commands = {}", number_of_commands));

    let mut symtab_fileoff: u32 = 0;
    let mut number_of_symbols: u32 = 0;
    let mut strtab_fileoff: u32 = 0;
    let mut map_fileoff_to_vmaddr: BTreeMap<u64, u64> = BTreeMap::new();

    let mut next: u32 = offsets.load_commands;
    for _i in 0..number_of_commands {
        let cmdtype: u32 = process.read(page + next).ok()?;
        print_limited::<128>(&format_args!("cmdtype: 0x{:X?}", cmdtype));
        if cmdtype == LC_SYMTAB {
            symtab_fileoff = process.read(page + next + offsets.symtab_offset).ok()?;
            number_of_symbols = process.read(page + next + offsets.number_of_symbols).ok()?;
            strtab_fileoff = process.read(page + next + offsets.strtab_offset).ok()?;
        } else if cmdtype == LC_SEGMENT_64 {
            let vmaddr: u64 = process.read(page + next + offsets.segcmd64_vmaddr).ok()?;
            let fileoff: u64 = process.read(page + next + offsets.segcmd64_fileoff).ok()?;
            map_fileoff_to_vmaddr.insert(fileoff, vmaddr);
            let nsects: u32 = process.read(page + next + offsets.segcmd64_nsects).ok()?;
            for j in 0..nsects {
                let sect = page + next + offsets.sizeof_segcmd64 + (j * offsets.sizeof_sect64);
                let sect_vmaddr: u64 = process.read(sect + offsets.sect64_vmaddr).ok()?;
                let sect_fileoff: u32 = process.read(sect + offsets.sect64_fileoff).ok()?;
                if sect_fileoff != 0 {
                    map_fileoff_to_vmaddr.insert(sect_fileoff as u64, sect_vmaddr);
                }
            }
        }
        let command_size: u32 = process.read(page + next + offsets.command_size).ok()?;
        next += command_size;
    }

    if symtab_fileoff == 0 || number_of_symbols == 0 || strtab_fileoff == 0 {
        return None;
    }
    print_limited::<128>(&format_args!("macho.rs symbols 152: number_of_symbols = {}", number_of_symbols));

    print_limited::<128>(&format_args!("symtab_fileoff: {:X?}, strtab_fileoff: {:X?}", symtab_fileoff, strtab_fileoff));
    let symtab_vmaddr = fileoff_to_vmaddr(&map_fileoff_to_vmaddr, symtab_fileoff as u64);
    let strtab_vmaddr = fileoff_to_vmaddr(&map_fileoff_to_vmaddr, strtab_fileoff as u64);
    print_limited::<128>(&format_args!("symtab_vmaddr: {:X?}, strtab_vmaddr: {:X?}", symtab_vmaddr, strtab_vmaddr));
    print_limited::<1024>(&format_args!("map_fileoff_to_vmaddr:\n{:X?}", map_fileoff_to_vmaddr));

    let strtab_vm_a: [u8; 0x100] = process.read(page + strtab_vmaddr).ok()?;
    let strtab_vm_s = alloc::string::String::from_utf8_lossy(&strtab_vm_a);
    print_limited::<0x200>(&format_args!("strtab_vm_s:\n{:X?}", strtab_vm_s));

    /*
    let strtab_fi_a: [u8; 0x100] = process.read(page + strtab_fileoff).ok()?;
    let strtab_fi_s = alloc::string::String::from_utf8_lossy(&strtab_fi_a);
    print_limited::<0x200>(&format_args!("strtab_fi_s:\n{:X?}", strtab_fi_s));
    */

    Some(
        (0..number_of_symbols)
            .filter_map(move |j| {
                let nlist_item = page + symtab_vmaddr + (j * offsets.size_of_nlist_item);
                let symname_offset: u32 = process.read(nlist_item).ok()?;
                let string_address = page + strtab_vmaddr + symname_offset;
                let symbol_fileoff = process.read(nlist_item + offsets.nlist_value).ok()?;
                let symbol_vmaddr = fileoff_to_vmaddr(&map_fileoff_to_vmaddr, symbol_fileoff);
                let symbol_address = page + symbol_vmaddr;
                Some(Symbol {
                    address: symbol_address,
                    name_addr: string_address,
                })
            })
            .fuse(),
    )
}

#[cfg(feature = "alloc")]
fn fileoff_to_vmaddr(map: &BTreeMap<u64, u64>, fileoff: u64) -> u64 {
    map.iter()
        .filter(|(&k, _)| k <= fileoff)
        .max_by_key(|(&k, _)| k)
        .map(|(&k, &v)| v + fileoff - k)
        .unwrap_or(fileoff)
}
