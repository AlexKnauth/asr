//! Support for parsing Mach-O format

#[cfg(feature = "alloc")]
use core::iter::FusedIterator;

#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

#[cfg(feature = "std")]
use crate::signature::Signature;
#[cfg(feature = "alloc")]
use crate::{string::ArrayCString, Error};
use crate::{Address, PointerSize, Process};

const CSTR: usize = 128;

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

#[cfg(feature = "std")]
const HEADER_SIZE: usize = 32;

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
}

#[cfg(feature = "alloc")]
impl MachOFormatOffsets {
    const fn new() -> Self {
        // offsets taken from:
        //  - https://github.com/hackf5/unityspy/blob/master/src/HackF5.UnitySpy/Offsets/MachOFormatOffsets.cs
        //  - https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
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

/// Symbols for a given module.
/// Only 64-bit Mach-O format is supported
#[cfg(feature = "alloc")]
#[allow(unused)]
pub struct Symbols<'a> {
    process: &'a Process,
    module_name: &'a str,
    module_range: (Address, u64),
    page: Address,
    offsets: MachOFormatOffsets,
    symtab_fileoff: u32,
    number_of_symbols: u32,
    strtab_fileoff: u32,
    map_fileoff_to_vmaddr: BTreeMap<u64, u64>,
    symtab_vmaddr: u64,
    strtab_vmaddr: u64,
}

#[cfg(feature = "alloc")]
impl<'a> Symbols<'a> {
    /// Attempts to initialize state for the symbols for a given module.
    pub fn new(
        process: &'a Process,
        module_name: &'a str,
        module_range: (Address, u64),
    ) -> Option<Self> {
        let page = scan_macho_page(process, module_range)?;
        let offsets = MachOFormatOffsets::new();
        let number_of_commands: u32 = process.read(page + offsets.number_of_commands).ok()?;

        let mut symtab_fileoff: u32 = 0;
        let mut number_of_symbols: u32 = 0;
        let mut strtab_fileoff: u32 = 0;
        let mut map_fileoff_to_vmaddr: BTreeMap<u64, u64> = BTreeMap::new();

        let mut next: u32 = offsets.load_commands;
        for _i in 0..number_of_commands {
            let cmdtype: u32 = process.read(page + next).ok()?;
            if cmdtype == LC_SYMTAB {
                symtab_fileoff = process.read(page + next + offsets.symtab_offset).ok()?;
                number_of_symbols = process.read(page + next + offsets.number_of_symbols).ok()?;
                strtab_fileoff = process.read(page + next + offsets.strtab_offset).ok()?;
            } else if cmdtype == LC_SEGMENT_64 {
                let vmaddr: u64 = process.read(page + next + offsets.segcmd64_vmaddr).ok()?;
                let fileoff: u64 = process.read(page + next + offsets.segcmd64_fileoff).ok()?;
                map_fileoff_to_vmaddr.insert(fileoff, vmaddr);
            }
            let command_size: u32 = process.read(page + next + offsets.command_size).ok()?;
            next += command_size;
        }

        if symtab_fileoff == 0 || number_of_symbols == 0 || strtab_fileoff == 0 {
            return None;
        }

        let symtab_vmaddr = fileoff_to_vmaddr(&map_fileoff_to_vmaddr, symtab_fileoff as u64);
        let strtab_vmaddr = fileoff_to_vmaddr(&map_fileoff_to_vmaddr, strtab_fileoff as u64);

        Some(Self {
            process,
            module_name,
            module_range,
            page,
            offsets,
            symtab_fileoff,
            number_of_symbols,
            strtab_fileoff,
            map_fileoff_to_vmaddr,
            symtab_vmaddr,
            strtab_vmaddr,
        })
    }

    /// Iterates over the exported symbols.
    pub fn iter(&self) -> impl FusedIterator<Item = Symbol> + '_ {
        (0..self.number_of_symbols)
            .filter_map(move |j| {
                let nlist_item =
                    self.page + self.symtab_vmaddr + (j * self.offsets.size_of_nlist_item);
                let symname_offset: u32 = self.process.read(nlist_item).ok()?;
                let string_address = self.page + self.strtab_vmaddr + symname_offset;
                let symbol_fileoff = self
                    .process
                    .read(nlist_item + self.offsets.nlist_value)
                    .ok()?;
                let symbol_vmaddr = fileoff_to_vmaddr(&self.map_fileoff_to_vmaddr, symbol_fileoff);
                let symbol_address = self.page + symbol_vmaddr;
                Some(Symbol {
                    address: symbol_address,
                    name_addr: string_address,
                })
            })
            .fuse()
    }

    /// Finds the address of an exported symbol by name.
    pub fn find_address(&self, symbol_name: &str) -> Option<Address> {
        // Try finding the symbol purely in memory first.
        if let Some(symbol) = self.iter().find(|symbol| {
            symbol
                .get_name::<CSTR>(self.process)
                .is_ok_and(|name| name.matches(symbol_name))
        }) {
            return Some(symbol.address);
        }
        #[cfg(feature = "std")]
        {
            // Otherwise try finding the symbol in the file.
            let symbol_name_bytes = symbol_name.as_bytes();
            let symbol_name_len = symbol_name_bytes.len();
            let module_path = self.process.get_module_path(self.module_name).ok()?;
            let all_bytes = file_read_all_bytes(module_path).ok()?;
            let macho_header: [u8; HEADER_SIZE] = self.process.read(self.page).ok()?;
            let macho_offset = memchr::memmem::find(&all_bytes, &macho_header)?;
            let macho_bytes = &all_bytes[macho_offset..];

            for j in 0..self.number_of_symbols {
                let nlist_item = self.symtab_fileoff + (j * self.offsets.size_of_nlist_item);
                let symname_offset: u32 = slice_read(macho_bytes, nlist_item).ok()?;
                let string_start = (self.strtab_fileoff + symname_offset) as usize;
                let string_end = string_start + symbol_name_len;
                if macho_bytes[string_end] == 0
                    && &macho_bytes[string_start..string_end] == symbol_name_bytes
                {
                    let symbol_fileoff: u64 =
                        slice_read(macho_bytes, nlist_item + self.offsets.nlist_value).ok()?;
                    let file_contents: [u8; 20] = slice_read(macho_bytes, symbol_fileoff).ok()?;
                    let file_signature: Signature<20> = Signature::Simple(file_contents);
                    return file_signature.scan_process_range(self.process, self.module_range);
                }
            }
        }
        None
    }
}

#[cfg(feature = "alloc")]
fn fileoff_to_vmaddr(map: &BTreeMap<u64, u64>, fileoff: u64) -> u64 {
    map.iter()
        .filter(|(&k, _)| k <= fileoff)
        .max_by_key(|(&k, _)| k)
        .map(|(&k, &v)| v + fileoff - k)
        .unwrap_or(fileoff)
}

// --------------------------------------------------------

#[cfg(feature = "std")]
fn file_read_all_bytes<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer: Vec<u8> = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buffer)?;
    Ok(buffer)
}

#[cfg(feature = "std")]
/// Reads a value of the type specified from the slice at the address
/// given.
fn slice_read<T: bytemuck::CheckedBitPattern, N: Into<u64>>(
    slice: &[u8],
    address: N,
) -> Result<T, bytemuck::checked::CheckedCastError> {
    let start: usize = Into::<u64>::into(address) as usize;
    let size = core::mem::size_of::<T>();
    let slice_src = &slice[start..(start + size)];
    bytemuck::checked::try_from_bytes(slice_src).cloned()
}
