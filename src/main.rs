use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Cursor;
use std::io::SeekFrom;

use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::ISO_8859_1;
use encoding::{DecoderTrap, Encoding};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_base_block() {
        let path = "boot/BCD";
        let mut file = BufReader::new(File::open(path).unwrap());

        let base_block = load_base_block(&mut file).unwrap();

        assert_eq!(base_block.primary_seq, 108);
        assert_eq!(base_block.secondary_seq, 108);
        assert_eq!(base_block.last_modified, 0x1d682ac2b8d0f88);
        assert_eq!(base_block.major_ver, 1);
        assert_eq!(base_block.minor_ver, 3);
        assert_eq!(base_block.file_type, 0);
        assert_eq!(base_block.file_format, 1);
        assert_eq!(base_block.root_cell_offset, 32);
        assert_eq!(base_block.hive_data_size, 32768);
        assert_eq!(base_block.clustering_factor, 1);
    }

    #[test]
    fn test_load_root_key_node() {
        let path = "boot/BCD";
        let mut file = BufReader::new(File::open(path).unwrap());

        let status = file.seek(SeekFrom::Start(4096 + 32));
        assert!(status.is_ok());
        let mut size = 65536;
        let root_cell_status = load_cell(&HIVE_NEW, &mut file, &mut size, false);
        assert!(root_cell_status.is_ok());
    }

    #[test]
    fn test_parse_key_node() {
        let buf = vec![
            0xa0, 0xff, 0xff, 0xff, 0x6e, 0x6b, 0x20, 0x00, //  |....nk .|
            0xba, 0x04, 0x00, 0x66, 0xd3, 0x4c, 0xd4, 0x01, //  |...f.L..|
            0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, //  |.... ...|
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |........|
            0x30, 0x05, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff, //  |0.......|
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //  |........|
            0x18, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, //  |........|
            0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |........|
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |........|
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, //  |........|
            0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20, //  |Control |
            0x50, 0x61, 0x6e, 0x65, 0x6c, 0x00, 0x00, 0x00, //  |Panel...|
        ];
        let result = parse_key_node(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.flags, 0x0020);
        assert_eq!(node.last_written, 0x01d44cd3660004ba);
        assert_eq!(node.access_bits, 0x00000000);
        assert_eq!(node.parent_offset, 0x00000020);
        assert_eq!(node.number_subkeys, 13);
        assert_eq!(node.number_volatile_subkeys, 0);
        assert_eq!(node.subkey_list_offset, 0x00010530);
        assert_eq!(node.volatile_subkey_list_offset, 0xffffffff);
        assert_eq!(node.key_value_count, 0);
        assert_eq!(node.key_value_offset, 0xffffffff);
        assert_eq!(node.key_security_offset, 0x00000318);
        assert_eq!(node.class_name_offset, 0xffffffff);
        assert_eq!(node.subkey_name_length_max, 26);
        assert_eq!(node.subkey_class_length_max, 0);
        assert_eq!(node.value_name_length_max, 0);
        assert_eq!(node.value_data_length_max, 0);
        assert_eq!(node.workvar, 0);
        assert_eq!(node.key_name_length, 13);
        assert_eq!(node.class_name_length, 0);
        assert_eq!(node.key_name, "Control Panel");
    }

    #[test]
    fn test_parse_key_value() {
        let buf = vec![
            0xc8, 0xff, 0xff, 0xff, 0x76, 0x6b, 0x1d, 0x00, //  |....vk..|
            0x04, 0x00, 0x00, 0x80, 0x32, 0x00, 0x00, 0x00, //  |....2...|
            0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfc, 0xcf, //  |........|
            0x54, 0x6f, 0x75, 0x63, 0x68, 0x4d, 0x6f, 0x64, //  |TouchMod|
            0x65, 0x4e, 0x5f, 0x48, 0x6f, 0x6c, 0x64, 0x54, //  |eN_HoldT|
            0x69, 0x6d, 0x65, 0x5f, 0x41, 0x6e, 0x69, 0x6d, //  |ime_Anim|
            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, //  |ation...|
        ];
        let result = parse_key_value(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.name.len(), 29);
        assert_eq!(node.data_size, 0x80000004);
        assert_eq!(node.data_offset, 50);
        assert_eq!(node.data_type, RegType::Dword);
        assert_eq!(node.flags, 0x0001);
        assert_eq!(node.spare, 0xcffc);
        assert_eq!(node.name, "TouchModeN_HoldTime_Animation");
    }

    #[test]
    fn test_parse_index_leaf() {
        // This cell is in NT 3.1 Hive format 1.1
        let buf = vec![
            0xe0, 0xff, 0xff, 0xff, 0x40, 0x08, 0x00, 0x00, //  |....@...|
            0x6c, 0x69, 0x03, 0x00, 0x30, 0x42, 0x00, 0x00, //  |li..0B..|
            0x60, 0x49, 0x00, 0x00, 0xf0, 0x55, 0x00, 0x00, //  |`I...U..|
            0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, //  |........|
        ];
        let mut file = Cursor::new(&buf);
        let mut size = 65536;
        let result = load_cell(
            &Hive {
                has_prev_pointer: true,
            },
            &mut file,
            &mut size,
            false,
        );
        assert!(result.is_ok());
        let node = match result.unwrap() {
            Cell::IndexLeaf(x) => x,
            _ => {
                panic!("Incorrect cell type");
            }
        };
        assert_eq!(node.elements.len(), 3);
        assert_eq!(node.elements[0].key_offset, 0x4230);
        assert_eq!(node.elements[1].key_offset, 0x4960);
        assert_eq!(node.elements[2].key_offset, 0x55f0);
    }

    #[test]
    fn test_parse_fast_leaf() {
        let buf = vec![
            0xf0, 0xff, 0xff, 0xff, 0x6c, 0x66, 0x01, 0x00, //  |....lf..|
            0x48, 0x05, 0x00, 0x00, 0x31, 0x32, 0x30, 0x30, //  |H...1200|
        ];
        let mut file = Cursor::new(&buf);
        let mut size = 65536;
        let result = load_cell(&HIVE_NEW, &mut file, &mut size, false);
        assert!(result.is_ok());
        let node = match result.unwrap() {
            Cell::FastLeaf(x) => x,
            _ => {
                panic!("Incorrect cell type");
            }
        };
        assert_eq!(node.elements.len(), 1);
        assert_eq!(node.elements[0].key_offset, 0x0548);
        assert_eq!(node.elements[0].name_hint, *b"1200");
    }

    #[test]
    fn test_parse_hash_leaf() {
        let buf = vec![
            0xf0, 0xff, 0xff, 0xff, 0x6c, 0x68, 0x01, 0x00, //  |....lh..|
            0xa8, 0x09, 0x00, 0x00, 0x82, 0x21, 0x8c, 0x70, //  |.....!.p|
            0xf8, 0xff, 0xff, 0xff, 0xe0, 0x2f, 0x00, 0x00, //  |...../..|
        ];
        let mut file = Cursor::new(&buf);
        let mut size = 65536;
        let result = load_cell(&HIVE_NEW, &mut file, &mut size, false);
        assert!(result.is_ok());
        let node = match result.unwrap() {
            Cell::HashLeaf(x) => x,
            _ => {
                panic!("Incorrect cell type");
            }
        };
        assert_eq!(node.elements.len(), 1);
        assert_eq!(node.elements[0].key_offset, 0x000009a8);
        assert_eq!(node.elements[0].name_hash, 0x708c2182);
    }

    #[test]
    fn test_parse_key_security() {
        let buf = vec![
            0xb8, 0x00, 0x00, 0x00, 0x73, 0x6b, 0x20, 0x00, //  |....sk .|
            0x80, 0x63, 0x00, 0x00, 0x68, 0x01, 0x00, 0x00, //  |.c..h...|
            0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, //  |....d...|
            0x01, 0x00, 0x04, 0x80, 0x48, 0x00, 0x00, 0x00, //  |....H...|
            0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  |X.......|
            0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x34, 0x00, //  |......4.|
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, //  |........|
            0x3f, 0x00, 0x0f, 0x00, 0x01, 0x02, 0x00, 0x00, //  |?.......|
            0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, //  |.... ...|
            0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, //  | .......|
            0x3f, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00, //  |?.......|
            0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, //  |........|
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, //  |........|
            0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, //  | ... ...|
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, //  |........|
        ];
        let result = parse_key_security(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.flink, 0x6380);
        assert_eq!(node.blink, 0x0168);
        assert_eq!(node.reference_count, 1);
        assert_eq!(node.descriptor.len(), 100 - 4);
        assert_eq!(node.descriptor, &buf[24..]);
    }
}

const INDEX_LEAF: u16 = 'l' as u16 + 'i' as u16 * 256; // (li) Subkeys list
const FAST_LEAF: u16 = 'l' as u16 + 'f' as u16 * 256; // (lf) Subkeys list with name hints
const HASH_LEAF: u16 = 'l' as u16 + 'h' as u16 * 256; // (lh) Subkeys list with name hashes
const _INDEX_ROOT: u16 = 'r' as u16 + 'i' as u16 * 256; // (ri) List of subkeys lists
const KEY_NODE: u16 = 'n' as u16 + 'k' as u16 * 256; // (nk) Registry key node
const KEY_VALUE: u16 = 'v' as u16 + 'k' as u16 * 256; // (vk) Registry key value
const KEY_SECURITY: u16 = 's' as u16 + 'k' as u16 * 256; // (sk) Security descriptor
const _BIG_DATA: u16 = 'd' as u16 + 'b' as u16 * 256; // (db) List of data segments

#[derive(Debug)]
struct KeyNode {
    flags: u16,
    last_written: u64,
    access_bits: u32,
    parent_offset: i32,
    number_subkeys: u32,
    number_volatile_subkeys: u32,
    subkey_list_offset: u32,
    volatile_subkey_list_offset: u32,
    key_value_count: u32,
    key_value_offset: u32,
    key_security_offset: u32,
    class_name_offset: u32,
    subkey_name_length_max: u32,
    subkey_class_length_max: u32,
    value_name_length_max: u32,
    value_data_length_max: u32,
    workvar: u32,
    key_name_length: u16,
    class_name_length: u16,
    key_name: String,
}

#[derive(Debug, Eq, PartialEq)]
enum RegType {
    None = 0x00000000,
    Sz = 0x00000001,
    ExpandSz = 0x00000002,
    Binary = 0x00000003,
    Dword = 0x00000004,
    DwordBigEndian = 0x00000005,
    Link = 0x00000006,
    MultiSz = 0x00000007,
    ResourceList = 0x00000008,
    FullResourceDescriptor = 0x00000009,
    ResourceRequirementsList = 0x0000000a,
    Qword = 0x0000000b,
}

impl TryFrom<u32> for RegType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == RegType::None as u32 => Ok(RegType::None),
            x if x == RegType::Sz as u32 => Ok(RegType::Sz),
            x if x == RegType::ExpandSz as u32 => Ok(RegType::ExpandSz),
            x if x == RegType::Binary as u32 => Ok(RegType::Binary),
            x if x == RegType::Dword as u32 => Ok(RegType::Dword),
            x if x == RegType::DwordBigEndian as u32 => Ok(RegType::DwordBigEndian),
            x if x == RegType::Link as u32 => Ok(RegType::Link),
            x if x == RegType::MultiSz as u32 => Ok(RegType::MultiSz),
            x if x == RegType::ResourceList as u32 => Ok(RegType::ResourceList),
            x if x == RegType::FullResourceDescriptor as u32 => Ok(RegType::FullResourceDescriptor),
            x if x == RegType::ResourceRequirementsList as u32 => {
                Ok(RegType::ResourceRequirementsList)
            }
            x if x == RegType::Qword as u32 => Ok(RegType::Qword),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct KeyValue {
    data_size: u32,
    data_offset: u32,
    data_type: RegType,
    flags: u16,
    spare: u16,
    name: String,
}

fn parse_key_value<R: Read + Seek>(source: &mut R) -> std::io::Result<KeyValue> {
    let name_length = source.read_u16::<LittleEndian>()?;
    let data_size = source.read_u32::<LittleEndian>()?;
    let data_offset = source.read_u32::<LittleEndian>()?;
    let data_type = source.read_u32::<LittleEndian>()?;
    let flags = source.read_u16::<LittleEndian>()?;
    let spare = source.read_u16::<LittleEndian>()?;
    let mut name = vec![0u8; name_length as usize];
    source.read_exact(&mut name)?;
    println!("Value: {:?}", std::str::from_utf8(&name));
    Ok(KeyValue {
        data_size,
        data_offset,
        data_type: data_type.try_into().unwrap(),
        flags,
        spare,
        name: ISO_8859_1.decode(&name, DecoderTrap::Strict).unwrap(),
    })
}

fn parse_key_node<R: Read + Seek>(source: &mut R) -> std::io::Result<KeyNode> {
    let flags = source.read_u16::<LittleEndian>()?;
    let last_written = source.read_u64::<LittleEndian>()?;
    let access_bits = source.read_u32::<LittleEndian>()?;
    let parent_offset = source.read_i32::<LittleEndian>()?;
    let number_subkeys = source.read_u32::<LittleEndian>()?;
    let number_volatile_subkeys = source.read_u32::<LittleEndian>()?;
    let subkey_list_offset = source.read_u32::<LittleEndian>()?;
    let volatile_subkey_list_offset = source.read_u32::<LittleEndian>()?;
    let key_value_count = source.read_u32::<LittleEndian>()?;
    let key_value_offset = source.read_u32::<LittleEndian>()?;
    let key_security_offset = source.read_u32::<LittleEndian>()?;
    let class_name_offset = source.read_u32::<LittleEndian>()?;
    let subkey_name_length_max = source.read_u32::<LittleEndian>()?;
    let subkey_class_length_max = source.read_u32::<LittleEndian>()?;
    let value_name_length_max = source.read_u32::<LittleEndian>()?;
    let value_data_length_max = source.read_u32::<LittleEndian>()?;
    let workvar = source.read_u32::<LittleEndian>()?;
    let key_name_length = source.read_u16::<LittleEndian>()?;
    let class_name_length = source.read_u16::<LittleEndian>()?;
    let mut key_name = vec![0u8; key_name_length as usize];
    source.read_exact(&mut key_name)?;
    //println!("Key: {:?}", std::str::from_utf8(&key_name));
    println!(
        "Key: {:?}",
        ISO_8859_1.decode(&key_name, DecoderTrap::Strict)
    );
    Ok(KeyNode {
        flags,
        last_written,
        access_bits,
        parent_offset,
        number_subkeys,
        number_volatile_subkeys,
        subkey_list_offset,
        volatile_subkey_list_offset,
        key_value_count,
        key_value_offset,
        key_security_offset,
        class_name_offset,
        subkey_name_length_max,
        subkey_class_length_max,
        value_name_length_max,
        value_data_length_max,
        workvar,
        key_name_length,
        class_name_length,
        key_name: ISO_8859_1.decode(&key_name, DecoderTrap::Strict).unwrap(),
    })
}

#[derive(Debug)]
struct IndexLeafElement {
    key_offset: u32,
}

#[derive(Debug)]
struct IndexLeaf {
    elements: Vec<IndexLeafElement>,
}

fn parse_index_leaf<R: Read + Seek>(source: &mut R) -> std::io::Result<IndexLeaf> {
    let count = source.read_u16::<LittleEndian>()?;
    let mut elements = Vec::new();
    println!("Number of leaves: {}", count);
    for _ in 0..count {
        let key_offset = source.read_u32::<LittleEndian>()?;
        elements.push(IndexLeafElement { key_offset });
    }
    Ok(IndexLeaf { elements })
}

#[derive(Debug)]
struct FastLeafElement {
    key_offset: u32,
    name_hint: [u8; 4],
}

#[derive(Debug)]
struct FastLeaf {
    elements: Vec<FastLeafElement>,
}

fn parse_fast_leaf<R: Read + Seek>(source: &mut R) -> std::io::Result<FastLeaf> {
    let count = source.read_u16::<LittleEndian>()?;
    let mut elements = Vec::new();
    println!("Number of leaves: {}", count);
    for _ in 0..count {
        let key_offset = source.read_u32::<LittleEndian>()?;
        let mut name_hint = [0u8; 4];
        source.read_exact(&mut name_hint)?;
        println!("Name hint: {:?}", std::str::from_utf8(&name_hint));
        elements.push(FastLeafElement {
            key_offset,
            name_hint,
        });
    }
    Ok(FastLeaf { elements })
}

#[derive(Debug)]
struct HashLeafElement {
    key_offset: u32,
    name_hash: u32,
}

#[derive(Debug)]
struct HashLeaf {
    elements: Vec<HashLeafElement>,
}

fn parse_hash_leaf<R: Read + Seek>(source: &mut R) -> std::io::Result<HashLeaf> {
    let count = source.read_u16::<LittleEndian>()?;
    let mut elements = vec![];
    println!("Number of leaves: {}", count);
    for _ in 0..count {
        elements.push(HashLeafElement {
            key_offset: source.read_u32::<LittleEndian>()?,
            name_hash: source.read_u32::<LittleEndian>()?,
        });
    }
    Ok(HashLeaf { elements })
}

#[derive(Debug)]
struct KeySecurity {
    flink: u32,
    blink: u32,
    reference_count: u32,
    descriptor: Vec<u8>,
}

fn parse_key_security<R: Read + Seek>(source: &mut R) -> std::io::Result<KeySecurity> {
    let _reserved = source.read_u16::<LittleEndian>()?;
    let flink = source.read_u32::<LittleEndian>()?;
    let blink = source.read_u32::<LittleEndian>()?;
    let reference_count = source.read_u32::<LittleEndian>()?;
    let descriptor_size = source.read_u32::<LittleEndian>()?;
    assert!(descriptor_size >= 4);
    let mut descriptor = vec![0u8; (descriptor_size - 4) as usize];
    source.read_exact(&mut descriptor)?;
    Ok(KeySecurity {
        flink,
        blink,
        reference_count,
        descriptor,
    })
}

struct Hive {
    has_prev_pointer: bool,
}

const HIVE_NEW: Hive = Hive {
    has_prev_pointer: false,
};

#[derive(Debug)]
struct Raw {
    data: Vec<u8>,
}

#[derive(Debug)]
enum Cell {
    KeyNode(KeyNode),
    KeyValue(KeyValue),
    IndexLeaf(IndexLeaf),
    FastLeaf(FastLeaf),
    HashLeaf(HashLeaf),
    KeySecurity(KeySecurity),
    Raw(Raw),
}

fn load_cell<R: Read + Seek>(
    hive: &Hive,
    source: &mut R,
    size: &mut u32,
    raw: bool,
) -> std::io::Result<Cell> {
    let mut cell_header_size = 4;
    let cell_size = source.read_i32::<LittleEndian>()?;
    assert!((cell_size.abs() & 0x07) == 0);
    *size -= cell_size.abs() as u32;
    if cell_size > 0 {
        println!("Cell unallocated");
        source.seek(SeekFrom::Current(cell_size.abs() as i64 - 6))?;
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::Other,
            "Empty cell",
        ));
    }
    if hive.has_prev_pointer {
        cell_header_size += 4;
        let _prev = source.read_i32::<LittleEndian>()?;
    }
    println!("Cell size: {}", cell_size.abs());
    if raw {
        let mut buf = vec![0u8; cell_size.abs() as usize - 4];
        source.read_exact(&mut buf)?;
        return Ok(Cell::Raw(Raw { data: buf }));
    }
    let mut key = [0u8; 2];
    source.read_exact(&mut key)?;
    println!("Cell raw: {:?}", &key);
    println!("Cell key: {:?}", std::str::from_utf8(&key));
    cell_header_size += 2;
    let cell_magic = key[0] as u16 + key[1] as u16 * 256;
    let mut buf = vec![0u8; cell_size.abs() as usize - cell_header_size];
    source.read_exact(&mut buf)?;
    let cell = match cell_magic {
        KEY_NODE => Cell::KeyNode(parse_key_node(&mut Cursor::new(buf))?),
        KEY_VALUE => Cell::KeyValue(parse_key_value(&mut Cursor::new(buf))?),
        INDEX_LEAF => Cell::IndexLeaf(parse_index_leaf(&mut Cursor::new(buf))?),
        FAST_LEAF => Cell::FastLeaf(parse_fast_leaf(&mut Cursor::new(buf))?),
        HASH_LEAF => Cell::HashLeaf(parse_hash_leaf(&mut Cursor::new(buf))?),
        KEY_SECURITY => Cell::KeySecurity(parse_key_security(&mut Cursor::new(buf))?),
        _ => {
            return Err(::std::io::Error::new(
                ::std::io::ErrorKind::Other,
                "Unknown cell",
            ));
        }
    };

    Ok(cell)
}

#[allow(dead_code)]
struct BaseBlock {
    primary_seq: u32,
    secondary_seq: u32,
    last_modified: u64,
    major_ver: u32,
    minor_ver: u32,
    file_type: u32,
    file_format: u32,
    root_cell_offset: u32,
    hive_data_size: u32,
    clustering_factor: u32,
}

fn load_base_block<R: Read + Seek>(source: &mut R) -> std::io::Result<BaseBlock> {
    let mut magic = [0u8; 4];
    source.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"regf");
    let primary_seq = source.read_u32::<LittleEndian>().unwrap();
    let secondary_seq = source.read_u32::<LittleEndian>().unwrap();
    let last_modified = source.read_u64::<LittleEndian>().unwrap();
    let major_ver = source.read_u32::<LittleEndian>().unwrap();
    let minor_ver = source.read_u32::<LittleEndian>().unwrap();
    let file_type = source.read_u32::<LittleEndian>().unwrap();
    let file_format = source.read_u32::<LittleEndian>().unwrap();
    let root_cell_offset = source.read_u32::<LittleEndian>().unwrap();
    let hive_data_size = source.read_u32::<LittleEndian>().unwrap();
    let clustering_factor = source.read_u32::<LittleEndian>().unwrap();
    println!(
        "P: {}, S: {}, LM: {}",
        primary_seq, secondary_seq, last_modified
    );
    println!(
        "({}, {}) -> {} - {}",
        major_ver, minor_ver, file_type, file_format
    );
    println!("Root Cell Offset: {}", root_cell_offset);
    println!("Hive Data: {}", hive_data_size);
    println!("Clustering Factor: {}", clustering_factor);

    source.seek(SeekFrom::Start(4096)).unwrap();
    Ok(BaseBlock {
        primary_seq,
        secondary_seq,
        last_modified,
        major_ver,
        minor_ver,
        file_type,
        file_format,
        root_cell_offset,
        hive_data_size,
        clustering_factor,
    })
}

fn dump_key_node<R: Read + Seek>(source: &mut R, offset: u64) {
    source.seek(SeekFrom::Start(offset + 4096)).unwrap();
    let mut size = 655360;
    println!("KN Offset: {}", offset);
    let cell = load_cell(&HIVE_NEW, source, &mut size, false).unwrap();
    println!("{:?}", cell);
    match cell {
        Cell::KeyNode(node) => {
            if node.number_subkeys > 0 {
                source
                    .seek(SeekFrom::Start(node.subkey_list_offset as u64 + 4096))
                    .unwrap();
                size = 655360;
                let subkey = load_cell(&HIVE_NEW, source, &mut size, false).unwrap();
                println!("{:?}", subkey);
                match subkey {
                    Cell::FastLeaf(child) => {
                        for offset in child.elements {
                            dump_key_node(source, offset.key_offset as u64);
                        }
                    }
                    Cell::HashLeaf(child) => {
                        for offset in child.elements {
                            dump_key_node(source, offset.key_offset as u64);
                        }
                    }
                    _ => {
                        panic!("Unknown child");
                    }
                }
            }
            if node.key_value_count > 0 {
                println!("KV List Offset: {:x}", node.key_value_offset as u64 + 4096);
                source
                    .seek(SeekFrom::Start(node.key_value_offset as u64 + 4096))
                    .unwrap();
                size = 655360;
                let key_value_list = load_cell(&HIVE_NEW, source, &mut size, true).unwrap();
                match key_value_list {
                    Cell::Raw(value) => {
                        let mut cursor = Cursor::new(&value.data[..]);
                        for _ in 0..node.key_value_count {
                            size = 655360;
                            let offset = cursor.read_u32::<LittleEndian>().unwrap();
                            source.seek(SeekFrom::Start(offset as u64 + 4096)).unwrap();
                            let key_value = load_cell(&HIVE_NEW, source, &mut size, false).unwrap();
                            println!("{:?}", key_value);
                            match key_value {
                                Cell::KeyValue(child) => {
                                    if child.data_size > 0 {
                                        if child.data_size & 0x80000000 != 0 {
                                            println!("Data: {:?}", child.data_offset);
                                        } else {
                                            source
                                                .seek(SeekFrom::Start(
                                                    child.data_offset as u64 + 4096,
                                                ))
                                                .unwrap();
                                            let data_value =
                                                load_cell(&HIVE_NEW, source, &mut size, true)
                                                    .unwrap();
                                            match data_value {
                                                Cell::Raw(n) => {
                                                    println!("Data: {:?}", n.data);
                                                }
                                                _ => {
                                                    panic!("Unknown child");
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    panic!("Unknown child");
                                }
                            }
                        }
                    }
                    _ => {
                        panic!("Unknown child");
                    }
                }
            }
        }
        _ => {
            panic!("Wrong type");
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let mut file = BufReader::new(File::open(path).unwrap());

    let base_block = load_base_block(&mut file).unwrap();

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"hbin");
    let _offset = file.read_u32::<LittleEndian>().unwrap();
    let mut size = file.read_u32::<LittleEndian>().unwrap();
    let _reserved = file.read_u64::<LittleEndian>().unwrap();
    let _timestamp = file.read_u64::<LittleEndian>().unwrap();
    let _spare = file.read_u32::<LittleEndian>().unwrap();
    println!("Bin size: {}", size);
    size -= 32;
    while size > 0 {
        //    let cell_size = file.read_i32::<LittleEndian>().unwrap();
        //    assert!((cell_size.abs() & 0x07) == 0);
        //    let mut key = [0u8; 2];
        //    file.read_exact(&mut key).unwrap();
        //    //assert_eq!(&magic, b"hbin");
        //    println!("Cell raw: {:?}", &key);
        //    println!("Cell key: {:?}", std::str::from_utf8(&key));
        //    file.seek(SeekFrom::Current(cell_size.abs() as i64 - 6));
        load_cell(&HIVE_NEW, &mut file, &mut size, false).ok();
    }
    dump_key_node(&mut file, base_block.root_cell_offset as u64);
}
