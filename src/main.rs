use std::io::Cursor;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::SeekFrom;
use std::convert::{TryFrom, TryInto};

use byteorder::{LittleEndian, ReadBytesExt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_node() {
        let buf = vec![
            0xa0, 0xff, 0xff, 0xff, 0x6e, 0x6b, 0x20, 0x00,  //  |....nk .|
            0xba, 0x04, 0x00, 0x66, 0xd3, 0x4c, 0xd4, 0x01,  //  |...f.L..|
            0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,  //  |.... ...|
            0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  |........|
            0x30, 0x05, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff,  //  |0.......|
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,  //  |........|
            0x18, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,  //  |........|
            0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  |........|
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  |........|
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,  //  |........|
            0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x20,  //  |Control |
            0x50, 0x61, 0x6e, 0x65, 0x6c, 0x00, 0x00, 0x00,  //  |Panel...|
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
    fn test_parse_hash_leaf() {
        let buf = vec![
            0xf0, 0xff, 0xff, 0xff, 0x6c, 0x68, 0x01, 0x00,  //  |....lh..|
            0xa8, 0x09, 0x00, 0x00, 0x82, 0x21, 0x8c, 0x70,  //  |.....!.p|
            0xf8, 0xff, 0xff, 0xff, 0xe0, 0x2f, 0x00, 0x00,  //  |...../..|
        ];
        let result = parse_hash_leaf(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.elements.len(), 1);
        assert_eq!(node.elements[0].key_offset, 0x000009a8);
        assert_eq!(node.elements[0].name_hash, 0x708c2182);
    }

    #[test]
    fn test_parse_key_value() {
        let buf = vec![
            0xc8, 0xff, 0xff, 0xff, 0x76, 0x6b, 0x1d, 0x00,  //  |....vk..|
            0x04, 0x00, 0x00, 0x80, 0x32, 0x00, 0x00, 0x00,  //  |....2...|
            0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfc, 0xcf,  //  |........|
            0x54, 0x6f, 0x75, 0x63, 0x68, 0x4d, 0x6f, 0x64,  //  |TouchMod|
            0x65, 0x4e, 0x5f, 0x48, 0x6f, 0x6c, 0x64, 0x54,  //  |eN_HoldT|
            0x69, 0x6d, 0x65, 0x5f, 0x41, 0x6e, 0x69, 0x6d,  //  |ime_Anim|
            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,  //  |ation...|
        ];
        let result = parse_key_value(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.name.len(), 29);
        assert_eq!(node.data_size, 0x80000004);
        assert_eq!(node.data_offset, 50);
        assert_eq!(node.data_type, DataType::RegDword);
        assert_eq!(node.flags, 0x0001);
        assert_eq!(node.spare, 0xcffc);
        assert_eq!(node.name, "TouchModeN_HoldTime_Animation");
    }

    #[test]
    fn test_parse_fast_leaf() {
        let buf = vec![
            0xf0, 0xff, 0xff, 0xff, 0x6c, 0x66, 0x01, 0x00,  //  |....lf..|
            0x48, 0x05, 0x00, 0x00, 0x31, 0x32, 0x30, 0x30,  //  |H...1200|
        ];
        let result = parse_fast_leaf(&mut Cursor::new(&buf[6..]));
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.elements.len(), 1);
        assert_eq!(node.elements[0].key_offset, 0x0548);
        assert_eq!(node.elements[0].name_hint, *b"1200");
    }

    #[test]
    fn test_parse_key_security() {
        let buf = vec![
            0xb8, 0x00, 0x00, 0x00, 0x73, 0x6b, 0x20, 0x00,  //  |....sk .|
            0x80, 0x63, 0x00, 0x00, 0x68, 0x01, 0x00, 0x00,  //  |.c..h...|
            0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,  //  |....d...|
            0x01, 0x00, 0x04, 0x80, 0x48, 0x00, 0x00, 0x00,  //  |....H...|
            0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  |X.......|
            0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x34, 0x00,  //  |......4.|
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00,  //  |........|
            0x3f, 0x00, 0x0f, 0x00, 0x01, 0x02, 0x00, 0x00,  //  |?.......|
            0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,  //  |.... ...|
            0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,  //  | .......|
            0x3f, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00,  //  |?.......|
            0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,  //  |........|
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,  //  |........|
            0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,  //  | ... ...|
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,  //  |........|
        ];
        let result = parse_key_security(&mut Cursor::new(&buf[6..]));
        !(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.flink, 0x6380);
        assert_eq!(node.blink, 0x0168);
        assert_eq!(node.reference_count, 1);
        assert_eq!(node.descriptor.len(), 100-4);
        assert_eq!(node.descriptor, &buf[24..]);
    }
}



const _INDEX_LEAF:   u16 = 'l' as u16 + 'i' as u16 * 256;  // (li) Subkeys list
const FAST_LEAF:    u16 = 'l' as u16 + 'f' as u16 * 256;  // (lf) Subkeys list with name hints
const _HASH_LEAF:    u16 = 'l' as u16 + 'h' as u16 * 256;  // (lh) Subkeys list with name hashes
const _INDEX_ROOT:   u16 = 'r' as u16 + 'i' as u16 * 256;  // (ri) List of subkeys lists
const KEY_NODE:     u16 = 'n' as u16 + 'k' as u16 * 256;  // (nk) Registry key node
const KEY_VALUE:    u16 = 'v' as u16 + 'k' as u16 * 256;  // (vk) Registry key value
const KEY_SECURITY: u16 = 's' as u16 + 'k' as u16 * 256;  // (sk) Security descriptor
const _BIG_DATA:     u16 = 'd' as u16 + 'b' as u16 * 256;  // (db) List of data segments

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

struct NameHash {
    key_offset: u32,
    name_hash: u32,
}

struct HashLeaf {
    elements: Vec<NameHash>,
}

fn parse_hash_leaf<R: Read + Seek>(source: &mut R) -> std::io::Result<HashLeaf> {
    let count = source.read_u16::<LittleEndian>()?;
    let mut elements = vec![];
    for _ in 0..count {
        elements.push(NameHash {
            key_offset: source.read_u32::<LittleEndian>()?,
            name_hash: source.read_u32::<LittleEndian>()?,
        });
    }
    Ok(HashLeaf {
        elements,
    })
}

#[derive(Debug, Eq, PartialEq)]
enum DataType {
    RegNone                      = 0x00000000,
    RegSz                        = 0x00000001,
    RegExpandSz                  = 0x00000002,
    RegBinary                    = 0x00000003,
    RegDword                     = 0x00000004,
    RegDwordBigEndian            = 0x00000005,
    RegLink                      = 0x00000006,
    RegMultiSz                   = 0x00000007,
    RegResourceList              = 0x00000008,
    RegFullResourceDescriptor    = 0x00000009,
    RegResourceRequirementsList  = 0x0000000a,
    RegQword                     = 0x0000000b,
}

impl TryFrom<u32> for DataType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == DataType::RegNone                     as u32 => Ok(DataType::RegNone                    ),
            x if x == DataType::RegSz                       as u32 => Ok(DataType::RegSz                      ),
            x if x == DataType::RegExpandSz                 as u32 => Ok(DataType::RegExpandSz                ),
            x if x == DataType::RegBinary                   as u32 => Ok(DataType::RegBinary                  ),
            x if x == DataType::RegDword                    as u32 => Ok(DataType::RegDword                   ),
            x if x == DataType::RegDwordBigEndian           as u32 => Ok(DataType::RegDwordBigEndian          ),
            x if x == DataType::RegLink                     as u32 => Ok(DataType::RegLink                    ),
            x if x == DataType::RegMultiSz                  as u32 => Ok(DataType::RegMultiSz                 ),
            x if x == DataType::RegResourceList             as u32 => Ok(DataType::RegResourceList            ),
            x if x == DataType::RegFullResourceDescriptor   as u32 => Ok(DataType::RegFullResourceDescriptor  ),
            x if x == DataType::RegResourceRequirementsList as u32 => Ok(DataType::RegResourceRequirementsList),
            x if x == DataType::RegQword                    as u32 => Ok(DataType::RegQword                   ),
            _ => Err(()),
        }
    }
}


struct KeyValue {
    data_size: u32,
    data_offset: u32,
    data_type: DataType,
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
        name: std::str::from_utf8(&name).unwrap().to_string(),
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
    println!("Key: {:?}", std::str::from_utf8(&key_name));
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
        key_name: std::str::from_utf8(&key_name).unwrap().to_string(),
    })
}


struct FastLeafElement {
    key_offset: u32,
    name_hint: [u8; 4],
}

struct FastLeaf {
    elements: Vec<FastLeafElement>,
}

fn parse_fast_leaf<R: Read + Seek>(source: &mut R) -> std::io::Result<FastLeaf> {
    let count = source.read_u16::<LittleEndian>()?;
    let mut elements = Vec::new();
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
    Ok(FastLeaf {
        elements,
    })
}


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


fn load_cell<R: Read + Seek>(source: &mut R, size: &mut u32) -> std::io::Result<()> {
    let cell_size = source.read_i32::<LittleEndian>()?;
    assert!((cell_size.abs() & 0x07) == 0);
    *size -= cell_size.abs() as u32;
    let mut key = [0u8; 2];
    source.read_exact(&mut key)?;
    //assert_eq!(&magic, b"hbin");
    if cell_size > 0 {
        println!("Cell unallocated");
        source.seek(SeekFrom::Current(cell_size.abs() as i64 - 6))?;
        return Ok(());
    }
    println!("Cell size: {}", cell_size.abs());
    println!("Cell raw: {:?}", &key);
    println!("Cell key: {:?}", std::str::from_utf8(&key));
    let cell_magic = key[0] as u16 + key[1] as u16 * 256;
    let mut _buf = vec![0u8; cell_size.abs() as usize - 6];
    source.read_exact(&mut _buf)?;
    match cell_magic {
        KEY_NODE => {
            parse_key_node(&mut Cursor::new(_buf))?;
        },
        KEY_VALUE => {
            parse_key_value(&mut Cursor::new(_buf))?;
        },
        FAST_LEAF => {
            parse_fast_leaf(&mut Cursor::new(_buf))?;
        },
        KEY_SECURITY => {
            parse_key_security(&mut Cursor::new(_buf))?;
        },
        _ => {},
    }

    Ok(())
}

fn main() {
    let path = std::env::args().skip(1).nth(0).unwrap();
    let mut file = BufReader::new(File::open(path).unwrap());

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"regf");
    let primary_seq = file.read_u32::<LittleEndian>().unwrap();
    let secondary_seq = file.read_u32::<LittleEndian>().unwrap();
    let last_modified = file.read_u64::<LittleEndian>().unwrap();
    let major_ver = file.read_u32::<LittleEndian>().unwrap();
    let minor_ver = file.read_u32::<LittleEndian>().unwrap();
    let file_type = file.read_u32::<LittleEndian>().unwrap();
    let file_format = file.read_u32::<LittleEndian>().unwrap();
    let root_cell_offset = file.read_u32::<LittleEndian>().unwrap();
    let hive_data_size = file.read_u32::<LittleEndian>().unwrap();
    let clustering_factor = file.read_u32::<LittleEndian>().unwrap();
    println!("P: {}, S: {}, LM: {}", primary_seq, secondary_seq, last_modified);
    println!("({}, {}) -> {} - {}", major_ver, minor_ver, file_type, file_format);
    println!("Root Cell Offset: {}", root_cell_offset);
    println!("Hive Data: {}", hive_data_size);
    println!("Clustering Factor: {}", clustering_factor);

    file.seek(SeekFrom::Start(4096)).unwrap();

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
      load_cell(&mut file, &mut size).unwrap();
    }
}
