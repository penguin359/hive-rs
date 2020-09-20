use std::io::Cursor;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::SeekFrom;

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
        //assert_eq!(node.last_written, 0x01d44cd3660004ba);
        //assert_eq!(node.access_bits, 0x00000000);
        //assert_eq!(node.parent_offset, 0x00000020);
        //assert_eq!(node.number_subkeys, 13);
        //assert_eq!(node.number_volatile_subkeys, 0);
        //assert_eq!(node.subkey_list_offset, 0x00010530);
        //assert_eq!(node.volatile_subkey_list_offset, 0xffffffff);
        //assert_eq!(node.key_value_count, 0);
        //assert_eq!(node.key_value_offset, 0xffffffff);
        //assert_eq!(node.key_security_offset, 0x00000318);
        //assert_eq!(node.class_name_offset, 0xffffffff);
        //assert_eq!(node.subkey_name_length_max, 26);
        //assert_eq!(node.subkey_class_length_max, 0);
        //assert_eq!(node.value_name_length_max, 0);
        //assert_eq!(node.value_data_length_max, 0);
        //assert_eq!(node.workvar, 0);
        //assert_eq!(node.key_name_length, 13);
        //assert_eq!(node.class_name_length, 0);
        //assert_eq!(node.key_name, "Control Panel");
    }
}



const _INDEX_LEAF:   u16 = 'l' as u16 + 'i' as u16 * 256;  // (li) Subkeys list
const _FAST_LEAF:    u16 = 'l' as u16 + 'f' as u16 * 256;  // (lf) Subkeys list with name hints
const _HASH_LEAF:    u16 = 'l' as u16 + 'h' as u16 * 256;  // (lh) Subkeys list with name hashes
const _INDEX_ROOT:   u16 = 'r' as u16 + 'i' as u16 * 256;  // (ri) List of subkeys lists
const KEY_NODE:     u16 = 'n' as u16 + 'k' as u16 * 256;  // (nk) Registry key node
const _KEY_VALUE:    u16 = 'v' as u16 + 'k' as u16 * 256;  // (vk) Registry key value
const _KEY_SECURITY: u16 = 's' as u16 + 'k' as u16 * 256;  // (sk) Security descriptor
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
