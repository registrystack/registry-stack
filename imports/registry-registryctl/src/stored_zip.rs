use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{ensure, Context, Result};

pub struct ZipEntry<'a> {
    name: &'a str,
    data: &'a [u8],
}

impl<'a> ZipEntry<'a> {
    pub const fn new(name: &'a str, data: &'a [u8]) -> Self {
        Self { name, data }
    }
}

pub struct ZipStoreWriter;

impl ZipStoreWriter {
    pub fn write(path: &Path, entries: &[ZipEntry<'_>]) -> Result<()> {
        let mut file =
            File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
        let mut central_entries = Vec::with_capacity(entries.len());

        for entry in entries {
            ensure!(
                entry.name.len() <= u16::MAX as usize,
                "zip entry name too long: {}",
                entry.name
            );
            ensure!(
                entry.data.len() <= u32::MAX as usize,
                "zip entry too large: {}",
                entry.name
            );

            let offset = file.stream_position()? as u32;
            let crc = crc32fast::hash(entry.data);
            write_local_header(&mut file, entry, crc)?;
            file.write_all(entry.data)?;
            central_entries.push(CentralEntry {
                name: entry.name.to_string(),
                crc,
                size: entry.data.len() as u32,
                offset,
            });
        }

        let central_offset = file.stream_position()? as u32;
        for entry in &central_entries {
            write_central_directory_entry(&mut file, entry)?;
        }
        let central_size = file.stream_position()? as u32 - central_offset;
        write_end_of_central_directory(
            &mut file,
            entries.len() as u16,
            central_size,
            central_offset,
        )?;
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}

struct CentralEntry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
}

fn write_local_header<W: Write>(writer: &mut W, entry: &ZipEntry<'_>, crc: u32) -> Result<()> {
    writer.write_all(&0x0403_4b50_u32.to_le_bytes())?;
    writer.write_all(&20_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&crc.to_le_bytes())?;
    writer.write_all(&(entry.data.len() as u32).to_le_bytes())?;
    writer.write_all(&(entry.data.len() as u32).to_le_bytes())?;
    writer.write_all(&(entry.name.len() as u16).to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(entry.name.as_bytes())?;
    Ok(())
}

fn write_central_directory_entry<W: Write>(writer: &mut W, entry: &CentralEntry) -> Result<()> {
    writer.write_all(&0x0201_4b50_u32.to_le_bytes())?;
    writer.write_all(&20_u16.to_le_bytes())?;
    writer.write_all(&20_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&entry.crc.to_le_bytes())?;
    writer.write_all(&entry.size.to_le_bytes())?;
    writer.write_all(&entry.size.to_le_bytes())?;
    writer.write_all(&(entry.name.len() as u16).to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u32.to_le_bytes())?;
    writer.write_all(&entry.offset.to_le_bytes())?;
    writer.write_all(entry.name.as_bytes())?;
    Ok(())
}

fn write_end_of_central_directory<W: Write>(
    writer: &mut W,
    entry_count: u16,
    central_size: u32,
    central_offset: u32,
) -> Result<()> {
    writer.write_all(&0x0605_4b50_u32.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    writer.write_all(&entry_count.to_le_bytes())?;
    writer.write_all(&entry_count.to_le_bytes())?;
    writer.write_all(&central_size.to_le_bytes())?;
    writer.write_all(&central_offset.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    Ok(())
}
