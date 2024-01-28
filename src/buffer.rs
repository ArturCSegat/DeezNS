use anyhow;
use crate::record::DnsRecord;

#[derive(Debug)]
pub struct DnsBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl DnsBuffer {
    pub fn new() -> DnsBuffer {
        DnsBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    pub fn step(&mut self, steps: usize) -> anyhow::Result<()> {
        self.pos += steps;
        Ok(())
    }


    pub fn seek(&mut self, pos: usize) -> anyhow::Result<()> {
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> anyhow::Result<u8> {
        if self.pos >= 512 {
            return Err(anyhow::anyhow!("read error: End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn get(&mut self, pos: usize) -> anyhow::Result<u8> {
        if pos >= 512 {
            return Err(anyhow::anyhow!("get error: End of buffer"));
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_range(&mut self, start: usize, len: usize) -> anyhow::Result<&[u8]> {
        if start + len >= 512 {
            return Err(anyhow::anyhow!("get_range error: End of buffer"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    pub fn read_u16(&mut self) -> anyhow::Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> anyhow::Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    pub fn write(&mut self, byte: u8) -> anyhow::Result<()> {
        if self.pos >= 512 {
            return Err(anyhow::anyhow!("write error: end of buffer"))
        }
        self.buf[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u16(&mut self, byte: u16) -> anyhow::Result<()> {
        if self.pos >= 512 {
            return Err(anyhow::anyhow!("write_u16 error: end of buffer"))
        }
        self.write((byte >> 8) as u8)?;
        self.write((byte & 0xFF) as u8)?;
        Ok(())
    }
    pub fn write_u32(&mut self, byte: u32) -> anyhow::Result<()> {
        if self.pos >= 512 {
            return Err(anyhow::anyhow!("write_u32 error: end of buffer"))
        }
        // most of the 0xFF are for the pretty, think the first and secnd are necessary
        self.write(((byte >> 24) & 0xFF) as u8)?;
        self.write(((byte >> 16) & 0xFF) as u8)?;
        self.write(((byte >> 8) & 0xFF) as u8)?;
        self.write(((byte >> 0) & 0xFF) as u8)?;
        Ok(())
    }

    #[allow(unused_variables, unused_mut)]
    pub fn get_domain(&mut self) -> anyhow::Result<String> {
        let mut local_pos = self.pos;

        // preventing jump looping
        let max_jumps = 5;
        let mut jump_counter = 0;
        let mut jumped = false;

        let mut domain_buffer = String::new();

        loop {
            if jump_counter > max_jumps {
                return Err(anyhow::anyhow!("Reaced max jump limit"));
            }
            let len = self.get(local_pos)?;
            // jump requested
            if (len & 0xC0) == 0xC0 {
                self.seek(local_pos + 2)?;

                let b2 = self.get(local_pos + 1)? as u16;            
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;     
                local_pos = offset as usize;

                jumped = true;
                jump_counter += 1;
                continue;
            } else {
                local_pos += 1;

                if len == 0 {
                    break;
                }

                if !domain_buffer.is_empty() {
                    domain_buffer.push('.');
                }

                domain_buffer.push_str(
                    &String::from_utf8_lossy(
                        self.get_range(local_pos, len as usize)?
                        ).to_lowercase()
                    );

                local_pos += len as usize;
            }
            
            // if no jump was perfomed, this makes sure local aligns with real pos
            // if a jump was perfomed, then local shouldn't align with real pos and we dont try do
            // to it
            if !jumped {
                self.seek(local_pos + 1)?;
            }
        }
        Ok(domain_buffer)
    }



}
