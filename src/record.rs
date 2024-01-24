use std::net::{Ipv4Addr, Ipv6Addr};
use anyhow;
use crate::buffer;

// represents the type of a record
#[derive(Debug, Clone)]
pub enum RDataType {
    UNKNOWN(u16),
    A(Option<Ipv4Addr>),
    NS(Option<String>),
    TXT(Option<String>),
    AAAA(Option<Ipv6Addr>),
}

impl RDataType {
    pub fn from_num(num: u16) -> RDataType {
        match num {
            1 => Self::A(None),
            2 => Self::NS(None),
            16 => Self::TXT(None),
            28 => Self::AAAA(None),
            _ => Self::UNKNOWN(num)
        }
    }

    pub fn to_num(&self) -> u16 {
        match self {
            RDataType::UNKNOWN(x) => *x, // unwrap is safe because x came from to_string()
            RDataType::NS(_) => 2,
            RDataType::A(_) => 1,
            RDataType::AAAA(_) => 28,
            RDataType::TXT(_) => 16,
        }
    }

    pub fn has_data(&self) -> bool {
        match self {
            RDataType::UNKNOWN(op) => true,
            RDataType::NS(op) => op.is_some(),
            RDataType::A(op) => op.is_some(),
            RDataType::AAAA(op) => op.is_some(),
            RDataType::TXT(op) => op.is_some(),
        }
    }
}

// represents the class of a record
#[derive(Debug, Clone)]
pub enum RClass {
    IN,
    SOMETHING(u16),
}

impl RClass {
    pub fn from_num(num: u16) -> RClass {
        match num {
            1 => Self::IN,
            _ => Self::SOMETHING(num)
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            RClass::IN => 1,
            RClass::SOMETHING(x) => x,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DnsRecord {
    pub domain: String,
    pub rtype: RDataType,
    pub rclass: RClass,
    pub ttl: Option<u32>,
    pub data_len: Option<u16>,
}

pub enum RecordType {
    QUESTION,
    OTHER,
}

impl DnsRecord {
    pub fn from_buf(buf: &mut buffer::DnsBuffer, record_type: RecordType) -> anyhow::Result<DnsRecord> {
        match record_type {
            RecordType::QUESTION => Ok(DnsRecord {
                domain: buf.get_domain()?,
                rtype: RDataType::from_num(buf.read_u16()?),
                rclass: RClass::from_num(buf.read_u16()?),
                ttl: None,
                data_len: None,
            }),
            RecordType::OTHER => {
                let domain = buf.get_domain()?;
                let mut rtype = RDataType::from_num(buf.read_u16()?);
                let rclass = RClass::from_num(buf.read_u16()?);
                let ttl = buf.read_u32()?;
                let data_len = buf.read_u16()?;

                rtype = match rtype {
                    RDataType::A(_) => {
                        let raw_addr = buf.read_u32()?;
                        RDataType::A(Some(Ipv4Addr::new(
                                    ((raw_addr >> 24) & 0xFF) as u8,
                                    ((raw_addr >> 16) & 0xFF) as u8,
                                    ((raw_addr >> 8) & 0xFF) as u8,
                                    ((raw_addr >> 0) & 0xFF) as u8,
                                    )))
                    }
                    RDataType::AAAA(_) => {
                        let raw_addr1 = buf.read_u32()?;
                        let raw_addr2 = buf.read_u32()?;
                        let raw_addr3 = buf.read_u32()?;
                        let raw_addr4 = buf.read_u32()?;
                        RDataType::AAAA(Some(Ipv6Addr::new(
                                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                                    )))
                    }
                    RDataType::NS(_) => {
                        RDataType::NS(Some(buf.get_domain()?))
                    }
                    RDataType::TXT(_) => {
                        RDataType::TXT(Some(String::from_utf8_lossy(buf.get_range(buf.pos, data_len as usize)?).to_string()))
                    }
                    RDataType::UNKNOWN(x)=> {
                        RDataType::UNKNOWN(x)
                    }
                };

                Ok(DnsRecord {
                    domain,
                    rtype,
                    rclass,
                    ttl: Some(ttl),
                    data_len: Some(data_len),
                })
            }
        }
    }

    pub fn write(&self, buf: &mut buffer::DnsBuffer) -> anyhow::Result<()> {
        // write domain, 
        for label in self.domain.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(anyhow::anyhow!("write_record error: exceeded max label lenght of 63"))
            }
            buf.write(len as u8)?;
            for byte in label.as_bytes() {
                buf.write(*byte)?;
            }
        }
        buf.write(0)?;
        // write type,
        println!("{:?}", self.rtype);
        buf.write_u16(self.rtype.to_num())?;
        // write class
        buf.write_u16(self.rclass.to_num())?;
        // write ttl,
        if let Some(ttl) = self.ttl {
            buf.write_u32(ttl)?;
        }
        // write data len
        if let Some(dlen) = self.data_len {
            buf.write_u16(dlen)?;
        }
        // write data   
        
        // garantees self.rtype has data and is safe to unwrap
        if !self.rtype.has_data() {
            return Ok(());
        }

        match &self.rtype {
            RDataType::A(data) => {
                for o in data.unwrap().octets() {
                    buf.write(o)?;
                }
            }
            RDataType::AAAA(data) => {
                for o in data.unwrap().octets() {
                    buf.write(o)?;
                }
            }
            RDataType::NS(data) | RDataType::TXT(data) => {
                for label in data.as_ref().unwrap().split('.') { 
                    let len = label.len();
                    if len > 63 {
                        return Err(anyhow::anyhow!("write_record error: exceeded max label lenght of 63"))
                    }
                    buf.write(len as u8)?;
                    for byte in label.as_bytes() {
                        buf.write(*byte)?;
                    }
                }
                buf.write(0)?;
            }
            RDataType::UNKNOWN(_) => {
                for b in "could read data, unknow type".to_owned().as_bytes() {
                    buf.write(*b)?;
                }
            }
        }
        Ok(())
    }
}

