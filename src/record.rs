use core::panic;
use crate::buffer;

// represents the type of a record
#[derive(Debug, Clone)]
pub enum RType {
    UNKNOWN(u16),
    A,
    NS,
}

impl RType {
    pub fn from_num(num: u16) -> RType {
        match num {
            1 => Self::A,
            2 => Self::NS,
            _ => Self::UNKNOWN(num)
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            RType::UNKNOWN(x) => x,
            RType::NS => 2,
            RType::A => 1,
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
    pub rtype: RType,
    pub rclass: RClass,
    pub ttl: Option<u32>,
    pub data_len: Option<u16>,
    pub data: Option<String>,
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
                rtype: RType::from_num(buf.read_u16()?),
                rclass: RClass::from_num(buf.read_u16()?),
                ttl: None,
                data_len: None,
                data: None
            }),
            RecordType::OTHER => {
                let domain = buf.get_domain()?;
                let rtype = RType::from_num(buf.read_u16()?);
                let rclass = RClass::from_num(buf.read_u16()?);
                let ttl = buf.read_u32()?;
                let data_len = buf.read_u16()?;
                // let data = String::from_utf8_lossy(buf.get_range(buf.pos, data_len as usize)?);

                let data = match rtype {
                    RType::A => {
                        let raw_addr = buf.read_u32()?;
                        let a = ((raw_addr >> 24) & 0xFF) as u8;
                        let b = ((raw_addr >> 16) & 0xFF) as u8;
                        let c = ((raw_addr >> 8) & 0xFF) as u8;
                        let d = ((raw_addr >> 0) & 0xFF) as u8;
                        format!("{}.{}.{}.{}", a, b, c, d)
                    }
                    RType::NS => {
                        buf.get_domain()?
                        }
                    RType::UNKNOWN(_)=> {
                        "cant read data, unknown rtype".to_owned()
                    }
                };
            
                Ok(DnsRecord {
                    domain,
                    rtype,
                    rclass,
                    ttl: Some(ttl),
                    data_len: Some(data_len),
                    data: Some(data),
                })
            }
        }
    }
}

