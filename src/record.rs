use crate::reader;

// represents the type of a record
#[derive(Debug)]
pub enum RType {
    UNKNOWN(u16),
    A,
}

impl RType {
    pub fn from_num(num: u16) -> RType {
        match num {
            1 => Self::A,
            _ => Self::UNKNOWN(num)
        }
    }

    pub fn to_num(&self) -> u16 {
        match *self {
            RType::UNKNOWN(x) => x,
            RType::A => 1,
        }
    }
}

// represents the class of a record
#[derive(Debug)]
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
pub struct Record {
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

impl Record {
    pub fn from_buf(buf: &mut reader::DnsBuffer, record_type: RecordType) -> anyhow::Result<Record> {
        match record_type {
            RecordType::QUESTION => Ok(Record {
                domain: buf.get_name_from_request()?,
                rtype: RType::from_num(buf.read_u16()?),
                rclass: RClass::from_num(buf.read_u16()?),
                ttl: None,
                data_len: None,
                data: None
            }),
            RecordType::OTHER => {
                let domain = buf.get_name_from_request()?;
                let rtype = RType::from_num(buf.read_u16()?);
                let rclass = RClass::from_num(buf.read_u16()?);
                let ttl = buf.read_u32()?;
                let data_len = buf.read_u16()?;
                // let data = String::from_utf8_lossy(buf.get_range(buf.pos, data_len as usize)?);
                let raw_addr = buf.read_u32()?;
                let a = ((raw_addr >> 24) & 0xFF) as u8;
                let b = ((raw_addr >> 16) & 0xFF) as u8;
                let c = ((raw_addr >> 8) & 0xFF) as u8;
                let d = ((raw_addr >> 0) & 0xFF) as u8;
                let data = format!("{}.{}.{}.{}", a, b, c, d);
            
                Ok(Record {
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

