use std::net::{Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use anyhow;
use crate::buffer;

#[derive(Debug, Clone)]
pub enum Domain {
    Domain(String),
    Jump(Box<[u8; 2]>),
}

impl Domain {
    pub fn get_string(&self, buf: &mut buffer::DnsBuffer) -> anyhow::Result<String> {
        match &self {
            Domain::Domain(str) => Ok(str.to_owned()),
            Domain::Jump(jump_offset) => {
                let pos_back = buf.pos; // save it for later
                buf.seek(jump_offset[1] as usize)?;
                let str = buf.get_domain()?;
                buf.pos = pos_back;
                Ok(str)
            },
        }
    }
}

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
            RDataType::UNKNOWN(x) => *x,
            RDataType::NS(_) => 2,
            RDataType::A(_) => 1,
            RDataType::AAAA(_) => 28,
            RDataType::TXT(_) => 16,
        }
    }

    pub fn has_data(&self) -> bool {
        match self {
            RDataType::UNKNOWN(_) => true,
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
    pub domain: Domain,
    pub rtype: RDataType,
    pub rclass: RClass,
    pub ttl: Option<u32>,
    pub data_len: Option<u16>,
}

pub enum RecordType {
    QUESTION,
    OTHER,
}

impl  DnsRecord {
    pub fn from_buf(buf: &mut buffer::DnsBuffer, record_type: RecordType, domains: &mut HashMap<String, u8>) -> anyhow::Result<DnsRecord> {
        let domain: Domain;
        let domain_text = buf.get_domain()?;

        domain = match domains.get(&domain_text)  {
            None => {
                let off = domain_text
                    .split('.')
                    .map(|label| {label.len() as u8 + 1})
                    .sum::<u8>()
                    + 1;
                domains.insert(domain_text.clone(), buf.pos as u8 - off);
                Domain::Domain(domain_text)
            }
            Some(offset) => {
                Domain::Jump(Box::new([0xC0, *offset]))
            }
        };

        let mut rtype = RDataType::from_num(buf.read_u16()?);
        let rclass = RClass::from_num(buf.read_u16()?);

        match record_type {
            RecordType::QUESTION => Ok(DnsRecord {
                domain,
                rtype,
                rclass,
                ttl: None,
                data_len: None,
            }),
            RecordType::OTHER => {
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

    pub fn write(&self, buf: &mut buffer::DnsBuffer, domain_jumps: &HashMap<String, u8>) -> anyhow::Result<()> {
        match &self.domain {
            Domain::Domain(domain) => {
                let mut found = false;
                for d in domain_jumps.keys() {
                    if let Some(idx) = domain.find(d) {
                        let (new, repeat) = domain.split_at(idx);
                        let new = new.trim_end_matches(|c| c == '.');
                        buf.write(new.len() as u8)?;
                        for b in new.as_bytes() {
                            buf.write(*b)?;
                        }
                        buf.write(0xC0)?;
                        buf.write(*domain_jumps.get(repeat).unwrap())?;
                        found = true;
                        break;
                    }
                }

                if !found {
                    for label in domain.split('.') {
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
            }
            Domain::Jump(jump_code) => {
                buf.write(jump_code[0])?;
                buf.write(jump_code[1])?;
            }
        }

        buf.write_u16(self.rtype.to_num())?;
        buf.write_u16(self.rclass.to_num())?;

        if let Some(ttl) = self.ttl {
            buf.write_u32(ttl)?;
        }
        if let Some(dlen) = self.data_len {
            buf.write_u16(dlen)?;
        }
        
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
                let mut found = false;
                for d in domain_jumps.keys() {
                    if let Some(idx) = data.as_ref().unwrap().find(d) {
                        let (new, repeat) = data.as_ref().unwrap().split_at(idx);
                        let new = new.trim_end_matches(|c| c == '.');
                        buf.write(new.len() as u8)?;
                        for b in new.as_bytes() {
                            buf.write(*b)?;
                        }
                        buf.write(0xC0)?;
                        buf.write(*domain_jumps.get(repeat).unwrap())?;
                        found = true;
                        break;
                    }
                }

                if !found {
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

