use std::collections::HashMap;
use crate::{header::DnsHeader, record::{DnsRecord, RecordType}, buffer::DnsBuffer};

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsRecord>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
    pub domain_jumps: HashMap<String, u8>, // maps a domaing to its respective offset
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
            domain_jumps: HashMap::new(),
        }
    }

    pub fn from_buf(buf: &mut DnsBuffer) -> anyhow::Result<DnsPacket> {
        let mut dns_p = DnsPacket::new();

        dns_p.header = DnsHeader::new();
        dns_p.header.read(buf)?;

        for _ in 0..dns_p.header.questions {
            dns_p.questions.push(DnsRecord::from_buf(buf, RecordType::QUESTION, &mut dns_p.domain_jumps)?);
        }
        for _ in 0..dns_p.header.answers {
            dns_p.answers.push(DnsRecord::from_buf(buf, RecordType::OTHER, &mut dns_p.domain_jumps)?);
        }
        for _ in 0..dns_p.header.authoritative_entries {
            dns_p.authorities.push(DnsRecord::from_buf(buf, RecordType::OTHER, &mut dns_p.domain_jumps)?);
        }
        for _ in 0..dns_p.header.resource_entries {
            dns_p.questions.push(DnsRecord::from_buf(buf, RecordType::OTHER, &mut dns_p.domain_jumps)?);
        }

        Ok(dns_p)
    }


    
}
