use crate::{header::DnsHeader, record::{DnsRecord, RecordType}, buffer::DnsBuffer};

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsRecord>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buf(buf: &mut DnsBuffer) -> anyhow::Result<DnsPacket> {
        let mut dns_p = DnsPacket::new();

        dns_p.header = DnsHeader::new();
        dns_p.header.read(buf)?;

        for _ in 0..dns_p.header.questions {
            dns_p.questions.push(DnsRecord::from_buf(buf, RecordType::QUESTION)?);
        }
        for _ in 0..dns_p.header.answers {
            let a = DnsRecord::from_buf(buf, RecordType::OTHER)?;
            // println!("{:?}", a);
            dns_p.answers.push(a);
            
        }
        for _ in 0..dns_p.header.authoritative_entries {
            dns_p.authorities.push(DnsRecord::from_buf(buf, RecordType::OTHER)?);
        }
        for _ in 0..dns_p.header.resource_entries {
            dns_p.questions.push(DnsRecord::from_buf(buf, RecordType::OTHER)?);
        }

        Ok(dns_p)
    }


    
}
