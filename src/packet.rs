use crate::{header::DnsHeader, record::{Record, RecordType}, buffer::DnsBuffer};

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<Record>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub resources: Vec<Record>,
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
            dns_p.questions.push(Record::from_buf(buf, RecordType::QUESTION)?);
        }
        for _ in 0..dns_p.header.answers {
            dns_p.answers.push(Record::from_buf(buf, RecordType::OTHER)?);
        }
        for _ in 0..dns_p.header.authoritative_entries {
            dns_p.authorities.push(Record::from_buf(buf, RecordType::OTHER)?);
        }
        for _ in 0..dns_p.header.resource_entries {
            dns_p.questions.push(Record::from_buf(buf, RecordType::OTHER)?);
        }

        Ok(dns_p)
    }


    
}
