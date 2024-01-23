use anyhow;
use crate::buffer::DnsBuffer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits // random id

    pub recursion_desired: bool,    // 1 bit // if the requesters wants the server to recurse
    pub truncated_message: bool,    // 1 bit // if the question is larger then 512 (UDP limit)
    pub authoritative_answer: bool, // 1 bit // if the responder owns the domain requested
    pub opcode: u8,                 // 4 bits // operation code (Typically always 0, see RFC1035 for details)
    pub response: bool,             // 1 bit // marks if q or r, 0 (false) for queries 1 (true) for responses

    pub rescode: ResultCode,       // 4 bits // set by server to indicate status of the query
    pub checking_disabled: bool,   // 1 bit 
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit // What? (Originally reserved for later use, but now used for DNSSEC queries.)
    pub recursion_available: bool, // 1 bit // if the server even has recursion

    pub questions: u16,             // 16 bits // counts ques
    pub answers: u16,               // 16 bits // counts
    pub authoritative_entries: u16, // 16 bits // etc
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buf: &mut DnsBuffer) -> anyhow::Result<()>{
        self.id = buf.read_u16()?;

        // flags 
        let flags_1 = buf.read()?;
        let flags_2 = buf.read()?;
        self.recursion_desired = (flags_1 & (1 << 0)) > 0;
        self.truncated_message = (flags_1 & (1 << 1)) > 0;
        self.authoritative_answer = (flags_1 & (1 << 2)) > 0;
        self.opcode = (flags_1 >> 3) & 0x0F;
        self.response = (flags_1 & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(flags_2 & 0x0F);
        self.checking_disabled = (flags_2 & (1 << 4)) > 0;
        self.authed_data = (flags_2 & (1 << 5)) > 0;
        self.z = (flags_2 & (1 << 6)) > 0;
        self.recursion_available = (flags_2 & (1 << 7)) > 0;


        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buf: &mut DnsBuffer) -> anyhow::Result<()> {
        buf.write_u16(self.id)?;

        buf.write(
            (self.recursion_desired as u8)
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | (self.opcode << 3)
            | ((self.response as u8) << 7) as u8,
            )?;

        buf.write(
            (self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7),
            )?;

        buf.write_u16(self.questions)?;
        buf.write_u16(self.answers)?;
        buf.write_u16(self.authoritative_entries)?;
        buf.write_u16(self.resource_entries)?;
        Ok(())
    }
}
