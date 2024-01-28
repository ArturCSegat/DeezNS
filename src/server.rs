use std::net::{UdpSocket, SocketAddr};
use std::collections::HashMap;
use anyhow;
use crate::{buffer::DnsBuffer, packet::DnsPacket};

pub struct Server {
    sock: UdpSocket,
}

impl Server {
    pub fn new(string: &str) -> Server {
        Server {
            sock: UdpSocket::bind((string, 3000)).unwrap()
        }
    }

    pub fn get_query(&self, buf: &mut DnsBuffer) -> anyhow::Result<(DnsPacket, SocketAddr)> {
        let (_, from) = self.sock.recv_from(&mut buf.buf)?;
        Ok((DnsPacket::from_buf(buf)?, from))
    }
    
    pub fn respond_with(&self, buf: &DnsBuffer, to: SocketAddr) -> anyhow::Result<()> {
        let _ = self.sock.send_to(&buf.buf[0..buf.pos], to)?;
        Ok(())
    }

    pub fn resolve(&self, pack: &DnsPacket) -> anyhow::Result<DnsPacket> {
        let server = ("8.8.8.8", 53);

        let buf = &mut DnsBuffer::new();
        // let quest_dom_jmp: HashMap<String, u8> = HashMap::new();
        pack.header.write(buf)?;
        let fuck = HashMap::new();
        for q in pack.questions.iter() {
            q.write(buf, &fuck)?;
        }
        
        self.sock.send_to(&buf.buf[0..buf.pos], server)?;

        let mut deez2 = DnsBuffer::new();
        self.sock.recv_from(&mut deez2.buf)?;
        Ok(DnsPacket::from_buf(&mut deez2)?)
    }
}
