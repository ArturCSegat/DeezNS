use std::net::UdpSocket;
use deez_ns::buffer::DnsBuffer;
use deez_ns::packet::DnsPacket;
use deez_ns::record::{DnsRecord, RType, RClass};

fn main() {
    let server = ("8.8.8.8", 53);

    let mut q_pack = DnsPacket::new();
    q_pack.header.recursion_desired = true;
    q_pack.header.questions = 1;
    q_pack.header.id = 6969;
    q_pack.questions.push(
        DnsRecord{
            domain: "google.com".to_owned(),
            rtype: RType::NS,
            rclass: RClass::IN,
            ttl: None,
            data_len: None,
            data: None,
        }
    );

    let sock = UdpSocket::bind(("0.0.0.0", 3000)).unwrap();
    let mut deez1 = DnsBuffer::new();
    q_pack.header.write(&mut deez1).unwrap();
    q_pack.questions.iter().for_each(|q| {deez1.write_record(q).unwrap()});

    sock.send_to(&deez1.buf[0..deez1.pos], server).unwrap();

    let mut deez2 = DnsBuffer::new();
    sock.recv_from(&mut deez2.buf).unwrap();

    let r_pack = DnsPacket::from_buf(&mut deez2);

    println!("{:#?}", r_pack);
}

