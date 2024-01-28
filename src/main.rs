use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use deez_ns::buffer::DnsBuffer;
use deez_ns::header::ResultCode;
use deez_ns::record::{DnsRecord, RDataType, RClass, Domain};
use deez_ns::server::Server;

fn main() {
    let mut cache: HashMap<String, RDataType> = HashMap::new();
    cache.insert("yahoo.com".to_owned(), RDataType::A(Some(Ipv4Addr::from_str("0.0.0.1").unwrap())));
    cache.insert("youtube.com".to_owned(), RDataType::A(Some(Ipv4Addr::from_str("0.0.0.2").unwrap())));
    
    let server = Server::new("0.0.0.0");
    
    loop {
        let buf = &mut DnsBuffer::new();
        let (mut pack, from) = server.get_query(buf).unwrap();

        let r_buf = &mut DnsBuffer::new();
        if let Some(data) =  cache.get(&pack.questions[0].domain.get_string(buf).unwrap()) {
            pack.header.response = true;
            pack.header.answers = 1;
            pack.header.rescode = ResultCode::NOERROR;
            pack.header.recursion_available = true;
            pack.header.write(r_buf).unwrap();

            let fuck = HashMap::new();
            pack.questions[0].write(r_buf, &fuck).unwrap();
            DnsRecord {
                domain: Domain::Jump(Box::new([0xC0, *pack.domain_jumps.get(&pack.questions[0].domain.get_string(buf).unwrap()).unwrap()])),
                rtype: data.clone(),
                rclass: RClass::IN,
                ttl: Some(1000),
                data_len: Some(4),
            }.write(r_buf, &pack.domain_jumps).unwrap();
        } else {
            let r_pack = server.resolve(&pack).unwrap();
            r_pack.header.write(r_buf).unwrap();
            let quest_dom_jmp: HashMap<String, u8> = HashMap::new();
            r_pack.questions.iter().for_each(|q| {q.write(r_buf, &quest_dom_jmp).unwrap()});
            r_pack.answers.iter().for_each(|a| {a.write(r_buf, &r_pack.domain_jumps).unwrap()});

            r_pack.questions
                .iter()
                .zip(r_pack.answers.iter())
                .for_each(
                    |(q, a)| {
                        cache.insert(q.domain.get_string(buf).unwrap(), a.rtype.clone());
                    }
                );
            println!("{:#?}", r_pack);
        }
        println!("{:02X?}", &r_buf.buf[0..r_buf.pos]);
        server.respond_with(r_buf, from).unwrap();
    }
}


