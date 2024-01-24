use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use deez_ns::buffer::DnsBuffer;
use deez_ns::header::ResultCode;
use deez_ns::record::{DnsRecord, RDataType, RClass};
use deez_ns::server::Server;

fn main() {
    let mut cache: HashMap<String, RDataType> = HashMap::new();
    cache.insert("google.com".to_owned(), RDataType::A(Some(Ipv4Addr::from_str("0.0.0.0").unwrap())));
    cache.insert("yahoo.com".to_owned(), RDataType::A(Some(Ipv4Addr::from_str("0.0.0.1").unwrap())));
    cache.insert("youtube.com".to_owned(), RDataType::A(Some(Ipv4Addr::from_str("0.0.0.2").unwrap())));
    
    let server = Server::new("0.0.0.0");
    
    loop {
        let buf = &mut DnsBuffer::new();
        let (mut pack, from) = server.get_query(buf).unwrap();
        println!("{:#?}", pack);

        let r_buf = &mut DnsBuffer::new();
        if let Some(data) =  cache.get(&pack.questions[0].domain) {
            pack.header.response = true;
            pack.header.answers = 1;
            pack.header.rescode = ResultCode::NOERROR;
            pack.header.recursion_available = true;
            pack.header.write(r_buf).unwrap();

            pack.questions[0].write(r_buf).unwrap();
            DnsRecord {
                domain: pack.questions[0].domain.clone(),
                rtype: data.clone(),
                rclass: RClass::IN,
                ttl: Some(1000),
                data_len: Some(4),
            }.write(r_buf).unwrap();
        } else {
            let r_pack = server.resolve(&pack).unwrap();
            r_pack.header.write(r_buf).unwrap();
            r_pack.questions.iter().for_each(|q| {q.write(r_buf).unwrap()});
            r_pack.answers.iter().for_each(|a| {a.write(r_buf).unwrap()});

            r_pack.questions
                .iter()
                .zip(r_pack.answers.iter())
                .for_each(
                    |(q, a)| {
                        cache.insert(q.domain.clone(), a.rtype.clone());
                    }
                );
        }
        server.respond_with(r_buf, from).unwrap();
    }
}


