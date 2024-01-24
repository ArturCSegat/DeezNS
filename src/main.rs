use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use deez_ns::buffer::DnsBuffer;
use deez_ns::header::ResultCode;
use deez_ns::record::{DnsRecord, RDataType, RClass};
use deez_ns::server::Server;

fn main() {
    let mut cache: HashMap<String, Ipv4Addr> = HashMap::new();
    cache.insert("google.com".to_owned(), Ipv4Addr::from_str("0.0.0.0").unwrap());
    cache.insert("yahoo.com".to_owned(), Ipv4Addr::from_str("0.0.0.1").unwrap());
    cache.insert("youtube.com".to_owned(), Ipv4Addr::from_str("0.0.0.2").unwrap());
    
    let server = Server::new("127.0.0.1");
    
    loop {
        let buf = &mut DnsBuffer::new();
        let (mut pack, from) = server.get_query(buf).unwrap();

        if let Some(ip) =  cache.get(&pack.questions[0].domain) {
            let r_buf = &mut DnsBuffer::new();
            pack.header.response = true;
            pack.header.answers = 1;
            pack.header.rescode = ResultCode::NOERROR;
            pack.header.recursion_available = true;
            pack.header.write(r_buf).unwrap();
            
            pack.questions[0].write(r_buf).unwrap();

            DnsRecord {
                domain: pack.questions[0].domain.clone(),
                rtype: RDataType::A(Some(*ip)),
                rclass: RClass::IN,
                ttl: Some(1000),
                data_len: Some(4),
            }.write(r_buf).unwrap();


            server.respond_with(r_buf, from).unwrap();
        }
    }
}


