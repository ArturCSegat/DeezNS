use deez_ns::reader::DnsBuffer;
use deez_ns::packet::DnsPacket;
use std::fs::File;
use std::io::Read;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    
    if args.len() != 2 {
        panic!("must provide exaclty 1 file to parse")
    }

    let mut deez = DnsBuffer::new();
    let mut f = File::open(&args[1]).unwrap();
    f.read(&mut deez.buf).unwrap();

    let pack = DnsPacket::from_buf(&mut deez).unwrap();
    pack.questions.iter().for_each(|r| {
        // let ip = Ipv4Addr::from_str(r.data.as_ref().unwrap().as_ref()).unwrap();
        println!("{:?}", r);
    });
    pack.answers.iter().for_each(|r| {
        // let ip = Ipv4Addr::from_str(r.data.as_ref().unwrap().as_ref()).unwrap();
        println!("{:?}", r);
    })
}
