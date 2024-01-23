use DeezNS::reader::DnsReader;
use DeezNS::packet::DnsPacket;
use std::fs::File;
use std::io::Read;

fn main() {
    let mut deez = DnsReader::new();
    let mut f = File::open("r2.txt").unwrap();
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
