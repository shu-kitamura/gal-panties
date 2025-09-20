use std::io::{Read, Write};
use std::net::TcpListener;

use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "7777")]
    port: String,
}

fn main() -> std::io::Result<()> {
    let opt = Opt::parse();
    let ipv4addr = get_ipv4addr(&opt.iface);
    let addr_port = format!("{}:{}", ipv4addr, opt.port);
    let listener = TcpListener::bind(addr_port)?;

    for stream_res in listener.incoming() {
        let mut stream = match stream_res {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };

        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let mut is_call_success: bool = false;

        let mut buf = [0u8; 1024];
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) => {
                    println!("disconnected: {}", peer);
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    eprintln!("read error from {}: {}", peer, e);
                    break;
                }
            };

            println!("> {}", String::from_utf8_lossy(&buf[..n]));

            if !is_call_success {
                let response = "願いを言え。どんな願いもひとつだけ叶えてやろう";
                println!("{}", response);
                stream.write_all(response.as_bytes()).unwrap();
                is_call_success = true;
            } else {
                let response = "たやすい願いだ";
                println!("{}", response);
                stream.write_all(response.as_bytes()).unwrap();
                break;
            }
        }
    }

    Ok(())
}

fn get_ipv4addr(iface: &str) -> String {
    let iface = pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .expect("Failed to get interface");
    let addr = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .expect("Failed to get IPv4 address");
    addr.ip().to_string()
}
