use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;

use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    addr: String,

    #[clap(short, long, default_value = "7777")]
    port: String,
}

fn main() -> std::io::Result<()> {
    let opt = Opt::parse();
    let addr_port = format!("{}:{}", opt.addr, opt.port);
    let mut stream = TcpStream::connect(&addr_port)?;

    first_connection(&mut stream)?;

    let stdin = io::stdin();
    let mut buf = [0u8; 1024];

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                eprintln!("stdin error: {}", e);
                break;
            }
        };

        let cmd = line.trim();
        if cmd.eq_ignore_ascii_case("/quit") || cmd.eq_ignore_ascii_case("/exit") {
            println!("disconnecting...");
            break;
        }

        // 送信
        stream.write_all(line.as_bytes())?;
        stream.flush()?;

        // 応答読み取り（1回分）
        let n = stream.read(&mut buf)?;
        if n == 0 {
            println!("server closed the connection");
            break;
        }
        let _resp = String::from_utf8_lossy(&buf[..n]);
    }

    Ok(())
}

fn first_connection(stream: &mut TcpStream) -> std::io::Result<()> {
    let spell = "いでよ ドラゴン";
    println!("{}", spell);
    stream.write_all(spell.as_bytes())?;
    stream.flush()?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let _resp = String::from_utf8_lossy(&buf[..n]);

    Ok(())
}
