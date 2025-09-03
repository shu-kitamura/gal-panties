use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;

const HOST: &str = "127.0.0.1";
const PORT: &str = "7777";

fn main() -> std::io::Result<()> {
    let addr = format!("{}:{}", HOST, PORT);
    let mut stream = TcpStream::connect(&addr)?;

    println!("type message to send. type /quit to disconnect.");

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
        let resp = String::from_utf8_lossy(&buf[..n]);
        println!("> {}", resp);
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
    let resp = String::from_utf8_lossy(&buf[..n]);
    println!("> {}", resp);

    Ok(())
}
