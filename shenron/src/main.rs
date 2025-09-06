use std::io::{Read, Write};
use std::net::TcpListener;

const HOST: &str = "127.0.0.1";
const PORT: &str = "7777";

fn main() -> std::io::Result<()> {
    let addr = format!("{}:{}", HOST, PORT);
    let listener = TcpListener::bind(addr)?;

    // シングルスレッドで逐次処理
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