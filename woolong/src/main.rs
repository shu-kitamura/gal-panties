use anyhow::Context as _;
use aya::{maps::AsyncPerfEventArray, programs::{Xdp, XdpFlags}, util::online_cpus};
use bytes::BytesMut;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/woolong"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("woolong").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");

    for cpu_id in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                println!("event");
                for buffer in buffers.iter_mut().take(events.read) {
                    let ptr = buffer.as_ptr() as *const woolong_common::Packet;
                    let packet = unsafe { ptr.read_unaligned() };
                    let mut data_str = String::new();
                    for i in 0..packet.data.len() {
                        data_str += &format!("{:02x} ", packet.data[i]);
                        if i % 16 == 15 {
                            data_str += "\n";
                        }
                    }
                    println!("{}", data_str);
                }
            }
        });
    }

    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
