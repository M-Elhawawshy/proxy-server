extern crate pnet;

use pnet::datalink;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use proxy::handle_ethernet_frame;
use proxy::{block, ThreadPool};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::{env, io, process};

use clap::{arg, Arg, ArgMatches, Command};

fn cli() -> Command {
    Command::new("proxy")
        .about("A program that implements a basic multithreaded proxy server written in Rust.")
        .subcommand_required(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("dump")
                .about("Dumps the incoming and outgoing packets to a given network interface")
                .arg(arg!(<INTERFACE> "The interface to read/write to"))
                .arg(
                    Arg::new("nthread")
                        .short('t')
                        .long("thread_number")
                        .default_value("5")
                        .help("Specifies the number of threads")
                        .value_name("INTEGER"),
                )
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("block")
                .about("blocks a certain IP from accessing the network")
                .arg(arg!(<IP> "The ip to block from the network")),
        )
}

fn dumb(interface: String, num_threads: usize) {
    use pnet::datalink::Channel::Ethernet;
    let pool: ThreadPool = ThreadPool::new(num_threads);
    let iface_name = interface;

    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("proxy: unhandled channel type"),
        Err(e) => panic!("proxy: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let f = handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
                pool.execute(move || f)
            }
            Err(e) => panic!("proxy: unable to receive packet: {}", e),
        }
    }
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("dump", sub_matches)) => {
            let interface: &String = sub_matches
                .get_one::<String>("INTERFACE")
                .expect("interface required");
            let t: usize = sub_matches
                .get_one::<String>("nthread")
                .unwrap()
                .parse()
                .unwrap();
            dumb(interface.to_owned(), t);
        }
        Some(("block", sub_matches)) => {
            let ip: &String = sub_matches.get_one("IP").expect("IP to block required");
            let ip: IpAddr = ip.as_str().parse().unwrap();
            block(ip);
            use proxy::show_blocked_ips;
            show_blocked_ips();
        }
        _ => {}
    }
}
