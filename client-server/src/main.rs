use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    let mut received_data = Vec::new();

    // Read data from the stream into the buffer until EOF or buffer capacity
    while let Ok(bytes_read) = stream.read(&mut buffer) {
        if bytes_read == 0 {
            // EOF reached
            break;
        }
        received_data.extend_from_slice(&buffer[..bytes_read]);
    }

    // Process the received data
    // Here you can deserialize, interpret, or handle the data according to your application logic
    println!("Received data: {:?}", received_data);
}
