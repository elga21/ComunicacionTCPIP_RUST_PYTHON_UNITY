use std::net::{TcpListener, TcpStream};
use std::io::{self, Read, Write};
use std::str;
use std::thread;
use std::collections::HashMap;
use std::sync::Mutex;

// Se utiliza lazy_static para inicializar una variable global que
// contendrá el estado de los servos de forma segura en un entorno multihilo.
lazy_static::lazy_static! {
    static ref SERVO_VALUES: Mutex<HashMap<String, String>> = {
        let mut map = HashMap::new();
        map.insert("RONZA".to_string(), "0".to_string());
        map.insert("ELEVACION".to_string(), "0".to_string());
        Mutex::new(map)
    };
}

// Función para calcular el checksum NMEA de una cadena.
fn calculate_nmea_checksum(data: &str) -> u8 {
    let mut checksum: u8 = 0;
    for byte in data.bytes() {
        checksum ^= byte;
    }
    checksum
}

// Esta función maneja cada conexión entrante.
fn handle_client(mut stream: TcpStream) {
    println!("Cliente conectado desde: {}", stream.peer_addr().unwrap());
    let mut buffer = [0; 256];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Cliente desconectado: {}", stream.peer_addr().unwrap());
                return;
            }
            Ok(bytes_read) => {
                let received = str::from_utf8(&buffer[..bytes_read])
                    .unwrap_or_default()
                    .trim_matches(char::from(0))
                    .trim();

                println!("Recibido: {}", received);

                // Lógica para procesar la trama NMEA y enviar el ACK al cliente original
                if received.starts_with("$") && received.contains("*") {
                    let parts: Vec<&str> = received.split('*').collect();
                    if parts.len() == 2 {
                        let data = parts[0].trim_start_matches("$");
                        let data_parts: Vec<&str> = data.split(',').collect();

                        if data_parts.len() >= 2 {
                            let servo_type = data_parts[1];
                            let servo_value = data_parts.get(2).unwrap_or(&"0");

                            // Actualiza el valor del servo en el mapa global.
                            let mut values = SERVO_VALUES.lock().unwrap();
                            if values.contains_key(servo_type) {
                                values.insert(servo_type.to_string(), servo_value.to_string());
                            }
                            drop(values); // Libera el lock

                            // 1. Enviar el ACK de vuelta al cliente original (Python)
                            let response_to_python = format!("$ACK,{}*{:02X}\r\n", servo_type, 0);
                            match stream.write_all(response_to_python.as_bytes()) {
                                Ok(_) => println!("Enviado ACK a Python: {}", response_to_python.trim()),
                                Err(e) => {
                                    eprintln!("Error al enviar ACK: {}", e);
                                    return;
                                }
                            }

                            // 2. Conectarse y enviar la nueva trama combinada en formato NMEA al destino
                            let destination_addr = "192.168.0.249:9090";
                            match TcpStream::connect(destination_addr) {
                                Ok(mut dest_stream) => {
                                    // Obtiene los valores de los servos del estado compartido
                                    let values = SERVO_VALUES.lock().unwrap();
                                    let ronza_val = values.get("RONZA").unwrap();
                                    let elevacion_val = values.get("ELEVACION").unwrap();

                                    // Construye la nueva trama NMEA con una coma entre los valores
                                    let nmea_data = format!("ACK,{},{}", ronza_val, elevacion_val);
                                    let checksum = calculate_nmea_checksum(&nmea_data);
                                    let full_nmea_frame = format!("${}*{:02X}\r\n", nmea_data, checksum);

                                    // Envía la trama en formato de bytes ASCII
                                    match dest_stream.write_all(full_nmea_frame.as_bytes()) {
                                        Ok(_) => println!("Trama NMEA enviada a {}: {}", destination_addr, full_nmea_frame.trim()),
                                        Err(e) => eprintln!("Error al enviar datos a {}: {}", destination_addr, e),
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error al conectar con {}: {}", destination_addr, e);
                                }
                            }
                        }
                    }
                } else {
                    eprintln!("Trama NMEA no válida o incompleta: {}", received);
                }
            }
            Err(e) => {
                eprintln!("Error de lectura: {}", e);
                return;
            }
        }
    }
}

fn main() -> io::Result<()> {
    let listen_addr = "192.168.0.20:9090";
    let listener = TcpListener::bind(listen_addr)?;

    println!("Servidor Rust escuchando en {}", listen_addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_client(stream));
            }
            Err(e) => {
                eprintln!("Error al aceptar la conexión: {}", e);
            }
        }
    }

    Ok(())
}