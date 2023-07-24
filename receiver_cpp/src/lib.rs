use std::io::{BufReader, Cursor, Read, Write};
use std::sync::Arc;

use mio::net::TcpListener;
use mio::net::TcpStream;
use rustls::{self, Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use std::net::SocketAddr;

use libc::strlen;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)]
pub struct Receiver {
    certificate_data: *const c_char,
    private_key_data: *const c_char,
    receiver_ip: *const c_char,
    port: u16,

    private: ReceiverPrivate,

    // New field to hold the accepted TcpStream
    accepted_stream: Option<TcpStream>,
    peer_address: Option<SocketAddr>,

    // New field to represent the SSL socket
    ssl_socket: Option<rustls::StreamOwned<rustls::server::ServerConnection, TcpStream>>,

    // New fields for receiving data
    buffer: Vec<u8>,
    bytes_read: usize,

    // New field to store the TLS configuration
    tls_config: Arc<ServerConfig>,
}

// Private variables
struct ReceiverPrivate {
    // New field for Rust TLS server
    listener: Option<TcpListener>,
}

impl Receiver {
    #[no_mangle]
    pub extern "C" fn receiver_new(
        certificate_env_var: *const c_char,
        private_key_env_var: *const c_char,
        receiver_ip: *const c_char,
        port: u16,
    ) -> *mut Self {
        // Here, we're using .expect() to unwrap the Result returned by get_env_variable.
        // If get_env_variable returns an Err, .expect() will cause the program to panic with a helpful error message.
        let certificate_data =
            Self::get_env_variable(certificate_env_var).expect("Failed to get certificate data");
        let private_key_data =
            Self::get_env_variable(private_key_env_var).expect("Failed to get private key data");

        check_keys(
            certificate_data,
            private_key_data,
            "Initialisation".to_string(),
        );

        // Build the TLS configuration
        let tls_config = Self::build_tls_config(certificate_data, private_key_data);
        let private = ReceiverPrivate { listener: None };

        let receiver = Receiver {
            certificate_data,
            private_key_data,
            receiver_ip,
            port,
            private,
            accepted_stream: None,
            peer_address: None,
            ssl_socket: None,
            buffer: Vec::new(),
            bytes_read: 0,
            // Store the TLS configuration in the struct
            tls_config,
        };

        Box::into_raw(Box::new(receiver))
    }

    fn get_env_variable(c_env_var_name: *const c_char) -> Result<*const c_char, &'static str> {
        // Convert the C-style string to a Rust string
        let env_var_name_str = Self::convert_c_string(c_env_var_name)?;

        // Try to get the environment variable
        let env_var_value_str = std::env::var(&env_var_name_str)
            .map_err(|_| "Failed to retrieve environment variable")?;

        #[cfg(feature = "test-env")]
        {
            // println!(
            //     "The value of the environment variable {} is {}",
            //     env_var_name_str, env_var_value_str
            // );
            println!(
                "The length of env_var_value_str is {}",
                env_var_value_str.len()
            );
        }
        // Safe: We are converting the valid Rust string `env_var_value_str` to a CString.
        // The CString owns the memory and will handle its deallocation.
        let cstr_env_var_value = CString::new(env_var_value_str).expect("Failed to create CString");

        #[cfg(feature = "test-env")]
        {
            // Safe: We are calling strlen on a pointer to a null-terminated C string
            let length = unsafe { strlen(cstr_env_var_value.as_ptr()) };
            println!(
                "The length of cstr_env_var_value for {} is {}",
                env_var_name_str, length
            );
        }
        // Memory management note: When we call CString::into_raw(), it gives ownership of the memory
        // occupied by the CString to the raw pointer. This means Rust will no longer clean up this
        // memory automatically: it becomes the caller's responsibility to convert the pointer back
        // into a CString with CString::from_raw() when they're done using it. Failing to do this will
        // result in a memory leak.
        Ok(cstr_env_var_value.into_raw())
    }

    // Helper function to convert *const c_char to a valid Rust String
    fn convert_c_string(ptr: *const c_char) -> Result<String, &'static str> {
        // Safety: We first check if the pointer is not null.
        if ptr.is_null() {
            return Err("Null pointer was provided.");
        }

        // Safety: We are using std::ffi::CStr::from_ptr to create a CStr from a raw pointer,
        // then calling to_string_lossy() on it, which ensures that the raw C string is valid UTF-8 data.
        // It's important that ptr points to a null-terminated string, and that the string remain unchanged
        // until the conversion is complete as the pointer is directly used, not cloned.
        let c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
        let str: String = c_str.to_string_lossy().into_owned();

        Ok(str)
    }

    fn build_tls_config(
        certificate_data: *const c_char,
        private_key_data: *const c_char,
    ) -> Arc<ServerConfig> {
        // check certificate and private key
        check_keys(
            certificate_data,
            private_key_data,
            "build_tls_config".to_string(),
        );

        // Convert *const c_char to valid Rust strings
        let cert_data = Self::convert_c_string(certificate_data)
            .map_err(|err| format!("Failed to convert certificate_data to string: {}", err))
            .expect("Failed to convert certificate_data to string");

        let key_data = Self::convert_c_string(private_key_data)
            .map_err(|err| format!("Failed to convert private_key_data to string: {}", err))
            .expect("Failed to convert private_key_data to string");

        // Parse the certificate and private key data from strings
        let certificates = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(cert_data)))
            .unwrap_or_else(|err| panic!("Failed to parse certificate: {}", err));
        // print key_data for debugging
        let private_keys =
            rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(Cursor::new(key_data)))
                .unwrap_or_else(|err| panic!("Failed to parse private key: {}", err));

        if private_keys.is_empty() {
            panic!("No private keys were parsed from the input data");
        }
        let private_key = PrivateKey(private_keys[0].clone());

        // Convert Vec<Vec<u8>> to Vec<Certificate>
        let certificates: Vec<Certificate> = certificates
            .into_iter()
            .map(|cert_data| Certificate(cert_data))
            .collect();

        // Set the supported TLS versions
        let versions = vec![&rustls::version::TLS12, &rustls::version::TLS13];

        // Build the TLS configuration using ConfigBuilder
        let config = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&versions)
            .expect("Failed to set supported TLS versions")
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .expect("Failed to set the certificate/key in ServerConfig");

        // For example, set other configurations if needed

        // Finalize the ServerConfig and create an Arc from it
        let server_config = Arc::new(config);
        // debug output server config complete
        println!("TLS server config complete");
        server_config
    }

    pub fn start_listening(&mut self) {
        let addr = format!(
            "{}:{}",
            Self::convert_c_string(self.receiver_ip)
                .expect("Failed to convert receiver_ip from C string to Rust string"),
            self.port
        );

        match addr.parse::<SocketAddr>() {
            Ok(parsed_addr) => {
                match TcpListener::bind(parsed_addr) {
                    Ok(listener) => {
                        self.private.listener = Some(listener);
                        println!(
                            "Listening on {}:{}",
                            Self::convert_c_string(self.receiver_ip).expect(
                                "Failed to convert receiver_ip from C string to Rust string"
                            ),
                            self.port
                        );
                    }
                    Err(e) => {
                        eprintln!("Failed to bind: {}", e);
                        self.private.listener = None; // Set listener to None on binding failure
                    }
                }
            }
            Err(e) => {
                eprintln!("Invalid address format: {}", e);
                self.private.listener = None; // Set listener to None on address parsing failure
            }
        }
    }

    pub fn accept_connection(&mut self) {
        if let Some(listener) = &self.private.listener {
            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    // Store the unencrypted TcpStream in accepted_stream
                    self.accepted_stream = Some(stream);
                    self.peer_address = Some(peer_addr);
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    // Handle the error as needed
                }
            }
        } else {
            // The listener is not available, handle the error condition
            eprintln!("Listener is not available");
        }
    }

    pub fn initialise_ssl(&mut self) {
        // Check if the accepted_stream is available
        if let Some(accepted_stream) = self.accepted_stream.take() {
            let tls_config = Arc::clone(&self.tls_config);

            // Create a new ServerConnection associated with the TLS configuration
            let server_connection = rustls::ServerConnection::new(tls_config)
                .expect("Failed to create ServerConnection");

            // Wrap the unencrypted TcpStream in rustls::StreamOwned to enable encryption
            let ssl_stream = rustls::StreamOwned::new(server_connection, accepted_stream);
            self.ssl_socket = Some(ssl_stream);
            println!("SSL socket initialized.");
        } else {
            eprintln!("No accepted stream available. Call accept_connection first.");
        }
    }

    pub fn do_handshake(&mut self) {
        if let Some(ssl_socket) = &mut self.ssl_socket {
            // Perform the TLS handshake
            match ssl_socket.get_mut().write_all(b"") {
                Ok(_) => println!("Handshake completed."),
                Err(err) => println!("Handshake failed: {:?}", err),
            }
        } else {
            println!("SSL socket not initialized.");
        }
    }

    pub fn receive_data(&mut self) -> String {
        if let Some(ssl_socket) = &mut self.ssl_socket {
            println!("Receiving data...");

            if self.bytes_read == 0 {
                self.buffer.clear();
            };

            self.bytes_read = match ssl_socket.read(&mut self.buffer) {
                Ok(bytes_read) => bytes_read,
                Err(err) => {
                    println!("Error: {:?}", err);
                    return String::new();
                }
            };

            if self.bytes_read == 0 {
                println!("Connection closed by peer");
                return String::new();
            }

            String::from_utf8_lossy(&self.buffer[..self.bytes_read]).to_string()
        } else {
            println!("SSL socket not initialized.");
            String::new()
        }
    }

    pub fn close_socket(&mut self) {
        println!("Closing socket...");

        if let Some(mut ssl_socket) = self.ssl_socket.take() {
            println!("Shutting down SSL socket...");
            let tcp_stream = ssl_socket.get_mut();
            // Shutdown the underlying TcpStream
            match tcp_stream.shutdown(std::net::Shutdown::Both) {
                Ok(_) => println!("Socket closed successfully."),
                Err(err) => println!("Failed to close socket: {:?}", err),
            }
        } else {
            println!("SSL socket not initialized or already closed.");
        }
    }

    #[no_mangle]
    pub extern "C" fn run(&mut self) -> *mut c_char {
        self.start_listening();
        self.accept_connection();
        self.initialise_ssl();
        self.do_handshake();
        let msg = self.receive_data();
        self.close_socket();

        // Convert the Rust String to a CString and give ownership to the caller
        let c_string = CString::new(msg).unwrap();
        c_string.into_raw()
    }
}

#[no_mangle]
pub extern "C" fn receiver_free(receiver: *mut Receiver) {
    unsafe {
        drop(Box::from_raw(receiver));
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // Perform any necessary cleanup here before the Receiver is deallocated
        // For example, close the listener and SSL socket
        if let Some(listener) = self.private.listener.take() {
            // Close the listener
            drop(listener);
        }

        if let Some(mut ssl_socket) = self.ssl_socket.take() {
            // Close the SSL socket
            let tcp_stream = ssl_socket.get_mut();
            let _ = tcp_stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn check_keys(certificate_data: *const c_char, private_key_data: *const c_char, header: String) {
    #[cfg(feature = "test-env")]
    {
        println!("{}", header);
        // Check that certificate_data and private_key_data are not empty
        let cert_cstr = unsafe { CStr::from_ptr(certificate_data) };
        let key_cstr = unsafe { CStr::from_ptr(private_key_data) };

        assert!(
            !cert_cstr.to_bytes().is_empty(),
            "certificate_data is empty"
        );
        assert!(!key_cstr.to_bytes().is_empty(), "private_key_data is empty");

        println!("certificate_data length: {}", cert_cstr.to_bytes().len());
        println!("private_key_data length: {}", key_cstr.to_bytes().len());
    }
}
