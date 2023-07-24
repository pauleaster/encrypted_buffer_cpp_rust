use receiver_cpp::Receiver;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::{CStr, CString};

    #[test]
    fn test_receiver_new_run_free() {
        // Define the test inputs
        let cert_env_var = CString::new("EB_RECEIVER_CERTIFICATE_DATA").unwrap();
        let key_env_var = CString::new("EB_RECEIVER_PRIVATE_KEY_DATA").unwrap();
        let ip = CString::new("127.0.0.1").unwrap();
        let port: u16 = 4321;
    
        // Get Rust str references from the CStrings
        let cert_env_var_str = cert_env_var.to_str().expect("Failed to convert CString to str");
        let key_env_var_str = key_env_var.to_str().expect("Failed to convert CString to str");
    
        // Read the environment variables required by the function
        let cert_data = match std::env::var(cert_env_var_str) {
            Ok(value) => value,
            Err(_) => panic!("EB_RECEIVER_CERTIFICATE_DATA not set"),
        };
        let key_data = match std::env::var(key_env_var_str) {
            Ok(value) => value,
            Err(_) => panic!("EB_RECEIVER_PRIVATE_KEY_DATA not set"),
        };
    
        // Print the length of certificate and key data for debugging
        println!(
            "Length of {}: {}",
            cert_env_var_str, cert_data.len()
        );
        println!("Length of {}: {}", key_env_var_str, key_data.len());

        // Call receiver_new() with the test inputs
        let receiver = unsafe {
            Receiver::receiver_new(
                cert_env_var.as_ptr(),
                key_env_var.as_ptr(),
                ip.as_ptr(),
                port,
            )
        };

        // Check that the returned receiver is not null
        assert!(!receiver.is_null());

        // Convert raw pointer back to a Rust mutable reference
        let receiver_ref = unsafe { &mut *receiver };

        // Call run() with the created receiver
        let result = unsafe { receiver_ref.run() };

        // Convert the returned raw pointer back to a Rust CString
        let cstr = unsafe { CString::from_raw(result) };

        // Check the contents of the returned string. This will depend on the expected behavior of the run() function.
        // For this example, we're just checking that the string is not empty.
        assert!(!cstr.to_str().unwrap().is_empty());

        // Call receiver_free() with the created receiver
        unsafe { receiver_cpp::receiver_free(receiver) };

        // It is challenging to write assertions for receiver_free() because it does not return a value,
        // and once it has been called, the receiver pointer is dangling, and any attempt to dereference it is undefined behavior.
        // However, a successful test run without a crash or memory leak can be considered as a passing test for receiver_free().
    }
}
