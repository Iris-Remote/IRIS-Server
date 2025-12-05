use std::{fs::File, io::BufReader};

use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

pub fn load_certs(cert_path: &str, key_path: &str) -> Result<ServerConfig, String> {
    let cert_file = &mut BufReader::new(File::open(cert_path).map_err(|e| e.to_string())?);
    let key_file = &mut BufReader::new(File::open(key_path).map_err(|e| e.to_string())?);

    let cert_chain = certs(cert_file)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(Certificate)
        .collect();
    
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        return Err("Could not locate PKCS 8 private keys.".to_string());
    }

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .map_err(|e| e.to_string())?;
    
    Ok(config)
}