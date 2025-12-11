use std::{collections::HashMap, fs::File, io::BufReader, sync::Arc};

use once_cell::sync::Lazy;
use rustls::{PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::{net::{TcpListener, TcpStream}, sync::Mutex};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use futures::{io::Take, SinkExt, StreamExt};
use tokio_tungstenite::accept_async;


type WsStream = tokio_tungstenite::WebSocketStream<TlsStream<TcpStream>>;
pub static QUERY_LIST: Lazy<std::sync::Mutex<Vec<(String,String,String)>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));
pub static WAITING_LIST: Lazy<std::sync::Mutex<Vec<(String,String,String,WsStream)>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));
pub async fn insert_stream(id:String,streamid:String,session_key:String ,stream:WsStream){
    let mut list = WAITING_LIST.lock().unwrap();
    list.push((id,streamid,session_key,stream));
}
pub async fn insert_query(id:String,streamid:String,key:String){
    let mut list = QUERY_LIST.lock().unwrap();
    list.push((id,streamid,key));
}
pub async fn handle_session_key(session_key:String,stream:WsStream) -> bool{
    let requester_info = {
        let list = QUERY_LIST.lock().unwrap();
        match list.iter().find(|(_, _, k)| k == &session_key) {
            Some(info) => (info.0.clone(), info.1.clone(), info.2.clone()),
            None => {
                drop(stream);
                return false;
            } , 
        }
    };
    let maybe_partner = {
        let mut list = WAITING_LIST.lock().unwrap();

        if let Some(index) = list.iter().position(|(_, _, k, _)| k == &session_key) {
            Some(list.remove(index)) 
        } else {
            None
        }
    };
    if let Some((_id, _resp, _key, partner_stream)) = maybe_partner {
        relay(stream, partner_stream).await;
        return true;
    }
    insert_stream(
        requester_info.0,
        requester_info.1,
        requester_info.2,
        stream,
    )
    .await;
    return true;
}


pub fn load_certs_tokio(cert_path: &str, key_path: &str) -> Result<tokio_rustls::rustls::ServerConfig, String> {
    let cert_file = &mut BufReader::new(File::open(cert_path).map_err(|e| e.to_string())?);
    let key_file = &mut BufReader::new(File::open(key_path).map_err(|e| e.to_string())?);

    let cert_chain = certs(cert_file)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(rustls::Certificate)
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

async fn relay(
    ws1: WsStream,
    ws2: WsStream,
) -> anyhow::Result<()> {

    let (mut sink1, mut stream1) = ws1.split();
    let (mut sink2, mut stream2) = ws2.split();
    let c1_to_c2 = async {
        while let Some(msg) = stream1.next().await {
            let msg = msg?;
            
            if msg.is_close() {
                sink2.send(msg).await?;
                break;
            }
            sink2.send(msg).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    let c2_to_c1 = async {
        while let Some(msg) = stream2.next().await {
            let msg = msg?;
            if msg.is_close() {
                sink1.send(msg).await?;
                break;
            }
            sink1.send(msg).await?;
        }

        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(c1_to_c2, c2_to_c1)?;

    println!("Relay closed");
    Ok(())
}

pub async fn streamingloop(cert_path: String,key_path: String,ws_addr: String) {
    let tls_config = load_certs_tokio(cert_path.as_str(), key_path.as_str())
        .expect("Failed to load SSL certificates");
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = match TcpListener::bind(ws_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            println!("TcpListener for the WSSTREAMS Couldnt be configured {:?}\n \n socket streams will not work commone is that the port is alread used if thats the case you can chose an other port in the source code",err);
            return;
        },
    };
    loop {
        let (stream1, _) = match listener.accept().await{
            Ok(d) => d,
            Err(_) => continue,
        };
        let tls_stream1 = match tls_acceptor.accept(stream1).await{
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let mut ws1 = match accept_async(tls_stream1).await{
            Ok(stream) => stream,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            if let Some(msg ) = ws1.next().await{
                let msg = match msg {
                    Ok(val) => val,
                    Err(e) => {
                        eprintln!("Error receiving message: {:?}", e); // REM
                        return;
                    }
                };
                let msgst: String = msg.to_string();
                if msgst.len() != 32{
                    println!("INVALID SESSION KEY");
                    return ;
                }
                let _ = handle_session_key(msgst, ws1).await;             
            }

        });
    }

}