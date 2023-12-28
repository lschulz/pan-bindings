extern crate clap;
extern crate pan_bindings;

use pan_bindings::*;

use clap::{Arg, Parser};
use std::error::Error;
use tokio::runtime::Handle;

use std::io;
use std::io::*;
use std::result::Result;
use time::macros;
use std::sync::Arc;
use scionnet::SocketAddrScion;
use std::str::FromStr;

use std::sync::Mutex as  stdMutex;
// use clap::error::ErrorKind;
//use parking_lot::ReentrantMutex as rmtx;
//type netMutex<T> = rmtx<RefCell<T>>;

use futures::lock::Mutex;

#[macro_use]
extern crate log;
extern crate simplelog;
// use simple_logger::SimpleLogger;

use simplelog::*;

#[derive(Parser)]
struct Arguments {
    #[arg(short, long)]
    local: String,
    #[arg(short, long)]
    remote: Option<String>,
    #[arg(short, long, default_value_t = 3)]
    count: u32, // for clients: how often will message be send
    #[arg(short, long)]
    message: Option<String>, // only for clients
    #[arg(short, long, default_value_t = false)]
    show_path: bool,
}

struct Server {
    conn: Arc<Mutex<ScionSocket>>,
}

impl Server {
    pub fn new() -> Self {
        let mut s = ScionSocket::default();
        let c= Arc::new(Mutex::new(s));
        /*
        let cc = c.clone();
        //tokio::task::spawn_blocking( 
        //    ||async move{ cc.lock().await.create_sock_adapter().await; }         );
        // Handle::current().block_on( async move{ cc.lock().await.create_sock_adapter().await; } );
        
        //rt.block_on( async{ s.create_sock_adapter().await; } );
        futures::executor::block_on(
            // async move {
           //Handle::current().spawn(
           // async move {
            async move{ cc.lock().await.create_sock_adapter().await; }                
            //} //).await.unwrap();
        //    }
        
        );*/
      
        Self {
            // initialize in an invalid state
            conn: c,
        }
    }

    pub fn listen(&mut self, local_addr: &String) -> Result<(), Box<dyn Error>> {
        unsafe {
            futures::executor::block_on( 
                async{
                    let mut lck = self.conn.lock().await;
                    let mut res = lck.bind(&local_addr); 
                    if !res.is_ok()
                    {
                        panic!("failed to bind socket");
                    }
                    //futures::executor::block_on(
                        // async move {
                       //Handle::current().spawn(
                       // async move {
                        
                    let res2 =lck.create_sock_adapter().await;                
                    if !res2.is_ok() 
                    {
                        panic!("failed to create unix socket");
                    }
                        //} //).await.unwrap();
                    //    }
                })
        }
        Ok(())
    }

    pub async fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        debug!("server starts");
        unsafe {
            println!(
                "server listening at: {}",
                // self.conn.lock().unwrap().get_local_addr().to_string()
                //Handle::current().
                futures::executor::block_on( async{self.conn.lock().await.get_local_addr().to_string()} )
            );
        }
      
        // let mut recv_buff: [u8; 4096] = [0; 4096];
        let mut recv_buff: Vec<u8> = vec![0; 4096];        
        // let mut from = SocketAddrScion::default();
        let mut cnt = 0;
        loop {
           
            unsafe {
                let read_block = async {
                    
                        self.conn.lock().await.read_some_from(
                            &mut recv_buff, /*, &mut from*/
                        )
                        .await                     
                    
                };

                

                //match futures::executor::block_on(read_block)
                match read_block.await
                 {
                    Ok((read, from_addr)) => 
                    {
                        cnt+=1;
                        debug!("async-read successfull ");
                    

                        println!("\n{} received {} bytes from {}",cnt, read, from_addr.to_string());
                    
                        //  print message #![feature(ascii_char)] #![feature(ascii_char_variants)]  [ASciiChar].as_str()
                        io::stdout()
                           .write_all(&recv_buff[0..read as usize] )
                        //   .write(std::str::from_utf8_unchecked(&recv_buff[0..read as usize] ) )
                            .expect("Invalid write");
                        io::stdout().flush();

                        // write back message

                        // let mut n: Result<(), Box<dyn Error>> = Err(Box::new(panError(0)));

                        let write_block = async {
                            
                                self.conn.lock().await.write_to(
                                &recv_buff[0..read as usize],
                                &from_addr
                            )
                            .await;
                          
                        };
                        futures::executor::block_on(write_block);
                    }
                    Err(e) => {
                    
                            println!("async_read failed");
                            return Err(Box::new(e));
                    
                    }
                }
            }
        }
    }

    pub async fn run(args: Arguments) {
        debug!("server runs");
        let mut server = Server::new();

        server
            .listen(&args.local)
            .expect("server cannot listen on local address");

        server.start(&args).await.expect("server failed");
    }
}

struct Client {
    //remote: SocketAddrScion,
    remote: Endpoint,
    conn: Arc<Mutex<ScionSocket>>,
}

impl Client {
    pub fn new() -> Self {

       
        let c = Arc::new(Mutex::new(ScionSocket::default()));
        
        Self {
            remote: Endpoint::default(),
            conn: c,
        }
    }

    pub fn connect(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
       
       /* unsafe {
            let remote_addr = resolve_udp_addr(&args.remote.as_ref().unwrap());

            let addr = match remote_addr {
                Err(e) => {
                    println!("resolve remote address failed");
                    return Err(Box::new(e));
                }
                Ok(add) => add,
            };

            self.conn.lock().unwrap().dial(
                &args.local, //if args.local.is_empty() {}else {},
                &addr,
            )
        } */

        
        //Handle::current().
        futures::executor::block_on( async{
            let mut lck =  self.conn.lock().await;
           lck.bind(&args.local);
           lck.create_sock_adapter().await;

        });
              self.remote =   resolve_udp_addr( &args.remote.as_ref().unwrap() )?; 
              Ok(())
    }

    pub async fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            debug!("client starts");
            //let mut rt = tokio::runtime::Runtime::new().unwrap();
         
            //   let mut recv_buff: [u8; 4096] = [0; 4096];
            let mut recv_buff: Vec<u8> = vec![0; 4096];

            for cnt in 0..args.count {
                let write_block = async {
                    
                        self.conn.lock().await.write_to(
                        &args.message.as_ref().unwrap().as_bytes(),
                       &SocketAddrScion::from_str( &args.remote.as_ref().unwrap()).unwrap()
                    )
                    .await
                };
              //  futures::executor::block_on(write_block);
              write_block.await;

            //    self.conn.lock().unwrap().set_deadline(1000);

              

                let read_block = async {
               
                       self.conn.lock().await.read_some( &mut recv_buff).await
                    
                };
              
             //   match   futures::executor::block_on(read_block)
                match read_block.await
                 {
                    Ok(read) => {
                        println!("{} received {} bytes",cnt, read);
                        
                    }
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            Ok(())
        }
    }

    pub async fn run(args: Arguments) {
        debug!("client runs");
        let mut client = Client::new();

        client
            .connect(&args)
            .expect("client cannot dial remote address");

        client.start(&args).await.expect("client failed");
    }
}

#[tokio::main]
async fn main() {
    //SimpleLogger::new().with_local_timestamps().init(LevelFilter::Debug, Config::default()); // is simple_logger
   // SimpleLogger::init(LevelFilter::Debug, Config::default() );
   //////// SimpleLogger::init(LevelFilter::Debug, ConfigBuilder::new().set_time_format_custom(format_description!("[second].[subsecond]")).set_time_level(LevelFilter::Debug).build() );
   env_logger::init();
    // ConfigBuilder::new().set_time_format_rfc2822().build()
    // set_time_format_rfc3339() set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]")
    

    let args = Arguments::parse();
   // let mut rt = tokio::runtime::Runtime::new().unwrap();
    if !args.remote.is_some() {
        Server::run(args).await;
    } else {
        Client::run(args).await;
    }
}
