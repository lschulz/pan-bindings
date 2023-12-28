extern crate clap;
// extern crate pan_bindings;
// use pan_bindings::*;

use pan::*;

use clap::{Arg, Parser};
use std::error::Error;

use std::io;
use std::io::*;
use std::result::Result;
use time::macros;
use std::sync::*;

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
        let c= Arc::new(Mutex::new(ScionSocket::default()));
      
        Self {
            // initialize in an invalid state
            conn: c,
        }
    }

    pub fn listen(&mut self, local_addr: &String) -> Result<(), Box<dyn Error>> {
        unsafe {
            match self.conn.lock().unwrap().bind(&local_addr) {
                Err(e) => Err( Box::new(e)),
                Ok(_) => Ok(()),
            }
        }
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        debug!("server starts");
        unsafe {
            println!(
                "server listening at: {}",
                self.conn.lock().unwrap().get_local_addr().to_string()
            );
        }
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        // let mut recv_buff: [u8; 4096] = [0; 4096];
        let mut recv_buff: Vec<u8> = vec![0; 4096];
        let mut path = Path::default();
        let mut from = Endpoint::default();
        let mut cnt = 0;
        loop {
            let mut res: Result<(i32, PanUDPAddr, PanPath), panError> =
                Err(panError(PAN_ERR_OK));

            unsafe {
                let read_block = async {
                    if args.show_path {
                        res = ScionSocket::async_read_from_via(self.conn.clone(), &mut recv_buff)
                            .await;
                    } else {
                        match ScionSocket::async_read_from(
                            self.conn.clone(),
                            &mut recv_buff, /*, &mut from*/
                        )
                        .await
                        {
                            Ok((i, f)) => {
                                res = Ok((i, f, 0));
                            }
                            Err(e) => {
                                println!("error: {}", e.to_string());
                                res = Err(e);
                            }
                        }
                    }
                };

                rt.block_on(read_block);

                match res {
                    Ok((read, from_addr, path_from)) => {
                        cnt+=1;
                        debug!("async-read successfull ");
                        from = Endpoint::new(Pan_GoHandle::new1(from_addr as u64));

                        println!("\n{} received {} bytes from {}",cnt, read, from.to_string());
                        if args.show_path {
                            // print path
                            debug!("path_from: {}", path_from);
                            path = Path::new(Pan_GoHandle::new1(path_from as u64));
                            println!("path: {}", path.to_string());
                        }

                        //  print message
                        io::stdout()
                            .write(&recv_buff[0..read as usize])
                            .expect("Invalid write");

                        // write back message

                        let mut n: Result<(), Box<dyn Error>> = Err(Box::new(panError(0)));

                        let write_block = async {
                            let nn = ScionSocket::async_write_to(
                                self.conn.clone(),
                                &recv_buff[0..read as usize],
                                from.get_handle(),
                            )
                            .await?;
                            Ok::<(), Box<dyn Error>>(nn)
                        };
                        rt.block_on(write_block);
                    }
                    Err(e) => {
                        if e.0 == panError(PAN_ERR_DEADLINE).0 {
                            // client is done
                            println!("timeout");
                            return Ok(());
                        } else {
                            println!("async_read failed");
                            return Err(Box::new(e));
                        }
                    }
                }
            }
        }
    }

    pub fn run(args: Arguments) {
        debug!("server runs");
        let mut server = Server::new();

        server
            .listen(&args.local)
            .expect("server cannot listen on local address");

        server.start(&args).expect("server failed");
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

        self.conn.lock().unwrap().bind( &args.local);
              self.remote =   resolve_udp_addr( &args.remote.as_ref().unwrap() )?; 
              Ok(())
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            debug!("client starts");
            let mut rt = tokio::runtime::Runtime::new().unwrap();
            let mut path = Path::default();
            //   let mut recv_buff: [u8; 4096] = [0; 4096];
            let mut recv_buff: Vec<u8> = vec![0; 4096];

            for cnt in 0..args.count {
                let write_block = async {
                    ScionSocket::async_write_to(
                        self.conn.clone(),
                        &args.message.as_ref().unwrap().as_bytes(),
                        self.remote.get_handle() as PanUDPAddr
                    )
                    .await
                };
                rt.block_on(write_block);

            //    self.conn.lock().unwrap().set_deadline(1000);

                let mut res: Result<i32, panError> = Err(panError(PAN_ERR_FAILED));

                let read_block = async {
                    if args.show_path {
                        match ScionSocket::async_read_from_via(self.conn.clone(), &mut recv_buff).await {
                            Ok((i, _,p)) => {
                                res = Ok(i);
                                path = Path::new(Pan_GoHandle::new1(p as u64));
                            }
                            Err(e) => {
                                res = Err(e);
                            }
                        }
                    } else {
                        res = ScionSocket::async_read(self.conn.clone(), &mut recv_buff).await;
                    }
                };
                rt.block_on(read_block);

                match res {
                    Ok(read) => {
                        println!("{} received {} bytes",cnt, read);
                        if path.is_valid() {
                            println!("path: {}", path.to_string());
                        }
                    }
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            Ok(())
        }
    }

    pub fn run(args: Arguments) {
        debug!("client runs");
        let mut client = Client::new();

        client
            .connect(&args)
            .expect("client cannot dial remote address");

        client.start(&args).expect("client failed");
    }
}

fn main() {
    //SimpleLogger::new().with_local_timestamps().init(LevelFilter::Debug, Config::default()); // is simple_logger
   // SimpleLogger::init(LevelFilter::Debug, Config::default() );
   //////// SimpleLogger::init(LevelFilter::Debug, ConfigBuilder::new().set_time_format_custom(format_description!("[second].[subsecond]")).set_time_level(LevelFilter::Debug).build() );
   env_logger::init();
    // ConfigBuilder::new().set_time_format_rfc2822().build()
    // set_time_format_rfc3339() set_time_format_custom(format_description!("[hour]:[minute]:[second].[subsecond]")
    

    let args = Arguments::parse();

    if !args.remote.is_some() {
        Server::run(args);
    } else {
        Client::run(args);
    }
}
