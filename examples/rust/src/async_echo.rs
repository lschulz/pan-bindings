extern crate clap;
extern crate pan_bindings;

use pan_bindings::*;

use clap::{Arg, Parser};
use std::error::Error;

use std::io;
use std::io::*;
use std::result::Result;

use std::sync::*;

#[macro_use]
extern crate log;
extern crate simplelog;

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
    conn: Arc<Mutex<ListenConn>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            conn: Arc::new(Mutex::new(ListenConn::default())),
        }
    }

    pub fn listen(&mut self, local_addr: &String) -> Result<(), Box<dyn Error>> {
        unsafe {
            match self.conn.lock().unwrap().listen(&local_addr) {
                Err(e) => Err(e),
                Ok(_) => Ok(()),
            }
        }
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            println!(
                "server listening at: {}",
                self.conn.lock().unwrap().get_local_endpoint().to_string()
            );
        }
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        // let mut recv_buff: [u8; 4096] = [0; 4096];
        let mut recv_buff: Vec<u8> = vec![0; 4096];
        let mut path = Path::default();
        let mut from = Endpoint::default();

        loop {
            let mut res: Result<(i32, PanUDPAddr, PanPath), Box<dyn Error>> =
                Err(Box::new(panError(PAN_ERR_OK)));

            unsafe {
                let read_block = async {
                    if args.show_path {
                        res = ListenConn::async_read_from_via(self.conn.clone(), &mut recv_buff)
                            .await;
                    } else {
                        match ListenConn::async_read_from(
                            self.conn.clone(),
                            &mut recv_buff, /*, &mut from*/
                        )
                        .await
                        {
                            Ok((i, f)) => {
                                res = Ok((i, f, 0));
                            }
                            Err(e) => {
                                println!("error: {}", e.description());
                                res = Err(e);
                            }
                        }
                    }
                };

                rt.block_on(read_block);

                match res {
                    Ok((read, from_addr, path_from)) => {
                        debug!("async-read successfull ");
                        from = Endpoint::new(Pan_GoHandle::new1(from_addr as u64));

                        println!("received {} bytes from {}", read, from.to_string());
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
                            let nn = ListenConn::async_write_to(
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
                        if e.downcast_ref::<panError>().unwrap().0 == panError(PAN_ERR_DEADLINE).0 {
                            // client is done
                            debug!("timeout");
                            return Ok(());
                        } else {
                            debug!("async_read failed");
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    pub fn run(args: Arguments) {
        let mut server = Server::new();

        server
            .listen(&args.local)
            .expect("server cannot listen on local address");

        server.start(&args).expect("server failed");
    }
}

struct Client {
    conn: Arc<Mutex<Conn>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            conn: Arc::new(Mutex::new(Conn::default())),
        }
    }

    pub fn connect(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            let remote_addr = resolve_udp_addr(&args.remote.as_ref().unwrap());

            let addr = match remote_addr {
                Err(e) => {
                    println!("resolve remote address failed");
                    return Err(e);
                }
                Ok(add) => add,
            };

            self.conn.lock().unwrap().dial(
                &args.local, //if args.local.is_empty() {}else {},
                &addr,
            )
        }
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            let mut rt = tokio::runtime::Runtime::new().unwrap();
            let mut path = Path::default();
            //   let mut recv_buff: [u8; 4096] = [0; 4096];
            let mut recv_buff: Vec<u8> = vec![0; 4096];

            for _ in 0..args.count {
                let write_block = async {
                    Conn::async_write(
                        self.conn.clone(),
                        &args.message.as_ref().unwrap().as_bytes(),
                    )
                    .await
                };
                rt.block_on(write_block);

                self.conn.lock().unwrap().set_deadline(1000);

                let mut res: Result<i32, Box<dyn Error>> = Err(Box::new(panError(PAN_ERR_FAILED)));

                let read_block = async {
                    if args.show_path {
                        match Conn::async_read_via(self.conn.clone(), &mut recv_buff).await {
                            Ok((i, p)) => {
                                res = Ok(i);
                                path = Path::new(Pan_GoHandle::new1(p as u64));
                            }
                            Err(e) => {
                                res = Err(e);
                            }
                        }
                    } else {
                        res = Conn::async_read(self.conn.clone(), &mut recv_buff).await;
                    }
                };
                rt.block_on(read_block);

                match res {
                    Ok(read) => {
                        println!("received {} bytes", read);
                        if path.is_valid() {
                            println!("path: {}", path.to_string());
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Ok(())
        }
    }

    pub fn run(args: Arguments) {
        let mut client = Client::new();

        client
            .connect(&args)
            .expect("client cannot dial remote address");

        client.start(&args).expect("client failed");
    }
}

fn main() {
  //  SimpleLogger::init(LevelFilter::Debug, Config::default());

    let args = Arguments::parse();

    if !args.remote.is_some() {
        Server::run(args);
    } else {
        Client::run(args);
    }
}
