extern crate clap;
extern crate pan_bindings;

use pan_bindings::*;

use clap::{Arg, Parser};
use std::error::Error;

use std::io;
use std::io::*;
use std::result::Result;

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

#[derive(Default)]
struct Server {
    conn: ListenConn,
}

impl Server {
    pub fn listen(&mut self, local_addr: &String) -> Result<(), Box<dyn Error>> {
        unsafe {
            match self.conn.listen(&local_addr) {
                Err(e) => Err(e),
                Ok(_) => Ok(()),
            }
        }
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            println!(
                "server listening at: {}",
                self.conn.get_local_endpoint().to_string()
            );
        }

        let mut recv_buff: [u8; 1024] = [0; 1024];
        let mut path = Path::default();
        let mut from = Endpoint::default();

        loop {
            let mut res: Result<i32, Box<dyn Error>>;
            unsafe {
                if args.show_path {
                    res = self.conn.readFromVia(&mut recv_buff, &mut from, &mut path);
                } else {
                    res = self.conn.readFrom(&mut recv_buff, &mut from);
                }

                match res {
                    Ok(read) => {
                        println!("received {} bytes from {}", read, from.to_string());
                        if args.show_path {
                            // print path
                            println!("path: {}", path.to_string());
                        }

                        //  print message
                        io::stdout()
                            .write(&recv_buff[0..read as usize])
                            .expect("Invalid write");

                        // write back message

                        let mut written: usize = 0;
                        while read as usize > written {
                            let n = self
                                .conn
                                .writeTo(&recv_buff[written..read as usize - written], &from);

                            match n {
                                Ok(write) => {
                                    written += write as usize;
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.downcast_ref::<panError>().unwrap().0 == panError(PAN_ERR_DEADLINE).0 {
                            // client is done
                            return Ok(());
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }

    pub fn run(args: Arguments) {
        let mut server = Server::default();

        server
            .listen(&args.local)
            .expect("server cannot listen on local address");

        server.start(&args).expect("server failed");
    }
}

#[derive(Default)]
struct Client {
    conn: Conn,
}

impl Client {
    pub fn connect(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            let remote_addr = resolve_udp_addr(&args.remote.as_ref().unwrap());

            let addr = match remote_addr {
                Err(e) =>{ println!("resolve remote address failed"); return Err(Box::new(e)) },
                Ok(add) => add,
            };

            match self.conn.dial(
                Some(&args.local), //if args.local.is_empty() {}else {},
                &addr,
            ) {
                Err(e) =>{ println!("dial failed"); Err(e)},
                _ => Ok(()),
            }
        }
    }

    pub fn start(&mut self, args: &Arguments) -> Result<(), Box<dyn Error>> {
        unsafe {
            let mut path = Path::default();
            let mut recv_buff: [u8; 1024] = [0; 1024];

            for _ in 0..args.count {
                match self.conn.write(&args.message.as_ref().unwrap().as_bytes()) {
                    Ok(i32) => {
                        if i32 as usize != args.message.as_ref().unwrap().len() {
                            panic!("message truncated on write");
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }

                self.conn.set_deadline(1000);

                let mut res: Result<i32, Box<dyn Error>>;
                if args.show_path {
                    res = self.conn.readVia(&mut recv_buff, &mut path);
                } else {
                    res = self.conn.read(&mut recv_buff);
                }

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
        let mut client = Client::default();

        client
            .connect(&args)
            .expect("client cannot dial remote address");

        client.start(&args).expect("client failed");
    }
}

fn main() {
    let args = Arguments::parse();

    if !args.remote.is_some() {
        Server::run(args);
    } else {
        Client::run(args);
    }
}
