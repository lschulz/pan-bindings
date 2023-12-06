#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ops::Deref;
use std::ptr::null;
use std::rc::Rc;

trait FnClone: FnOnce(PanError) {
    fn clone_box(&self) -> Rc<dyn FnClone>;
}

impl<T> FnClone for T
where
    T: 'static + FnOnce(PanError) + Clone,
{
    fn clone_box(&self) -> Rc<dyn FnClone> {
        Rc::new(self.clone())
    }
}

// #[derive(Deref)]
// #[deref(forward)]
struct myRc(Rc<dyn FnClone>);

impl Clone for myRc {
    fn clone(&self) -> Self {
        myRc((**self).clone_box())
    }
}

impl Deref for myRc {
    type Target = <Rc<(dyn FnClone<Output = ()> + 'static)> as Deref>::Target;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt;
use std::future::*;
use std::io::{self, Bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::*;
//use std::rc::Rc;
use std::str;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
extern crate tokio;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};

//use dyn_clone::DynClone;
//extern crate dyn_clone;
//use dyn_clone::DynClone;

//mod bindings;
//use bindings::*;

#[derive(Debug, Clone, Copy)]
pub struct panError(pub u32);

impl Error for panError {}

impl fmt::Display for panError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "panError: {}", self.0)
    }
}

impl Default for Pan_GoHandle {
    fn default() -> Self {
        Self {
            handle: Pan_GoHandle_INVALID_HANDLE,
        }
    }
}

// impl Error for PanError {}

pub trait GoHandleOwner {
    // : Default
    // fn new() -> Self; // better derive Default ?!
    unsafe fn as_bool(&self) -> bool;
    unsafe fn is_valid(&self) -> bool;
    unsafe fn get_handle(&self) -> usize;
    unsafe fn release_handle(&mut self) -> usize;
    // GoHandle member h
}

use std::os::raw::*;

pub struct PathInterface {
    h: Pan_GoHandle,
}

impl PathInterface {
    fn new(handle: Pan_GoHandle) -> Self {
        PathInterface { h: handle }
    }
}

impl Default for PathInterface {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl GoHandleOwner for PathInterface {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub struct PathFingerprint {
    h: Pan_GoHandle,
}

impl PathFingerprint {
    fn new(handle: Pan_GoHandle) -> Self {
        PathFingerprint { h: handle }
    }
}

impl Default for PathFingerprint {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl GoHandleOwner for PathFingerprint {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub struct Path {
    h: Pan_GoHandle,
}

impl Path {
    pub fn new(handle: Pan_GoHandle) -> Self {
        Self { h: handle }
    }

    pub unsafe fn to_string(&self) -> String {
        let c_str = CStr::from_ptr(PanPathToString(self.get_handle()));
        c_str.to_string_lossy().into_owned()
    }

    pub unsafe fn get_fingerprint(&self) -> PathFingerprint {
        PathFingerprint::new(Pan_GoHandle::new1(
            PanPathGetFingerprint(self.get_handle()) as u64
        ))
    }

    pub unsafe fn contains_interface(&self, iface: &PathInterface) -> bool {
        PanPathContainsInterface(self.get_handle(), iface.get_handle()) != 0
    }
}

impl Default for Path {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl GoHandleOwner for Path {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub trait PathPolicy: GoHandleOwner {
    fn cb_filter(self: &mut Self, paths: *const usize, count: usize, user: usize) -> usize;
    /*
     using PathTag = std::uintptr_t;
    using Paths = std::vector<std::pair<Path, PathTag>>;
    virtual void filter(Paths& paths) = 0;
     */
}

pub trait PathSelector: GoHandleOwner {
    // Callbacks for Go
    fn cb_path(self: &mut Self, user: c_uint) -> c_uint;
    fn cb_initialize(
        self: &mut Self,
        local: c_uint,
        remote: c_uint,
        paths: *const c_uint,
        count: c_uint,
        user: c_uint,
    );
    fn cb_refresh(self: &mut Self, paths: *const c_uint, count: c_uint, user: c_uint);
    fn cb_path_down(self: &mut Self, pf: c_uint, pi: c_uint, user: c_uint);
    fn cb_close(self: &mut Self, user: c_uint);
    /*
        fn path(&self) -> Path;
        fn initialize(&self, local: udp::Endpoint, remote: udp::Endpoint, paths: &mut Vec<Path>);
        fn refresh(&self, paths: &mut Vec<Path>);
        fn path_down(&self, pf: PathFingerprint, pi: PathInterface);
        fn close(&self);
    */
}

pub trait ReplySelector: GoHandleOwner {
    // fn new() -> Self;
    // the c++ version has no self parameter. But rust apparently needs this
    // to allow for Box<dyn ReplySelector>  to compile
    fn cb_path(&mut self, remote: c_uint, user: c_uint) -> c_uint;
    fn cb_initialize(&mut self, local: c_uint, user: c_uint);
    fn cb_record(&mut self, remote: c_uint, path: c_uint, user: c_uint);
    fn cb_path_down(&mut self, pf: c_uint, pi: c_uint, user: c_uint);
    fn cb_close(&mut self, user: c_uint);
    /*
    fn path(&self, remote: udp::Endpoint) -> Path;
    fn initialize(&self, local: udp::Endpoint);
    fn record(&self, remote: udp::Endpoint, path: Path);
    fn path_down(&self, pf: PathFingerprint, pi: PathInterface);
    fn close(&self);
     */
}

//mod upd { // maybe unnecessary

pub struct Endpoint {
    h: Pan_GoHandle,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl Endpoint {
    pub fn new(handle: Pan_GoHandle) -> Endpoint {
        Self { h: handle }
    }

    pub unsafe fn to_string(&self) -> String {
        let c_string_ptr = PanUDPAddrToString(self.get_handle());

        let c_str = CStr::from_ptr(c_string_ptr);
        std::str::from_utf8_unchecked(c_str.to_bytes()).to_string()
    }

    pub unsafe fn get_ia(&self) -> u64 {
        let mut ia: u64 = 0;
        PanUDPAddrGetIA(self.get_handle(), &mut ia as *mut u64);
        ia
    }

    pub unsafe fn get_ip(&self) -> IpAddr {
        if PanUDPAddrIsIPv6(self.get_handle()) != 0 {
            let mut ipv6_bytes: [u8; 16] = [0; 16];
            PanUDPAddrGetIPv6(self.get_handle(), ipv6_bytes.as_mut_ptr());
            IpAddr::V6(Ipv6Addr::from(ipv6_bytes))
        } else {
            let mut ipv4_bytes: [u8; 4] = [0; 4];

            PanUDPAddrGetIPv4(self.get_handle(), ipv4_bytes.as_mut_ptr());
            IpAddr::V4(Ipv4Addr::from(ipv4_bytes))
        }
    }

    pub unsafe fn get_port(&self) -> u16 {
        PanUDPAddrGetPort(self.get_handle())
    }
}

impl GoHandleOwner for Endpoint {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

use std::error::Error;

pub unsafe fn resolve_udp_addr(address: &str) -> Result<Endpoint, Box<dyn Error>> {
    let mut h: Pan_GoHandle = Default::default();
    let err: PanError = PanResolveUDPAddr(
        address.as_ptr() as *const ::std::os::raw::c_char,
        h.resetAndGetAddressOf() as *mut PanUDPAddr,
    );

    if err == 0 {
        Ok(Endpoint::new(h))
    } else {
        Err(Box::new(panError(err)))
    }
}

//} mod udp

pub struct ListenSockAdapter {
    h: Pan_GoHandle,
}

impl ListenSockAdapter {
    pub fn new(handle: Pan_GoHandle) -> Self {
        Self { h: handle }
    }

    pub unsafe fn close(&mut self) {
        if self.is_valid() {
            let err = PanListenSockAdapterClose(self.get_handle());
            self.h.reset1();
        }
    }
}
impl Default for ListenSockAdapter {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl GoHandleOwner for ListenSockAdapter {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub struct ListenConn {
    h: Pan_GoHandle,
    selector: Option<Box<dyn ReplySelector>>,

    read_state: ReadState,

    async_read_timeout: std::os::raw::c_int, // milliseconds

    waker: Option<Waker>,
}

impl Default for ListenConn {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
            selector: None,
            waker: None,
            read_state: ReadState::Initial,
            async_read_timeout: 100, //ms
        }
    }
}

enum ReadState {
    Initial,
    WaitReading {
        // completion has not yet been called
        // buffer: Rc< RefCell< Vec<u8>>>,
        buffer: *mut Vec<u8>,
        bytes_read: *mut i32,
        //buffer: Rc<Box<&'a mut [u8]>>,
        from: *mut PanUDPAddr,
        path: *mut PanPath,
        //waker: Option<Waker>,
    },
    ReadyReading {
        //buffer: Rc< RefCell<Vec<u8>>>,
        buffer: *mut Vec<u8>,
        bytes_read: i32,
        //buffer: Rc<Box<&'a mut [u8]>>,
        from: PanUDPAddr,
        path: PanPath,
        //waker: Option<Waker>,
    },
    Error(panError),
}

pub struct ReadFuture {
    // waker: Option<Waker>,
    from: PanUDPAddr,
    path: PanPath,
    bytes: i32,
    conn: Arc<Mutex<ListenConn>>, //connection from which we read
}

impl ReadFuture {
    pub fn new(c: Arc<Mutex<ListenConn>>) -> ReadFuture {
        Self {
            conn: c.clone(),
            bytes: 0,
            from: 0,
            path:0,
        }
    }
}

impl Future for ReadFuture {
    type Output = Result<(i32, PanUDPAddr,PanPath), Box<dyn Error>>;

    fn poll(
        self: Pin<&mut ReadFuture>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(i32, PanUDPAddr,PanPath), Box<dyn Error>>> {
        // check what read state the connection is in
        // depending on this return Pending or the Ready result

        let mut locked_conn = self.conn.lock().unwrap();

        match locked_conn.read_state {
            ReadState::Initial => {
                debug!("future_poll: found initial");
                Poll::Pending
            }

            ReadState::Error(err) => {
                debug!("future_poll: found error");
                Poll::Ready(Err(Box::new(err.clone())))
            }

            ReadState::ReadyReading {
                buffer: _,
                from,
                path,
                bytes_read,
            } => {
                debug!("future_poll: found ready_reading");
                Poll::Ready(Ok((bytes_read, from,path)))
            }
            ReadState::WaitReading {
                buffer: _,
                from: _,
                path: _,
                bytes_read: _,
            } => {
                debug!("future_poll: found wait_reading");
                // store the waker in the listen conn
                // so the completion can wake us, once the result is available
                unsafe {
                    locked_conn.waker = Some(cx.waker().clone());
                }
                debug!("future set waker");

                Poll::Pending
            }
        }
    }
}

impl ListenConn {
    unsafe extern "C" fn read_completer(arc: *mut c_void, code: PanError) {
        let mut _self: Arc<Mutex<ListenConn>> =
            Arc::<Mutex<ListenConn>>::from_raw(std::mem::transmute(arc));
        debug!("completion_handler invoked with code: {}", code);
        match code {
            PAN_ERR_OK => {
              
                match _self.lock() {
                    Ok(ref mut c) => {
                        debug!("completer got the lock :)");
                        match &mut c.read_state {
                            ReadState::WaitReading {
                                bytes_read: br,
                                buffer: bu,
                                from: fr,
                                path: p,
                            } => {
                                debug!("completion_handler found state: wait_reading");
                                c.read_state = ReadState::ReadyReading {
                                    bytes_read: **br,
                                    buffer: bu.clone(),
                                    path: **p,
                                    from: **fr,
                                };
                            }
                            ReadState::Initial => {
                                debug!("completion_handler found unexpected state: Initial");
                            }
                            ReadState::Error(_) => {
                                debug!("completion_handler found unexpected state: ReadReady");
                            }
                            ReadState::ReadyReading { .. } => {
                                debug!("completion_handler found unexpected state: Ready");
                            }
                        };
                    }
                    Err(_) => {
                        panic!("completer cant get lock");
                    }
                }
            }
            PAN_ERR_DEADLINE => {
                (&mut _self.lock().unwrap()).read_state = ReadState::Error(panError(code));
            }
            PAN_ERR_FAILED => {
                (&mut _self.lock().unwrap()).read_state = ReadState::Error(panError(code));
            }
            _ => {}
        }
        debug!("completer finished code matching");

        // check if the future has been awaited already (polled)
        // if so, the waker has been stored, and we need to call it

        match _self.lock() {
            Ok(ref mut c) => match &mut c.waker {
                Some(ref mut w) => {
                    w.clone().wake();
                }
                None => {}
            },
            Err(e) => {
                panic!("completer cannot get lock on conn");
            }
        }

        debug!("completer finished ");
    }

    pub async fn async_read(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, Box<dyn Error>> {
      
      match  unsafe { ListenConn::async_read_impl(this, recv_buff).await }
      {
        Ok( (i32,_,_) ) =>
        {
            Ok(i32 )
        },
        Err(e) =>{ Err(e) }
      }

    }

    pub async fn async_read_from(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr), Box<dyn Error>> {
      
      match  unsafe { ListenConn::async_read_impl(this, recv_buff).await }
      {
        Ok( (i32,from,_) ) =>
        {
            Ok((i32,from ))
        },
        Err(e) =>{ Err(e) }
      }

    }

    pub async fn async_read_from_via(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr,PanPath), Box<dyn Error>> {
      
        unsafe { ListenConn::async_read_impl(this, recv_buff).await }
      
    }

    pub unsafe fn async_read_impl<'c, 'b, 'a>(
        this: Arc<Mutex<ListenConn>>,
        recv_buffer: &'b mut Vec<u8>, //  from: & mut PanUDPAddr,
    ) -> ReadFuture {
        let mut handle = 0;
        let mut read_tout = 0;
        
        let mut _read_future: ReadFuture;
        {
            let mut s = this.lock().unwrap();
            handle = s.get_handle();
            read_tout = s.async_read_timeout;
        }

        _read_future = ReadFuture::new(this.clone());

        let ffn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, PanError)> =
            Some(ListenConn::read_completer);

        let err: PanError = PanListenConnReadFromAsyncVia(
            handle,
            recv_buffer.as_mut_ptr() as *mut c_void,
            recv_buffer.len() as i32,
            &mut _read_future.from as *mut PanUDPAddr,
            &mut _read_future.path as *mut PanPath,
            &mut _read_future.bytes as *mut i32,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ListenConn>>::into_raw(this.clone()) as *mut c_void,
        );

        // check if the read was ready right away
        if err == PAN_ERR_OK {
            println!("Go returned OK");
            // the read already has completed successfully
            // and the waker wont be called, as the results are already available

            // return a ReadFuture that is instantly Ready when polled

            this.lock().unwrap().read_state = ReadState::ReadyReading {
                buffer: recv_buffer as *mut Vec<u8>,
                from: _read_future.from,
                path: _read_future.path,
                bytes_read: _read_future.bytes as i32,
            };
            _read_future
        } else if err == PAN_ERR_WOULDBLOCK {
            println!("Go returned wouldblock");
            /* return a ReadFuture that when polled:

            - is not instantly ready unless the completion_handler was called
             but returns Pending

            */

            this.lock().unwrap().read_state = ReadState::WaitReading {
                buffer: recv_buffer as *mut Vec<u8>,
                from: &mut _read_future.from as *mut PanUDPAddr,
                path: &mut _read_future.path as *mut PanPath,
                bytes_read: &mut _read_future.bytes as *mut i32,
            };
            debug!("main go the lock");
            _read_future
        } else {
            println!("Go returned FAILURE ");
            // there was a real error and we are screwed
            this.lock().unwrap().read_state = ReadState::Error(panError(err));
            _read_future
        }
    }
    /*
    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer).await
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data).await
    }*/

    pub unsafe fn set_deadline(&mut self, t: &std::time::Duration) {
        PanListenConnSetDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
    }

    pub unsafe fn set_read_deadline(&mut self, t: &std::time::Duration) {
        PanListenConnSetReadDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
    }

    pub unsafe fn set_write_deadline(&mut self, t: &std::time::Duration) {
        PanListenConnSetWriteDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
    }

    pub unsafe fn close(&mut self) {
        if self.is_valid() {
            PanListenConnClose(self.get_handle());
            self.h.reset1();
        }
    }

    pub unsafe fn listen(&mut self, local: &str) -> Result<(), Box<dyn Error>> {
        let err: PanError = PanListenUDP(
            local.as_ptr() as *const i8,
            if self.selector.is_some() {
                self.selector.as_ref().unwrap().get_handle()
            } else {
                Pan_GoHandle::default().get() as usize
            },
            self.h.resetAndGetAddressOf() as *mut usize,
        );

        if err == 0 {
            Ok(())
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn get_local_endpoint(&self) -> Endpoint {
        Endpoint::new(Pan_GoHandle::new1(
            PanListenConnLocalAddr(self.get_handle()) as u64,
        ))
    }

    pub unsafe fn read(self: &mut Self, buffer: &mut [u8]) -> Result<i32, Box<dyn Error>> {
        let mut h_from: Pan_GoHandle = Pan_GoHandle::default();
        let mut n: i32 = 0;
        let err = PanListenConnReadFrom(
            self.get_handle(),
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            h_from.resetAndGetAddressOf() as *mut PanUDPAddr,
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn readFrom(
        self: &mut Self,
        buffer: &mut [u8],
        from: &mut Endpoint,
    ) -> Result<i32, Box<dyn Error>> {
        let mut h_from: Pan_GoHandle = Pan_GoHandle::default();
        let mut n: i32 = 0;
        let err = PanListenConnReadFrom(
            self.get_handle(),
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            h_from.resetAndGetAddressOf() as *mut PanUDPAddr,
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            *from = Endpoint::new(h_from);
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    // maybe better return tuple (i32, from, path) instead of out parameters ?!
    pub unsafe fn readFromVia(
        self: &mut Self,
        buffer: &mut [u8],
        from: &mut Endpoint,
        path: &mut Path,
    ) -> Result<i32, Box<dyn Error>> {
        let mut h_from: Pan_GoHandle = Pan_GoHandle::default();
        let mut h_path: Pan_GoHandle = Pan_GoHandle::default();
        let mut n: i32 = 0;

        let err = PanListenConnReadFromVia(
            self.get_handle(),
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            h_from.resetAndGetAddressOf() as *mut PanUDPAddr,
            h_path.resetAndGetAddressOf() as *mut PanPath,
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            *from = Endpoint::new(h_from);
            *path = Path::new(h_path);
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn writeTo(
        self: &mut Self,
        buffer: &[u8],
        to: &Endpoint,
    ) -> Result<i32, Box<dyn Error>> {
        let mut n: i32 = 0;
        let err = PanListenConnWriteTo(
            self.get_handle(),
            buffer.as_ptr() as *const std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            to.get_handle(),
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn writeToVia(
        self: &mut Self,
        buffer: &[u8],
        to: &Endpoint,
        path: &Path,
    ) -> Result<i32, Box<dyn Error>> {
        let mut n: i32 = 0;
        let err = PanListenConnWriteToVia(
            self.get_handle(),
            buffer.as_ptr() as *const std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            to.get_handle(),
            path.get_handle(),
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn create_sock_adapter(
        &self,
        go_socket_path: &str,
        c_socket_path: &str,
    ) -> Result<ListenSockAdapter, Box<dyn Error>> {
        let mut handle: Pan_GoHandle = Default::default();
        let err: PanError = PanNewListenSockAdapter(
            self.get_handle(),
            go_socket_path.as_ptr() as *const i8,
            c_socket_path.as_ptr() as *const i8,
            handle.resetAndGetAddressOf() as *mut usize,
        );
        if err == 0 {
            Ok(ListenSockAdapter::new(handle))
        } else {
            Err(Box::new(panError(err)))
        }
    }
}

/*
impl Default for ListenConn {
    fn default() -> Self {
     unsafe{
        Self {
            h: Pan_GoHandle::default(),
            selector: Box::from_raw(std::ptr::null_mut() ),//  Box::<dyn ReplySelector>::new(Default::default()),
        }
    }
    }
} */

impl GoHandleOwner for ListenConn {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub struct ConnSockAdapter {
    h: Pan_GoHandle,
}

impl ConnSockAdapter {
    pub unsafe fn new(handle: Pan_GoHandle) -> ConnSockAdapter {
        Self { h: handle }
    }

    pub unsafe fn close(&mut self) {
        if self.is_valid() {
            PanConnSockAdapterClose(self.get_handle());
            self.h.reset1();
        }
    }
}

impl Default for ConnSockAdapter {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl GoHandleOwner for ConnSockAdapter {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

pub struct Conn {
    h: Pan_GoHandle,
    policy: Option<Box<dyn PathPolicy>>,
    selector: Option<Box<dyn PathSelector>>,
}

impl Conn {
    pub unsafe fn close(&mut self) {
        if self.is_valid() {
            PanConnClose(self.get_handle());
            self.h.reset1();
        }
    }

    pub unsafe fn get_local_endpoint(&self) -> Endpoint {
        Endpoint::new(Pan_GoHandle::new1(
            PanConnLocalAddr(self.get_handle()) as u64
        ))
    }

    pub unsafe fn get_remote_endpoint(&self) -> Endpoint {
        Endpoint::new(Pan_GoHandle::new1(
            PanConnRemoteAddr(self.get_handle()) as u64
        ))
    }

    pub unsafe fn dial(
        self: &mut Self,
        local: &str,
        remote: &Endpoint,
    ) -> Result<(), Box<dyn Error>> {
        let err = PanDialUDP(
            local.as_ptr() as *const i8,
            remote.get_handle(),
            if self.policy.is_some() {
                (self.policy.as_mut()).unwrap().get_handle()
            } else {
                PAN_INVALID_HANDLE as usize
            },
            if self.selector.is_some() {
                self.selector.as_mut().unwrap().get_handle()
            } else {
                PAN_INVALID_HANDLE as usize
            },
            self.h.resetAndGetAddressOf() as *mut PanConn,
        );

        if err == 0 {
            Ok(())
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn set_deadline(self: &mut Self, timeout: u32) {
        PanConnSetDeadline(self.get_handle(), timeout);
    }

    pub unsafe fn set_read_deadline(self: &mut Self, timeout: u32) {
        PanConnSetReadDeadline(self.get_handle(), timeout);
    }

    pub unsafe fn set_write_deadline(self: &mut Self, timeout: u32) {
        PanConnSetWriteDeadline(self.get_handle(), timeout);
    }

    pub unsafe fn write(self: &Self, buffer: &[u8]) -> Result<i32, Box<dyn Error>> {
        let mut n: i32 = 0;
        let err = PanConnWrite(
            self.get_handle(),
            buffer.as_ptr() as *const std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            Ok(n)
        } else {
            {
                return Err(Box::new(panError(err)));
            }
        }
    }

    pub unsafe fn writeVia(self: &Self, buffer: &[u8], path: &Path) -> Result<i32, Box<dyn Error>> {
        let mut n: i32 = 0;
        let err = PanConnWriteVia(
            self.get_handle(),
            buffer.as_ptr() as *const std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            path.get_handle(),
            &mut n as *mut std::os::raw::c_int,
        );

        if err == 0 {
            Ok(n)
        } else {
            {
                return Err(Box::new(panError(err)));
            }
        }
    }

    pub unsafe fn read(self: &Self, buffer: &mut [u8]) -> Result<i32, Box<dyn Error>> {
        let mut n: i32 = 0;
        let err = PanConnRead(
            self.get_handle(),
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            &mut n as *mut std::os::raw::c_int,
        );
        if err == 0 {
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn readVia(
        self: &Self,
        buffer: &mut [u8],
        path: &mut Path,
    ) -> Result<i32, Box<dyn Error>> {
        let mut h_path: Pan_GoHandle = Pan_GoHandle::default();
        let mut n: i32 = 0;
        let err = PanConnReadVia(
            self.get_handle(),
            buffer.as_mut_ptr() as *mut std::os::raw::c_void,
            buffer.len() as std::os::raw::c_int,
            h_path.resetAndGetAddressOf() as *mut PanPath,
            &mut n as *mut std::os::raw::c_int,
        );
        if err == 0 {
            *path = Path::new(h_path);
            Ok(n)
        } else {
            Err(Box::new(panError(err)))
        }
    }

    pub unsafe fn createSockAdaper(
        self: &mut Self,
        go_socket_path: &str,
        c_socket_path: &str,
    ) -> Result<ConnSockAdapter, Box<dyn Error>> {
        let mut handle: Pan_GoHandle = Pan_GoHandle::default();

        let err = PanNewConnSockAdapter(
            self.get_handle(),
            go_socket_path.as_ptr() as *const i8,
            c_socket_path.as_ptr() as *const i8,
            handle.resetAndGetAddressOf() as *mut PanConnSockAdapter,
        );

        if err == 0 {
            Ok(ConnSockAdapter::new(handle))
        } else {
            Err(Box::new(panError(err)))
        }
    }
}

impl Default for Conn {
    fn default() -> Self {
        unsafe {
            Self {
                h: Pan_GoHandle::default(),
                selector: None,
                policy: None,
            }
        }
    }
}

impl GoHandleOwner for Conn {
    unsafe fn as_bool(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn is_valid(&self) -> bool {
        self.h.isValid()
    }
    unsafe fn get_handle(&self) -> usize {
        let retn: usize = self.h.get() as usize;
        retn
    }
    unsafe fn release_handle(&mut self) -> usize {
        let prt: usize = self.h.release() as usize;
        prt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    /*
    #[test]
    fn round_trip_compression_decompression() {
        unsafe {
            let input = include_str!("../futurama-quotes.txt").as_bytes();
            let mut compressed_output: Vec<u8> = vec![0; input.len()];
            let mut decompressed_output: Vec<u8> = vec![0; input.len()];

            // Construct a compression stream.
            let mut stream: bz_stream = mem::zeroed();
            let result = BZ2_bzCompressInit(&mut stream as *mut _,
                                            1,   // 1 x 100000 block size
                                            4,   // verbosity (4 = most verbose)
                                            0);  // default work factor
            match result {
                r if r == (BZ_CONFIG_ERROR as _) => panic!("BZ_CONFIG_ERROR"),
                r if r == (BZ_PARAM_ERROR as _) => panic!("BZ_PARAM_ERROR"),
                r if r == (BZ_MEM_ERROR as _) => panic!("BZ_MEM_ERROR"),
                r if r == (BZ_OK as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            // Compress `input` into `compressed_output`.
            stream.next_in = input.as_ptr() as *mut _;
            stream.avail_in = input.len() as _;
            stream.next_out = compressed_output.as_mut_ptr() as *mut _;
            stream.avail_out = compressed_output.len() as _;
            let result = BZ2_bzCompress(&mut stream as *mut _, BZ_FINISH as _);
            match result {
                r if r == (BZ_RUN_OK as _) => panic!("BZ_RUN_OK"),
                r if r == (BZ_FLUSH_OK as _) => panic!("BZ_FLUSH_OK"),
                r if r == (BZ_FINISH_OK as _) => panic!("BZ_FINISH_OK"),
                r if r == (BZ_SEQUENCE_ERROR as _) => panic!("BZ_SEQUENCE_ERROR"),
                r if r == (BZ_STREAM_END as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            // Finish the compression stream.
            let result = BZ2_bzCompressEnd(&mut stream as *mut _);
            match result {
                r if r == (BZ_PARAM_ERROR as _) => panic!("BZ_PARAM_ERROR"),
                r if r == (BZ_OK as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            // Construct a decompression stream.
            let mut stream: bz_stream = mem::zeroed();
            let result = BZ2_bzDecompressInit(&mut stream as *mut _,
                                              4,   // verbosity (4 = most verbose)
                                              0);  // default small factor
            match result {
                r if r == (BZ_CONFIG_ERROR as _) => panic!("BZ_CONFIG_ERROR"),
                r if r == (BZ_PARAM_ERROR as _) => panic!("BZ_PARAM_ERROR"),
                r if r == (BZ_MEM_ERROR as _) => panic!("BZ_MEM_ERROR"),
                r if r == (BZ_OK as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            // Decompress `compressed_output` into `decompressed_output`.
            stream.next_in = compressed_output.as_ptr() as *mut _;
            stream.avail_in = compressed_output.len() as _;
            stream.next_out = decompressed_output.as_mut_ptr() as *mut _;
            stream.avail_out = decompressed_output.len() as _;
            let result = BZ2_bzDecompress(&mut stream as *mut _);
            match result {
                r if r == (BZ_PARAM_ERROR as _) => panic!("BZ_PARAM_ERROR"),
                r if r == (BZ_DATA_ERROR as _) => panic!("BZ_DATA_ERROR"),
                r if r == (BZ_DATA_ERROR_MAGIC as _) => panic!("BZ_DATA_ERROR"),
                r if r == (BZ_MEM_ERROR as _) => panic!("BZ_MEM_ERROR"),
                r if r == (BZ_OK as _) => panic!("BZ_OK"),
                r if r == (BZ_STREAM_END as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            // Close the decompression stream.
            let result = BZ2_bzDecompressEnd(&mut stream as *mut _);
            match result {
                r if r == (BZ_PARAM_ERROR as _) => panic!("BZ_PARAM_ERROR"),
                r if r == (BZ_OK as _) => {},
                r => panic!("Unknown return value = {}", r),
            }

            assert_eq!(input, &decompressed_output[..]);
        }
    }
    */
}
