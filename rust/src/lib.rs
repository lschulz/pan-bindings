#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ops::Deref;
use std::ptr::null;
use std::rc::Rc;

use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt;
use std::future::*;
use std::io::{self, Bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::*;
use std::str;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
extern crate tokio;
use log::*;
use tokio::io::{AsyncRead, AsyncReadExt};

//extern crate typenum;
//use typenum::Same;

// Define a trait for checking type equality
//trait IsSameType<T: Sized>: Same<T> {}

// Implement the trait for cases where types are the same
//impl<T: Sized> IsSameType<T> for T {}

trait IsSameType<T> {
    const IS_SAME_TYPE: bool;
}

impl IsSameType<ListenConn> for ListenConn {
    const IS_SAME_TYPE: bool = true;
}

impl IsSameType<Conn> for ListenConn {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<ListenConn> for Conn {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<Conn> for Conn {
    const IS_SAME_TYPE: bool = true;
}

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

// todo: make this a proc_macro
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

    mtx_read: Arc<Mutex<ReadState>>,
    mtx_write: Arc<Mutex<WriteState>>,

    async_read_timeout: std::os::raw::c_int,  // milliseconds
    async_write_timeout: std::os::raw::c_int, // milliseconds
}

impl Connection for ListenConn {

    fn get_rstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<ReadState>> {
        s.lock().unwrap().mtx_read.clone()
    }

    fn get_wstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<WriteState>> {
        s.lock().unwrap().mtx_write.clone()
    }

    fn rstate(&mut self) -> Arc<Mutex<ReadState>> {
        self.mtx_read.clone()
    }

    fn wstate(&mut self) -> Arc<Mutex<WriteState>> {
        self.mtx_write.clone()
    }

    fn get_async_read_timeout(&mut self) -> &mut std::os::raw::c_int {
        &mut self.async_read_timeout
    }
    fn get_async_write_timeout(&mut self) -> &mut std::os::raw::c_int {
        &mut self.async_write_timeout
    }
}

impl Default for ListenConn {
    fn default() -> Self {
        let rstate = ReadState::Initial; // Assuming ReadState has an Initial variant
        let wstate = WriteState::Initial; // Assuming WriteState has an Initial variant

        let mtx_r = Arc::new(Mutex::new(rstate));
        let mtx_w = Arc::new(Mutex::new(wstate));

        Self {
            h: Pan_GoHandle::default(),
            selector: None,
            mtx_read: mtx_r,
            mtx_write: mtx_w,
            async_read_timeout: 100,  //ms
            async_write_timeout: 100, //ms
        }
    }
}

enum WriteState {
    Initial,
    Error(panError),
    WaitWrite {
        bytes_written: *mut i32,
        waker: Option<Waker>,
    },
    ReadyWriting {
        bytes_written: i32,
    },
}

pub struct WriteFuture {
    bytes_written: Box<i32>,       // heap allocate, so that address is pinned
    state: Arc<Mutex<WriteState>>, //connection to which we write
}

impl WriteFuture {
    pub fn new(c: Arc<Mutex<WriteState>>) -> WriteFuture {
        Self {
            state: c.clone(),
            bytes_written: Box::new(0),
        }
    }
}

impl Future for WriteFuture {
    type Output = Result<i32, Box<dyn Error>>;

    fn poll(
        self: Pin<&mut WriteFuture>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<i32, Box<dyn Error>>> {
        match &mut *self.state.clone().lock().unwrap() {
            WriteState::Initial => {
                debug!("future_poll: found initial");
                Poll::Pending
            }

            WriteState::Error(err) => {
                debug!("future_poll: found error");
                Poll::Ready(Err(Box::new(err.clone())))
            }

            WriteState::ReadyWriting { bytes_written } => {
                debug!("future_poll: found ready_reading");
                Poll::Ready(Ok(*bytes_written))
            }
            WriteState::WaitWrite {
                bytes_written: _,
                waker: ref mut w,
            } => {
                debug!("future_poll: found wait_reading");
                // store the waker in the listen conn
                // so the completion can wake us, once the result is available
                unsafe {
                    *w = Some(cx.waker().clone());
                }
                debug!("future set waker");

                Poll::Pending
            }
        }
    }
}

enum ReadState {
    Initial,
    WaitReading {
        // completion has not yet been called
        buffer: *mut Vec<u8>,
        bytes_read:*mut i32,
        from: *mut PanUDPAddr,
        path: *mut PanPath,

        waker: Option<Waker>,
    },
    ReadyReading {
        buffer: *mut Vec<u8>,
        bytes_read: i32,
        from: PanUDPAddr,
        path: PanPath,
        //waker: Option<Waker>,
    },
    Error(panError),
}

pub struct ReadFuture {
    
    from: Box< PanUDPAddr>,
    path: Box<PanPath>,
    bytes: Box<i32>,
    state: Arc<Mutex<ReadState>>, //connection from which we read
}

impl ReadFuture {
    pub fn new(c: Arc<Mutex<ReadState>>) -> ReadFuture {
        Self {
            state: c.clone(),
            bytes: Box::new(0),
            from: Box::new(0),
            path: Box::new(0),
        }
    }
}

trait Connection: GoHandleOwner {
    /*fn get_read_state_locked(&mut self) ->Arc<Mutex<ReadState>>;
    fn get_write_state_locked(&mut self ) -> Arc<Mutex<WriteState>>;*/

    fn get_rstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<ReadState>>;
    fn get_wstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<WriteState>>;

    /*   fn get_read_state(&mut self) -> &mut ReadState;
    fn get_write_state(&mut self) -> &mut WriteState;
    */

    fn rstate(&mut self) -> Arc<Mutex<ReadState>>;
    fn wstate(&mut self) -> Arc<Mutex<WriteState>>;

    fn get_async_read_timeout(&mut self) -> &mut std::os::raw::c_int; // milliseconds
    fn get_async_write_timeout(&mut self) -> &mut std::os::raw::c_int; // milliseconds
}

impl Future for ReadFuture {
    type Output = Result<(i32, PanUDPAddr, PanPath), Box<dyn Error>>;

    fn poll(
        self: Pin<&mut ReadFuture>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(i32, PanUDPAddr, PanPath), Box<dyn Error>>> {
        // check what read state the connection is in
        // depending on this return Pending or the Ready result

        let mut ss =&  *self.state.clone();
        let mut s = ss.lock().unwrap();
        match  *s {
            ReadState::Initial => {
                warn!("read future_poll: found initial");
                Poll::Pending
            }

            ReadState::Error(err) => {
                warn!("read future_poll: found error");
                *s = ReadState::Initial;

                Poll::Ready(Err(Box::new(err.clone())))
            }

            ReadState::ReadyReading {
                buffer: _,
                from,
                path,
                bytes_read,
            } => {
                debug!("future_poll: found ready_reading");
                *s = ReadState::Initial; // end this read cycle

                Poll::Ready(Ok((bytes_read, from, path)))
            }
            ReadState::WaitReading {
                buffer: _,
                from: _,
                path: _,
                waker: ref mut w,
                bytes_read: _,
            } => {
                debug!("future_poll: found wait_reading");
                // store the waker in the listen conn
                // so the completion can wake us, once the result is available
                
                *w = Some(cx.waker().clone());
                
                debug!("future set read waker");

                Poll::Pending
            }
        }
    }
}

unsafe extern "C" fn read_completer(arc: *mut c_void, code: PanError) {
    let mut _self: Arc<Mutex<ReadState>> =
        Arc::<Mutex<ReadState>>::from_raw(std::mem::transmute(arc));
    debug!("read handler invoked with code: {}", code);
    match code {
        PAN_ERR_OK => {
            match _self.lock() {
                Ok(mut c) => {
                    // let mut s = _self.lock().unwrap();
                    //  match & mut *s {
                    match &mut *c {
                        ReadState::WaitReading {
                            bytes_read: br,
                            buffer: bu,
                            from: fr,
                            path: p,
                            waker: w,
                        } => {
                            debug!("read handler found state: wait_reading");

                            match w {
                                Some(ww) => {
                                    ww.clone().wake();
                                }
                                None => {
                                    debug!("completer found no waker");
                                }
                            }
                            *c = ReadState::ReadyReading {
                                bytes_read: **br,
                                buffer: bu.clone(),
                                path: **p,
                                from: **fr,
                            };
                        }
                        ReadState::Initial => {
                            debug!("read_handler found unexpected state: Initial");
                            //  return ; // Dont call the waker
                            // this happens when the completer gets to lock the listen conn,
                            // before the main thread could transit the read state to WaitReading
                            // In this case the future has to be polled again
                            // this could be avoided if the Go functions were given another callback function pointer
                            // 'OnSuspend' which would be called, right before the go method returns WOULDBLOCK
                            // This callback would prepare the listen conn's state for the completion handler to run
                            // i.e. transit from ReadState::Initial to ReadState::WaitRead
                        }
                        ReadState::Error(_) => {
                            debug!("read_handler found unexpected state: ReadReady");
                        }
                        ReadState::ReadyReading { .. } => {
                            debug!("read_handler found unexpected state: Ready");
                        }
                    };
                }
                Err(_) => {
                    panic!("read handler cant get lock");
                }
            }
        }
        //  PAN_ERR_DEADLINE => {
        _ => {
            match _self.lock() {
                Ok(mut c) => {
                    // let mut s = _self.lock().unwrap();
                    //  match & mut *s {
                    match &mut *c {
                        ReadState::WaitReading {
                            bytes_read: br,
                            buffer: bu,
                            from: fr,
                            path: p,
                            waker: w,
                        } => {
                            let mut www = w.clone();
                             // make a copy before we change the state, the reference points to
                            *c = ReadState::Error(panError(code));
                            match www {
                                None => {
                                    debug!("read completer found no waker");
                                }
                                Some(wwww) => {
                                    wwww.wake();
                                }
                            }
                        }
                        ReadState::Initial => {
                            debug!("read_handler found unexpected state: Initial");
                        }
                        ReadState::Error(_) => {
                            debug!("read_handler found unexpected state: ReadReady");
                        }
                        ReadState::ReadyReading { .. } => {
                            debug!("read_handler found unexpected state: Ready");
                        }
                    }
                }
                Err(_) => {}
            }
        } /*   PAN_ERR_FAILED => {
              *(_self.lock().unwrap()) = ReadState::Error(panError(code));
          }
          _ => {}*/
    }
    debug!("read handler finished code matching");

    // check if the future has been awaited already (polled)
    // if so, the waker has been stored, and we need to call it

    debug!("read handler done ");
}

unsafe extern "C" fn write_completer(arc: *mut c_void, code: PanError) {
    let mut _self: Arc<Mutex<WriteState>> =
        Arc::<Mutex<WriteState>>::from_raw(std::mem::transmute(arc));
    debug!(" write_handler invoked with code: {}", code);
    match code {
        PAN_ERR_OK => {
            match _self.lock() {
                Ok(mut c) => {
                    debug!("write handler got the lock :)");

                    match &mut *c {
                        WriteState::WaitWrite {
                            bytes_written: br,
                            waker: w,
                        } => {
                            debug!("write_handler found state: wait_reading");
                            let ww = w.clone();

                            *c = WriteState::ReadyWriting {
                                bytes_written: **br,
                            };
                            // check if the future has been awaited already (polled)
                            // if so, the waker has been stored, and we need to call it
                            match ww {
                                Some(www) => {
                                    www.clone().wake();
                                }
                                None => {
                                    debug!("completer found no waker");
                                }
                            }
                        }
                        WriteState::Initial => {
                            debug!("write_handler found unexpected state: Initial");
                            // return; // dont call the waker
                        }
                        WriteState::Error(_) => {
                            debug!("write handler found unexpected state: ReadReady");
                        }
                        WriteState::ReadyWriting { .. } => {
                            debug!("write_handler found unexpected state: Ready");
                        }
                    };
                }
                Err(_) => {
                    panic!("write handler cant get lock");
                }
            }
        }
        _ => {
            match _self.lock() {
                Ok(mut c) => {
                    debug!("write handler got the lock :)");

                    match &mut *c {
                        WriteState::WaitWrite {
                            bytes_written: br,
                            waker: w,
                        } => {
                            debug!("write_handler found state: wait_reading");
                            let ww = w.clone();

                            *c = WriteState::Error(panError(code));

                            match ww {
                                Some(www) => {
                                    www.clone().wake();
                                }
                                None => {
                                    debug!("completer found no waker");
                                }
                            }
                        }
                        WriteState::Initial => {
                            debug!("write_handler found unexpected state: Initial");
                            // return; // dont call the waker
                        }
                        WriteState::Error(_) => {
                            debug!("write handler found unexpected state: ReadReady");
                        }
                        WriteState::ReadyWriting { .. } => {
                            debug!("write_handler found unexpected state: Ready");
                        }
                    };
                }
                Err(_) => {
                    panic!("write handler cant get lock");
                }
            }
        }
    }
    debug!(" write handler finished code matching");

    debug!("write handler done ");
}

// maybe add the timeout as a parameter here (now its a member of the listen-conn)
unsafe fn async_write_some_impl<C>(
    this: Arc<Mutex<C>>,
    send_buff: &[u8],
    to: PanUDPAddr,
    via: Option<PanPath>,
) -> WriteFuture
where
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
{
    let mut handle = 0;
    let mut write_tout = 0;

    let mut _write_future: WriteFuture;
    {
        let mut s = this.lock().unwrap();
        handle = s.get_handle();
        write_tout = *s.get_async_write_timeout();
    }

    _write_future = WriteFuture::new(C::get_wstate(this.clone()).clone());

    let mut llck = C::get_wstate(this.clone());
    let mut lck = llck.lock().unwrap(); // prevent the completer from running ahead

    let ffn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, PanError)> =
        Some(write_completer);
    let mut err: PanError = PAN_ERR_FAILED;
    debug!("initiate write operation");
    if <C as IsSameType<ListenConn>>::IS_SAME_TYPE {
        if via.is_none() {
            err = PanListenConnWriteToAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                to,
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone()) as *mut c_void,
            );
        } else {
            err = PanListenConnWriteToViaAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                to,
                via.unwrap(),
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone()) as *mut c_void,
            );
        }
    } else if <C as IsSameType<Conn>>::IS_SAME_TYPE {
        if via.is_none() {
            err = PanConnWriteAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone()) as *mut c_void,
            );
        } else {
            err = PanConnWriteViaAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                via.unwrap(),
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this.clone()).clone()) as *mut c_void,
            );
        }
    }

    // check if the write was ready right away
    if err == PAN_ERR_OK {
        debug!("Go write completed immediately");
        // the write already has completed successfully
        // and the waker wont be called, as the results are already available

        // return a WriteFuture that is instantly Ready when polled

        *lck = WriteState::ReadyWriting {
            bytes_written: *_write_future.bytes_written as i32,
        };
        _write_future
    } else if err == PAN_ERR_WOULDBLOCK {
        debug!("Go write returned WOULDBLOCK");
        /* return a WriteFuture that when polled:

        - is not instantly ready unless the completion_handler was called
         but returns Pending

        */

        
        *lck= WriteState::WaitWrite {
            bytes_written: &mut *_write_future.bytes_written as *mut i32,
            waker: None,
        };
        debug!("main got the lock");
        _write_future
    } else {
        debug!("Go write returned FAILURE ");
        // there was a real error and we are screwed
        
        *lck = WriteState::Error(panError(err));
        _write_future
    }
}

async fn async_write_impl<C>(
    this: Arc<Mutex<C>>,
    send_buff: &[u8],
    to: PanUDPAddr,
    via: Option<PanPath>,
) -> Result<(), Box<dyn Error>>
where
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
{
    let bytes_to_send: i32 = send_buff.len() as i32;
    let mut bytes_written: i32 = 0;

    while bytes_to_send > bytes_written {
        bytes_written += unsafe {
            async_write_some_impl::<C>(
                this.clone(),
                &send_buff[bytes_written as usize..(bytes_to_send - bytes_written) as usize],
                to,
                via,
            )
        }
        .await?
    }
    Ok(())
}

// actuall async_read_some_impl
unsafe fn async_read_impl<'b, C>(
    this: Arc<Mutex<C>>,
    recv_buffer: &'b mut Vec<u8>, //  from: & mut PanUDPAddr,
) -> ReadFuture
where
    C: Connection,
    C: IsSameType<ListenConn>,
    C: IsSameType<Conn>,
{
    let mut handle = 0;
    let mut read_tout = 0;

    let mut _read_future: ReadFuture;
    {
        let mut s = this.lock().unwrap();
        handle = s.get_handle();
        read_tout = *s.get_async_read_timeout();
    }

    _read_future = ReadFuture::new(C::get_rstate(this.clone()));

    let mut llck = C::get_rstate(this.clone());
    let mut lck = llck.lock().unwrap();  // prevent completer from running ahead

    let ffn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, PanError)> =
        Some(read_completer);

    let mut p = Box::into_raw( _read_future.path) as *mut PanPath;
    let mut b = Box::into_raw( _read_future.bytes) as *mut i32;
    let mut f = Box::into_raw( _read_future.from) as *mut PanUDPAddr;


    debug!("initiate async_read operation ");
    let mut err: PanError = PAN_ERR_FAILED;
    if <C as IsSameType<ListenConn>>::IS_SAME_TYPE {
        err = PanListenConnReadFromAsyncVia(
            handle,
            recv_buffer.as_mut_ptr() as *mut c_void,
            recv_buffer.len() as i32,
            f,
            p,
            b,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ReadState>>::into_raw(C::get_rstate(this.clone())) as *mut c_void,
        );
    } else if <C as IsSameType<Conn>>::IS_SAME_TYPE {
        err = PanConnReadViaAsync(
            handle,
            recv_buffer.as_mut_ptr() as *mut c_void,
            recv_buffer.len() as i32,
            p,
            b,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ReadState>>::into_raw(C::get_rstate(this.clone())) as *mut c_void,
        );
    }

    _read_future.path = Box::from_raw(p);
    _read_future.bytes = Box::from_raw(b);
    _read_future.from = Box::from_raw(f);

    // check if the read was ready right away
    if err == PAN_ERR_OK {
        debug!("Go read completed immediately");
        // the read already has completed successfully
        // and the waker wont be called, as the results are already available

        // return a ReadFuture that is instantly Ready when polled
     
        *lck = ReadState::ReadyReading {
            buffer: recv_buffer as *mut Vec<u8>,
            from: *_read_future.from,
            path: *_read_future.path,
            bytes_read: *_read_future.bytes as i32,
        };
        _read_future
    } else if err == PAN_ERR_WOULDBLOCK {
        debug!("Go read wouldblock");
        /* return a ReadFuture that when polled:

        - is not instantly ready unless the completion_handler was called
         but returns Pending

        */

        
        *lck = ReadState::WaitReading {
            buffer: recv_buffer as *mut Vec<u8>,
            from: f,
            path: p,
            bytes_read: b,
            waker: None,
        };
        debug!("main go the lock");
        _read_future
    } else {
        debug!("Go read returned FAILURE ");
        // there was a real error and we are screwed
    
        *lck = ReadState::Error(panError(err));
        _read_future
    }
}

impl ListenConn {
    pub async fn async_write_some_to(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe { async_write_some_impl::<ListenConn>(this, send_buff, to, None).await }
    }

    pub async fn async_write_to(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<ListenConn>(this, send_buff, to, None).await
    }

    pub async fn async_write_to_via(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &[u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<ListenConn>(this, send_buff, to, Some(via)).await
    }

    pub async fn async_write_some_to_via(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &Vec<u8>,
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe { async_write_some_impl::<ListenConn>(this, send_buff, to, Some(via)).await }
    }

    // actually async_read_some
    pub async fn async_read(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, Box<dyn Error>> {
        match unsafe { async_read_impl::<ListenConn>(this, recv_buff).await } {
            Ok((i32, _, _)) => Ok(i32),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from
    pub async fn async_read_from(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr), Box<dyn Error>> {
        match unsafe { async_read_impl::<ListenConn>(this, recv_buff).await } {
            Ok((i32, from, _)) => Ok((i32, from)),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from_via
    pub async fn async_read_from_via(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr, PanPath), Box<dyn Error>> {
        unsafe { async_read_impl::<ListenConn>(this, recv_buff).await }
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

   mtx_read: Arc<Mutex<ReadState>>,
   mtx_write: Arc<Mutex<WriteState>>,

    async_read_timeout: std::os::raw::c_int,  // milliseconds
    async_write_timeout: std::os::raw::c_int, // milliseconds

}

impl Connection for Conn {
  

    fn get_async_read_timeout(&mut self) -> &mut std::os::raw::c_int {
        &mut self.async_read_timeout
    }
    fn get_async_write_timeout(&mut self) -> &mut std::os::raw::c_int {
        &mut self.async_write_timeout
    }

    fn get_rstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<ReadState>> {
        s.lock().unwrap().mtx_read.clone()
    }

    fn get_wstate(s: Arc<Mutex<Self>>) -> Arc<Mutex<WriteState>> {
        s.lock().unwrap().mtx_write.clone()
    }

    fn rstate(&mut self) -> Arc<Mutex<ReadState>> {
        self.mtx_read.clone()
    }

    fn wstate(&mut self) -> Arc<Mutex<WriteState>> {
        self.mtx_write.clone()
    }
}

impl Conn {
    pub async fn async_write_some(
        this: Arc<Mutex<Conn>>,
        send_buff: &[u8],
    ) -> Result<i32, Box<dyn Error>> {
        unsafe { async_write_some_impl::<Conn>(this, send_buff, 0, None).await }
    }

    pub async fn async_write(
        this: Arc<Mutex<Conn>>,
        send_buff: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<Conn>(this, send_buff, 0, None).await
    }

    pub async fn async_write_via(
        this: Arc<Mutex<Conn>>,
        send_buff: &[u8],
        via: PanPath,
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<Conn>(this, send_buff, 0, Some(via)).await
    }

    pub async fn async_write_some_via(
        this: Arc<Mutex<Conn>>,
        send_buff: &Vec<u8>,
        via: PanPath,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe { async_write_some_impl::<Conn>(this, send_buff, 0, Some(via)).await }
    }

    // actually async_read_some
    pub async fn async_read(
        this: Arc<Mutex<Conn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, Box<dyn Error>> {
        match unsafe { async_read_impl::<Conn>(this, recv_buff).await } {
            Ok((i32, _, _)) => Ok(i32),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_via
    pub async fn async_read_via(
        this: Arc<Mutex<Conn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanPath), Box<dyn Error>> {
        match unsafe { async_read_impl::<Conn>(this, recv_buff).await } {
            Ok((i, _, p)) => Ok((i, p)),
            Err(e) => Err(e),
        }
    }

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
                mtx_read: Arc::new(Mutex::new(ReadState::Initial)),
                mtx_write: Arc::new( Mutex::new(WriteState::Initial) ),
                async_read_timeout: 100,  //ms
                async_write_timeout: 100, //ms
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
