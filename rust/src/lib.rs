#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![feature(ptr_metadata)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use byteorder::LittleEndian;
use futures::future::{Future, TryFutureExt};
use std::any::Any;

use std::collections::hash_map;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt;
// use std::os::unix::net::UnixDatagram;
use async_std::os::unix::net::UnixDatagram;
use std::future::*;
use std::io::Cursor;
use std::io::{self, Bytes};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::pin::*;
use std::ptr::null;
use std::io::Write;
use std::ptr::*;
// use byteorder::{BigEndian} ;//, ByteOrder, ReadBytesExt, WriteBytesExt};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};

use std::rc::Rc;
use std::str;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
extern crate snet;
use snet::*;
extern crate tokio;
use async_recursion::async_recursion;
use log::*;
// use tokio::io::{AsyncRead, AsyncReadExt};

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg32;
// use  rand::rngs::StdRng;

mod bindings;
//pub use self::bindings::PanUDPAddr;

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

impl IsSameType<ScionSocket> for ListenConn {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<ListenConn> for Conn {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<Conn> for Conn {
    const IS_SAME_TYPE: bool = true;
}

impl IsSameType<ScionSocket> for Conn {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<ScionSocket> for ScionSocket {
    const IS_SAME_TYPE: bool = true;
}

impl IsSameType<ListenConn> for ScionSocket {
    const IS_SAME_TYPE: bool = false;
}

impl IsSameType<Conn> for ScionSocket {
    const IS_SAME_TYPE: bool = false;
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

impl PartialEq for PathFingerprint {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            PanPathFingerprintAreEqual(
                self.get_handle() as PanPathFingerprint,
                other.get_handle() as PanPathFingerprint,
            ) == 1
        }
    }
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

#[derive(Debug)]
pub struct Path {
    h: Pan_GoHandle,
}

impl Path {
    pub fn new(handle: Pan_GoHandle) -> Self {
        Self { h: handle }
    }

    pub fn to_string(&self) -> String {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Path ");
            }
            let c_str = CStr::from_ptr(PanPathToString(self.get_handle()));
            c_str.to_string_lossy().into_owned()
        }
    }

    pub fn get_fingerprint(&self) -> PathFingerprint {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Path ");
            }
            PathFingerprint::new(Pan_GoHandle::new1(
                PanPathGetFingerprint(self.get_handle()) as u64
            ))
        }
    }

    pub fn contains_interface(&self, iface: &PathInterface) -> bool {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Path ");
            }
            PanPathContainsInterface(self.get_handle(), iface.get_handle()) != 0
        }
    }
}

impl Default for Path {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
        }
    }
}

impl Clone for Path {
    fn clone(&self) -> Path {
        unsafe { Path::new(Pan_GoHandle_Duplicate(self.get_handle() as u64)) }
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

mod path_policy {

    use crate::{FstBestPolicy, PathPolicy};
    use std::borrow::BorrowMut;
    use std::ptr::*;
    use std::sync::Once;

    type meta_type = <dyn PathPolicy as Pointee>::Metadata;
    static mut STD_ONCE_META: Option<meta_type> = None;
    static INIT_META: Once = Once::new();

    fn meta<'a>() -> &'a meta_type {
        INIT_META.call_once(|| {
            // Since this access is inside a call_once, before any other accesses, it is safe
            unsafe {
                let nullptr: *mut dyn PathPolicy = std::ptr::null_mut::<FstBestPolicy>();
                *STD_ONCE_META.borrow_mut() = Some(std::ptr::metadata(nullptr));
            }
        });

        // As long as this function is the only place with access to the static variable,
        // giving out a read-only borrow here is safe because it is guaranteed no more mutable
        // references will exist at this point or in the future.
        unsafe { STD_ONCE_META.as_ref().unwrap() }
    }

    pub(crate) fn from_raw(user: usize) -> Box<dyn PathPolicy> {
        let back_to_thin_ptr: *mut () = user as *mut ();
        let reconstructed_fat_ptr: *mut dyn PathPolicy =
            std::ptr::from_raw_parts_mut::<dyn PathPolicy>(back_to_thin_ptr as *mut _, *meta());
        let mut bx: Box<dyn PathPolicy> = unsafe { Box::from_raw(reconstructed_fat_ptr) };
        bx
    }
}

type Paths = Vec<(Path, usize)>;

pub trait PathPolicy: GoHandleOwner + Send + fmt::Debug {
    unsafe extern "C" fn cb_filter(paths: *mut usize, count: usize, user: usize) -> usize
    where
        Self: Sized,
    {
        debug!("path-policy: cb_filter invoked ");
        let mut bx = path_policy::from_raw(user);

        let mut path_obj: Paths = Paths::new();
        path_obj.reserve(count);

        for i in 0..count {
            let ptr = *paths.add(i);
            // let handle = Pan_GoHandle_Duplicate( ptr as u64); // fails -> invalid GoHandle
            let mut handle = Pan_GoHandle::new1(ptr as u64);
            //  path_obj.push(  (Path::new(handle.duplicate() ),ptr as usize ) ); // segfaults
            path_obj.push((Path::new(handle), ptr as usize));
        }

        bx.filter(&mut path_obj);

        let new_cnt = path_obj.len();
        assert!(new_cnt <= count);
        for i in 0..new_cnt {
            *paths.add(i) = path_obj[i].1;
        }

        Box::into_raw(bx);
        new_cnt
    }

    /*
     using PathTag = std::uintptr_t;
    using Paths = std::vector<std::pair<Path, PathTag>>;
    virtual void filter(Paths& paths) = 0;
    */

    // #![feature(associated_type_defaults)]
    /*fn filter( &mut Paths );
    type PathTag = usize;
    type Paths = Vec<(Path,PathTag)>; */

    fn filter(&mut self, paths: &mut Paths);
}

// example policy that always selects the fst provided path
// regardless of its attributes
#[derive(Debug)]
pub struct FstBestPolicy {
    h: Pan_GoHandle,
}

impl Default for FstBestPolicy {
    fn default() -> Self {
        FstBestPolicy {
            h: Pan_GoHandle::default(),
        }
    }
}

unsafe impl Send for FstBestPolicy {}

impl FstBestPolicy {
    pub fn init(&mut self) {
        unsafe {
            let f: Option<unsafe extern "C" fn(*mut usize, usize, usize) -> usize> =
                Some(<FstBestPolicy as PathPolicy>::cb_filter);

            let this: *mut dyn PathPolicy = self as *mut FstBestPolicy;

            let thin_ptr: *mut () = this as *mut ();
            let user = thin_ptr as usize;

            let p = PanNewCPolicy(f, user);

            self.h.reset(p as u64);
        }
    }
}

impl GoHandleOwner for FstBestPolicy {
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

impl PathPolicy for FstBestPolicy {
    fn filter(&mut self, paths: &mut Paths) {
        debug!("path-policy: filter invoked");
        paths.truncate(1); // keep only the fst path
    }
}

mod path_selector {

    use crate::{DefaultSelector, PathSelector};
    use std::borrow::BorrowMut;
    use std::ptr::*;
    use std::sync::Once;

    type meta_type = <dyn PathSelector as Pointee>::Metadata;
    static mut STD_ONCE_META: Option<meta_type> = None;
    static INIT_META: Once = Once::new();

    fn meta<'a>() -> &'a meta_type {
        INIT_META.call_once(|| {
            // Since this access is inside a call_once, before any other accesses, it is safe
            unsafe {
                let nullptr: *mut dyn PathSelector = std::ptr::null_mut::<DefaultSelector>();
                *STD_ONCE_META.borrow_mut() = Some(std::ptr::metadata(nullptr));
            }
        });

        // As long as this function is the only place with access to the static variable,
        // giving out a read-only borrow here is safe because it is guaranteed no more mutable
        // references will exist at this point or in the future.
        unsafe { STD_ONCE_META.as_ref().unwrap() }
    }

    pub(crate) fn from_raw(user: usize) -> Box<dyn PathSelector> {
        let back_to_thin_ptr: *mut () = user as *mut ();
        let reconstructed_fat_ptr: *mut dyn PathSelector =
            std::ptr::from_raw_parts_mut::<dyn PathSelector>(back_to_thin_ptr as *mut _, *meta());
        let mut bx: Box<dyn PathSelector> = unsafe { Box::from_raw(reconstructed_fat_ptr) };
        bx
    }
}

pub trait PathSelector: GoHandleOwner + Send + fmt::Debug {
    // Callbacks for Go
    unsafe extern "C" fn cb_path(user: usize) -> PanPath
    where
        Self: Sized,
    {
        let mut bx = path_selector::from_raw(user);

        let res = bx.path().release_handle();
        Box::into_raw(bx);
        res
    }

    unsafe extern "C" fn cb_initialize(
        local: PanUDPAddr,
        remote: PanUDPAddr,
        paths: *mut PanPath,
        count: usize,
        user: usize,
    ) where
        Self: Sized,
    {
        let mut bx = path_selector::from_raw(user);

        let mut path_objs: Vec<Path> = Vec::<Path>::new();
        path_objs.reserve(count);
        for i in 0..count {
            path_objs.push(Path::new(Pan_GoHandle::new1(*paths.add(i) as u64)));
        }
        bx.initialize(
            &Endpoint::new(Pan_GoHandle::new1(local as u64)),
            &Endpoint::new(Pan_GoHandle::new1(remote as u64)),
            path_objs,
        );
        Box::into_raw(bx);
    }

    unsafe extern "C" fn cb_refresh(paths: *mut PanPath, count: usize, user: usize)
    where
        Self: Sized,
    {
        let mut bx = path_selector::from_raw(user);
        let mut path_objs: Vec<Path> = Vec::<Path>::new();
        path_objs.reserve(count);
        for i in 0..count {
            path_objs.push(Path::new(Pan_GoHandle::new1(*paths.add(i) as u64)));
        }
        bx.refresh(path_objs);

        Box::into_raw(bx);
    }

    unsafe extern "C" fn cb_path_down(pf: PanPathFingerprint, pi: PanPathInterface, user: usize)
    where
        Self: Sized,
    {
        let mut bx = path_selector::from_raw(user);

        bx.path_down(
            PathFingerprint::new(Pan_GoHandle::new1(pf as u64)),
            PathInterface::new(Pan_GoHandle::new1(pi as u64)),
        );

        Box::into_raw(bx);
    }

    unsafe extern "C" fn cb_close(user: usize)
    where
        Self: Sized,
    {
        let mut bx = path_selector::from_raw(user);
        bx.close();
        Box::into_raw(bx);
    }

    fn path(&mut self) -> Path;
    fn initialize(&mut self, local: &Endpoint, remote: &Endpoint, paths: Vec<Path>); // paths are moved into
    fn refresh(&mut self, paths: Vec<Path>); // paths are moved into
    fn path_down(&mut self, pf: PathFingerprint, pi: PathInterface);
    fn close(&mut self);
}

#[derive(Debug)]
pub struct DefaultSelector {
    h: Pan_GoHandle,
    paths: Vec<Path>,
    curr_path: usize,
}

impl Default for DefaultSelector {
    fn default() -> Self {
        Self {
            h: Pan_GoHandle::default(),
            paths: Vec::<Path>::new(),
            curr_path: 0,
        }
    }
}

impl DefaultSelector {
    pub fn init(&mut self) {
        let mut callbacks: PanSelectorCallbacks = PanSelectorCallbacks {
            path: Some(<DefaultSelector as PathSelector>::cb_path),
            initialize: Some(<DefaultSelector as PathSelector>::cb_initialize),
            refresh: Some(<DefaultSelector as PathSelector>::cb_refresh),
            pathDown: Some(<DefaultSelector as PathSelector>::cb_path_down),
            close: Some(<DefaultSelector as PathSelector>::cb_close),
        };

        let this: *mut dyn PathSelector = self as *mut DefaultSelector;

        let thin_ptr: *mut () = this as *mut ();
        let user = thin_ptr as usize;

        unsafe {
            self.h
                .reset(PanNewCSelector(&mut callbacks as *mut PanSelectorCallbacks, user) as u64);
        }
    }
}

unsafe impl Send for DefaultSelector {}

impl GoHandleOwner for DefaultSelector {
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

impl PathSelector for DefaultSelector {
    // better change signature to Option<Path> ?!
    fn path(&mut self) -> Path {
        debug!("path requested from path-selector");
        return self.paths[self.curr_path].clone();
        // unimplemented!()
    }
    fn initialize(&mut self, local: &Endpoint, remote: &Endpoint, paths: Vec<Path>) {
        debug!("default path-selector initialized");
        self.paths = paths;
        self.curr_path = 0;
    }

    fn refresh(&mut self, new_paths: Vec<Path>) {
        debug!("default path-selector refreshed");
        let curr_fp = self.paths[self.curr_path].get_fingerprint();

        for i in 0..new_paths.len() {
            if new_paths[i].get_fingerprint() == curr_fp {
                self.curr_path = i;
                break;
            }
        }
        self.paths = new_paths;
    }

    fn path_down(&mut self, pf: PathFingerprint, pi: PathInterface) {
        debug!("default path selector notified about path-down ");
        if !self.paths.is_empty() {
            let current = &self.paths[self.curr_path];
            if current.get_fingerprint() == pf || current.contains_interface(&pi) {
                self.curr_path = (self.curr_path + 1) % self.paths.len();
            }
        }
    }

    fn close(&mut self) {
        debug!("default path selector closed");
    }
}

mod reply_selector {

    use crate::{DefaultReplySelector, ReplySelector};
    use std::borrow::BorrowMut;
    use std::ptr::*;
    use std::sync::Once;

    type meta_type = <dyn ReplySelector as Pointee>::Metadata;
    static mut STD_ONCE_META: Option<meta_type> = None;
    static INIT_META: Once = Once::new();

    fn meta<'a>() -> &'a meta_type {
        INIT_META.call_once(|| {
            // Since this access is inside a call_once, before any other accesses, it is safe
            unsafe {
                let nullptr: *mut dyn ReplySelector = std::ptr::null_mut::<DefaultReplySelector>();
                *STD_ONCE_META.borrow_mut() = Some(std::ptr::metadata(nullptr));
            }
        });

        // As long as this function is the only place with access to the static variable,
        // giving out a read-only borrow here is safe because it is guaranteed no more mutable
        // references will exist at this point or in the future.
        unsafe { STD_ONCE_META.as_ref().unwrap() }
    }

    pub(crate) fn from_raw(user: usize) -> Box<dyn ReplySelector> {
        let back_to_thin_ptr: *mut () = user as *mut ();
        let reconstructed_fat_ptr: *mut dyn ReplySelector =
            std::ptr::from_raw_parts_mut::<dyn ReplySelector>(back_to_thin_ptr as *mut _, *meta());
        let mut bx: Box<dyn ReplySelector> = unsafe { Box::from_raw(reconstructed_fat_ptr) };
        bx
    }
}

pub trait ReplySelector: GoHandleOwner + Send + fmt::Debug {
    unsafe extern "C" fn cb_path(remote: PanUDPAddr, user: usize) -> usize
    where
        Self: Sized,
    {
        let mut bx = reply_selector::from_raw(user);

        let res = bx
            .path(Endpoint::new(Pan_GoHandle::new1(remote as u64)))
            .release_handle();
        Box::into_raw(bx);
        res
    }

    // unsafe extern "C" fn cb_initialize(local: PanUDPAddr, user: usize)
    unsafe extern "C" fn cb_initialize(local: u64, user: usize)
    where
        Self: Sized,
    {
        let mut bx = reply_selector::from_raw(user);

        let res = bx.initialize(Endpoint::new(Pan_GoHandle::new1(local as u64)));
        Box::into_raw(bx);
        res
    }

    unsafe extern "C" fn cb_record(remote: PanUDPAddr, path: PanPath, user: usize)
    where
        Self: Sized,
    {
        let mut bx = reply_selector::from_raw(user);

        let res = bx.record(
            Endpoint::new(Pan_GoHandle::new1(remote as u64)),
            Path::new(Pan_GoHandle::new1(path as u64)),
        );
        Box::into_raw(bx);
        res
    }

    unsafe extern "C" fn cb_path_down(pf: PanPathFingerprint, pi: PanPathInterface, user: usize)
    where
        Self: Sized,
    {
        let mut bx = reply_selector::from_raw(user);

        let res = bx.path_down(
            PathFingerprint::new(Pan_GoHandle::new1(pf as u64)),
            PathInterface::new(Pan_GoHandle::new1(pi as u64)),
        );
        Box::into_raw(bx);
        res
    }

    unsafe extern "C" fn cb_close(user: usize)
    where
        Self: Sized,
    {
        let mut bx = reply_selector::from_raw(user);

        let res = bx.close();
        Box::into_raw(bx);
        res
    }

    fn path(&mut self, remote: Endpoint) -> Path;
    fn initialize(&mut self, local: Endpoint);
    fn record(&mut self, remote: Endpoint, path: Path);
    fn path_down(&mut self, pf: PathFingerprint, pi: PathInterface);
    fn close(&mut self);
}

#[derive(Debug)]
pub struct DefaultReplySelector {
    h: Pan_GoHandle,
    remotes: HashMap<String, Path>,
}

impl Default for DefaultReplySelector {
    fn default() -> Self {
        Self {
            remotes: HashMap::default(),
            h: Pan_GoHandle::default(),
        }
    }
}

impl DefaultReplySelector {
    pub fn init(&mut self) {
        let mut callbacks: PanReplySelCallbacks = PanReplySelCallbacks {
            path: Some(<DefaultReplySelector as ReplySelector>::cb_path),
            initialize: Some(<DefaultReplySelector as ReplySelector>::cb_initialize),
            record: Some(<DefaultReplySelector as ReplySelector>::cb_record),
            pathDown: Some(<DefaultReplySelector as ReplySelector>::cb_path_down),
            close: Some(<DefaultReplySelector as ReplySelector>::cb_close),
        };

        let this: *mut dyn ReplySelector = self as *mut DefaultReplySelector;

        let thin_ptr: *mut () = this as *mut ();
        let user = thin_ptr as usize;

        unsafe {
            self.h.reset(
                PanNewCReplySelector(&mut callbacks as *mut PanReplySelCallbacks, user) as u64,
            );
        }
    }
}

unsafe impl Send for DefaultReplySelector {}

impl GoHandleOwner for DefaultReplySelector {
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

impl ReplySelector for DefaultReplySelector {
    // maybe change signature to: Option<Path>
    fn path(&mut self, remote: Endpoint) -> Path {
        debug!("default-reply-selector: path requested");
        (*self.remotes.get::<String>(&remote.to_string()).unwrap()).clone()
    }

    fn initialize(&mut self, local: Endpoint) {
        debug!("default-reply-selector: initialized");
    }

    fn record(&mut self, remote: Endpoint, path: Path) {
        debug!("default-reply-selector: recorded path");
        self.remotes.insert(remote.to_string(), path);
    }

    fn path_down(&mut self, pf: PathFingerprint, pi: PathInterface) {
        debug!("default-reply-selector: path_down");
    }

    fn close(&mut self) {
        debug!("default-reply-selector: closed");
    }
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

impl Into<snet::SocketAddr> for Endpoint {
    /* 19-ffaa:1:1094,127.0.0.1:37227 -> 37904-100a:aff1:300,127.0.0.1:37227
    fn into(self) -> snet::SocketAddr {
        snet::SocketAddr::SCION(
             SocketAddrScion::new1(
                ScionAddr::new1(self.get_isd(),
                 self.get_asn(),
                  self.get_ip().into()),
                   self.get_port()))
    }
    */

    fn into(self) -> snet::SocketAddr {
        unsafe {
            if !self.is_valid() {
                panic!("cannot convert invalid panEndpoint to SocketAddr ");
            }

            snet::SocketAddr::SCION(
                <snet::SocketAddrScion as FromStr>::from_str(&self.to_string()).unwrap(),
            )
        }
    }
}

impl From<snet::SocketAddrScion> for Endpoint {
    fn from(addr: snet::SocketAddrScion) -> Endpoint {
        <Self as FromStr>::from_str(&addr.to_string()).unwrap()
    }
}

impl From<snet::SocketAddr> for Endpoint {
    fn from(addr: snet::SocketAddr) -> Endpoint {
        <Self as FromStr>::from_str(&addr.to_string()).unwrap()
    }
}

impl FromStr for Endpoint {
    type Err = panError;
    fn from_str(s: &str) -> Result<Endpoint, Self::Err> {
        resolve_udp_addr(s)
    }
}

impl Endpoint {
    pub fn get_isd(&self) -> u16 {
        isd_from_ia(self.get_ia())
    }

    pub fn get_asn(&self) -> u64 {
        as_from_ia(self.get_ia())
    }

    pub fn new(handle: Pan_GoHandle) -> Endpoint {
        Self { h: handle }
    }

    pub fn new1(addr: &str) -> Endpoint {
        resolve_udp_addr(addr).unwrap()
    }

    pub fn to_string(&self) -> String {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Endpoint ");
            }
            let c_string_ptr = PanUDPAddrToString(self.get_handle());

            let c_str = CStr::from_ptr(c_string_ptr);
            std::str::from_utf8_unchecked(c_str.to_bytes()).to_string()
        }
    }

    pub fn get_ia(&self) -> u64 {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Endpoint ");
            }
            let mut ia: u64 = 0;
            PanUDPAddrGetIA(self.get_handle(), &mut ia as *mut u64);

            ia
        }
    }

    pub fn get_ip(&self) -> IpAddr {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Endpoint ");
            }
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
    }

    pub fn get_port(&self) -> u16 {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Endpoint ");
            }
            PanUDPAddrGetPort(self.get_handle())
        }
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

pub fn resolve_udp_addr(address: &str) -> Result<Endpoint, panError> {
    unsafe {
        let mut h: Pan_GoHandle = Default::default();
        let err: PanError = PanResolveUDPAddrN(
            address.as_ptr() as *const ::std::os::raw::c_char,
            address.len() as i32,
            h.resetAndGetAddressOf() as *mut PanUDPAddr,
        );

        if err == 0 {
            Ok(Endpoint::new(h))
        } else {
            Err(panError(err))
        }
    }
}

//} mod udp

#[derive(Debug)]
pub struct ListenSockAdapter {
    h: Pan_GoHandle,
}

impl ListenSockAdapter {
    pub fn new(handle: Pan_GoHandle) -> Self {
        Self { h: handle }
    }

    pub fn close(&mut self) {
        unsafe {
            if self.is_valid() {
                let err = PanListenSockAdapterClose(self.get_handle());
                self.h.reset1();
            }
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

#[derive(Debug)]
pub struct ScionSocket {
    h: Pan_GoHandle,
    adapter: Option<ListenSockAdapter>,
    unix_sock: Option<UnixDatagram>,

    mtx_read: Arc<Mutex<ReadState>>,
    mtx_write: Arc<Mutex<WriteState>>,

    async_read_timeout: std::os::raw::c_int,  // milliseconds
    async_write_timeout: std::os::raw::c_int, // milliseconds
}

impl GoHandleOwner for ScionSocket {
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

impl Connection for ScionSocket {
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

impl Default for ScionSocket {
    fn default() -> Self {
        let rstate = ReadState::Initial; // Assuming ReadState has an Initial variant
        let wstate = WriteState::Initial; // Assuming WriteState has an Initial variant

        let mtx_r = Arc::new(Mutex::new(rstate));
        let mtx_w = Arc::new(Mutex::new(wstate));

        let mut handle = unsafe { Pan_GoHandle::new1(PanNewScionSocket2() as u64) };
        unsafe {
            assert!(handle.isValid());
        }

        Self {
            h: handle,
            adapter: None,
            unix_sock: None,

            mtx_read: mtx_r,
            mtx_write: mtx_w,
            async_read_timeout: 100,  //ms
            async_write_timeout: 100, //ms
        }
    }
}


/* generates the IPC proxy header and writes it into the buffers fst 30 bytes */
pub fn make_proxy_header( buff: &mut[u8], remote: snet::SocketAddrScion ) 
{
    if buff.len() < 30 {
        panic!("not enough buffer space to write proxy header");
    }

    let mut w = io::Cursor::new(buff);
    w.write_u64::<BigEndian>(remote.ia());

    let addr_len: u32 = match (*remote.host()) {
        snet::IpAddr::V4(_) => 4,
        snet::IpAddr::V6(_)=>16
    };
    w.write_u32::<LittleEndian>( addr_len);

    match (*remote.host()) {
        snet::IpAddr::V4(ip) => {
            w.write_all(&ip.octets());
        },
        snet::IpAddr::V6(ip)=>{
            for &segment in &ip.segments() {
                w.write_u16::<BigEndian>(segment);
            }
        }
    }
    w.write_u16::<LittleEndian>(remote.port());

}

/* parses the IPC proxy header from the buffers fst 30 bytes */
pub fn parse_proxy_header(buff: &[u8]) -> io::Result<snet::SocketAddrScion> {

    if buff.len() < 30 {
        panic!("not enough buffer space to parse proxy header");
    }

    let mut rdr = Cursor::new(buff);
    let ia: u64 = rdr.read_u64::<BigEndian>()?;

    let addr_len: u32 = rdr.read_u32::<LittleEndian>()?;
    let mut host: IpAddr = Ipv4Addr::new(0, 0, 0, 0).into();

    match addr_len {
        4 => {
            let b0 = rdr.read_u8()?;
            let b1 = rdr.read_u8()?;
            let b2 = rdr.read_u8()?;
            let b3 = rdr.read_u8()?;
            host = Ipv4Addr::new(b0, b1, b2, b3).into();
        }
        16 => {          
            let mut seg = [0_u16; 8];

            for x in seg.iter_mut() {
                *x = rdr.read_u16::<BigEndian>()?;
            }

            host = Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            )
            .into();
        }
        _ => {
            unreachable!();
        }
    };
    let p: u16 = rdr.read_u16::<LittleEndian>()?;
    Ok(SocketAddrScion{addr: ScionAddr{ia: ia, host: host.into()},port: p})
}

// Reader/Writer interface using a Unix Domain Socket
// to call any of these methods 'create_sock_adapter()' has to have been called
// to initialize and connect the unix domain socket
impl ScionSocket {
    
    pub async fn write_some_to(&mut self, send_buff: &[u8],
         to: PanUDPAddr) -> io::Result<usize> {
        if self.unix_sock.is_none() {
            panic!("write_some_to requires initialized unix domain socket");
        }
        self.unix_sock.as_ref().unwrap().send(send_buff).await
    }

 /* // for this to be  possible, the path GoHandle had to be included as a field in the proxy header 
     pub async fn write_some_to_via(
        &mut self,
        send_buff: &Vec<u8>,
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<i32, panError> {
        if self.unix_sock.is_none() {
            panic!("write_some_to_via requires initialized unix domain socket");
        }
    }
*/

    pub async fn write_to(
        &mut self,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<(), Box<dyn Error>> {
    }

    pub async fn write_to_via(
        &mut self,
        send_buff: &[u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<(), Box<dyn Error>> {
    }

    pub fn write_to2<'a>(
        &mut self,
        send_buff: &'a [u8],
        to: &Endpoint,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + Sync + 'a>> {
    }

    pub fn write_to_via2<'a>(
        &mut self,
        send_buff: &'a [u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + 'a>> {
    }

    pub fn read2(&mut self, recv_buf: &mut [u8]) -> ReadFuture {}

    // actually read_some
    pub async fn read(&mut self, recv_buff: &mut Vec<u8>) -> Result<i32, panError> {}

    // actually async_read_some_from
    pub async fn read_from(
        &mut self,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr), panError> {
    }

    // actually async_read_some_from_via
    pub async fn read_from_via(
        &mut self,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr, PanPath), panError> {
    }
}

// Reader/Writer interface implemented with completion callbacks
impl ScionSocket {
    pub async fn async_write_some_to(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<ScionSocket>(this, send_buff, to, None).await }
    }

    pub async fn async_write_some_to_via(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &Vec<u8>,
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<ScionSocket>(this, send_buff, to, Some(via)).await }
    }

    pub async fn async_write_to(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<ScionSocket>(this, send_buff, to, None).await
    }

    pub async fn async_write_to_via(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &[u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<(), Box<dyn Error>> {
        async_write_impl::<ScionSocket>(this, send_buff, to, Some(via)).await
    }

    pub fn async_write_to2<'a>(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &'a [u8],
        to: &Endpoint,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + Sync + 'a>> {
        unsafe { async_write_impl2::<ScionSocket>(this, send_buff, to.get_handle(), None) }
    }

    pub fn async_write_to_via2<'a>(
        this: Arc<Mutex<ScionSocket>>,
        send_buff: &'a [u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + 'a>> {
        async_write_impl2::<ScionSocket>(this, send_buff, to, Some(via))
    }

    pub fn async_read2(this: Arc<Mutex<ScionSocket>>, recv_buf: &mut [u8]) -> ReadFuture {
        unsafe { async_read_impl::<ScionSocket>(this, recv_buf) }
    }

    // actually async_read_some
    pub async fn async_read(
        this: Arc<Mutex<ScionSocket>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, panError> {
        match unsafe { async_read_impl::<ScionSocket>(this, recv_buff).await } {
            Ok((i32, _, _)) => Ok(i32),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from
    pub async fn async_read_from(
        this: Arc<Mutex<ScionSocket>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr), panError> {
        match unsafe { async_read_impl::<ScionSocket>(this, recv_buff).await } {
            Ok((i32, from, _)) => Ok((i32, from)),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from_via
    pub async fn async_read_from_via(
        this: Arc<Mutex<ScionSocket>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr, PanPath), panError> {
        unsafe { async_read_impl::<ScionSocket>(this, recv_buff).await }
    }
}

impl ScionSocket {
    pub fn create_sock_adapter(&mut self) -> Result<(), Box<dyn Error>> {
        let mut rng = Pcg32::seed_from_u64(42);
        // let mut rng = rand::thread_rng();

        let randnr: u32 = rng.gen();

        let go_sock_path: String = format!("/tmp/scion/pan/go{}", randnr);
        let rust_sock_path: String = format!("/tmp/scion/pan/rust{}", randnr);

        return self.create_sock_adapter_impl(&go_sock_path, &rust_sock_path);
    }

    fn create_sock_adapter_impl(
        &mut self,
        go_socket_path: &str,
        rust_socket_path: &str,
    ) -> Result<(), Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ScionSocket ");
            }
            let mut handle: Pan_GoHandle = Default::default();
            let err: PanError = PanNewListenSockAdapter(
                self.get_handle(),
                go_socket_path.as_ptr() as *const i8,
                rust_socket_path.as_ptr() as *const i8,
                handle.resetAndGetAddressOf() as *mut usize,
            );
            if err == 0 {
                self.adapter = Some(ListenSockAdapter::new(handle));
                let mut sock = UnixDatagram::bind(rust_socket_path)?;

                match sock.connect(rust_socket_path) {
                    Ok(sock) => {}
                    Err(e) => {
                        panic!("Couldn't connect: {e:?}");
                    }
                };
                self.unix_sock = Some(sock);
                Ok(())
            } else {
                Err(Box::new(panError(err)))
            }
        }
    }

    pub fn new(listen: snet::SocketAddr) -> Self {
        let rstate = ReadState::Initial; // Assuming ReadState has an Initial variant
        let wstate = WriteState::Initial; // Assuming WriteState has an Initial variant

        let mtx_r = Arc::new(Mutex::new(rstate));
        let mtx_w = Arc::new(Mutex::new(wstate));

        let mut handle = unsafe {
            let add = listen.to_string();
            let h = PanNewScionSocket(add.as_ptr() as *const i8, add.len() as i32) as u64;
            Pan_GoHandle::new1(h)
        };

        let s = Self {
            h: handle,
            adapter: None,
            unix_sock: None,
            mtx_read: mtx_r,
            mtx_write: mtx_w,
            async_read_timeout: 100,  //ms
            async_write_timeout: 100, //ms
        };

        unsafe {
            assert!(s.is_valid());
        }
        s
    }

    pub fn get_local_addr(&self) -> snet::SocketAddr {
        unsafe {
            if !self.is_valid() {
                panic!("method called on invalid handle");
            }

            let ptr = PanScionSocketGetLocalAddr(self.get_handle());
            let c_str = CStr::from_ptr(ptr);
            <snet::SocketAddr as FromStr>::from_str(&c_str.to_string_lossy()).unwrap()
        }
    }

    pub fn bind(&mut self, listen_addr: &str) -> Result<(), panError> {
        unsafe {
            let res = PanScionSocketBind(self.get_handle(), listen_addr.as_ptr() as *const i8);

            match res {
                PAN_ERR_OK => Ok(()),
                _ => Err(panError(res)),
            }
        }
    }

    /*
    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer).await
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data).await
    }*/

    pub fn set_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanScionSocketSetDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn set_read_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanScionSocketSetReadDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn set_write_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanScionSocketSetWriteDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn close(&mut self) {
        unsafe {
            if self.is_valid() {
                PanScionSocketClose(self.get_handle());
                self.h.reset1();
            }
        }
    }
}

#[derive(Debug)]
pub struct ListenConn {
    h: Pan_GoHandle,
    selector: Option<Box<dyn ReplySelector + Send + Sync>>,

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
#[derive(Debug)]
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

unsafe impl Send for WriteState {}
unsafe impl Sync for WriteState {}

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

/*
pub trait TryFuture: Future + Sealed {
    type Ok;
    type Error;

    // Required method
    fn try_poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<Self::Ok, Self::Error>>;
}
 */

impl Future for WriteFuture {
    type Output = Result<i32, panError>;

    fn poll(self: Pin<&mut WriteFuture>, cx: &mut Context<'_>) -> Poll<Result<i32, panError>> {
        match &mut *self.state.clone().lock().unwrap() {
            WriteState::Initial => {
                debug!("write_future_poll: found initial");
                Poll::Pending
            }

            WriteState::Error(err) => {
                debug!("write_future_poll: found error");
                Poll::Ready(Err(*err))
            }

            WriteState::ReadyWriting { bytes_written } => {
                debug!(
                    "write_future_poll: found ready_writing {}bytes",
                    *bytes_written
                );
                Poll::Ready(Ok(*bytes_written))
            }
            WriteState::WaitWrite {
                bytes_written: _,
                waker: ref mut w,
            } => {
                debug!("write_future_poll: found wait_writing");
                // store the waker in the listen conn
                // so the completion can wake us, once the result is available
                unsafe {
                    *w = Some(cx.waker().clone());
                }
                debug!("write_future set waker");

                Poll::Pending
            }
        }
    }
}

#[derive(Debug)]
enum ReadState {
    Initial,
    WaitReading {
        // completion has not yet been called
        //  buffer: *mut Vec<u8>,
        bytes_read: *mut i32,
        from: *mut PanUDPAddr,
        path: *mut PanPath,

        waker: Option<Waker>,
    },
    ReadyReading {
        // buffer: *mut Vec<u8>,
        bytes_read: i32,
        from: PanUDPAddr,
        path: PanPath,
        //waker: Option<Waker>,
    },
    Error(panError),
}

unsafe impl Send for ReadState {}
unsafe impl Sync for ReadState {}

pub struct ReadFuture {
    from: Box<PanUDPAddr>,
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

pub trait Connection: GoHandleOwner {
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
    type Output = Result<(i32, PanUDPAddr, PanPath), panError>;

    fn poll(
        self: Pin<&mut ReadFuture>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(i32, PanUDPAddr, PanPath), panError>> {
        // check what read state the connection is in
        // depending on this return Pending or the Ready result

        let mut ss = &*self.state.clone();
        let mut s = ss.lock().unwrap();
        match *s {
            ReadState::Initial => {
                warn!("read future_poll: found initial");
                Poll::Pending
            }

            ReadState::Error(err) => {
                warn!("read future_poll: found error");
                *s = ReadState::Initial;

                Poll::Ready(Err(err.clone()))
            }

            ReadState::ReadyReading {
                // buffer: _,
                from,
                path,
                bytes_read,
            } => {
                debug!("future_poll: found ready_reading");
                *s = ReadState::Initial; // end this read cycle

                Poll::Ready(Ok((bytes_read, from, path)))
            }
            ReadState::WaitReading {
                // buffer: _,
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
                            //  buffer: bu,
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
                                //buffer: bu.clone(),
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
                            //buffer: bu,
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
                            debug!("write_handler found state: wait_write");
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
                            debug!("write handler found unexpected state: Error");
                        }
                        WriteState::ReadyWriting { .. } => {
                            debug!("write_handler found unexpected state: ReadyWriting");
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
                            debug!("write_handler found state: wait_write");
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
                            debug!("write handler found unexpected state: Error");
                        }
                        WriteState::ReadyWriting { .. } => {
                            debug!("write_handler found unexpected state: ReadyWriting");
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
    C: ?Send,
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
    C: IsSameType<ScionSocket>,
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

    let ffn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, PanError)> = Some(write_completer);
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
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone())
                    as *mut c_void,
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
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone())
                    as *mut c_void,
            );
        }
    } else if <C as IsSameType<ScionSocket>>::IS_SAME_TYPE {
        if via.is_none() {
            err = PanScionSocketWriteToAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                to,
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone())
                    as *mut c_void,
            );
        } else {
            err = PanScionSocketWriteToViaAsync(
                handle,
                send_buff.as_ptr() as *const c_void,
                send_buff.len() as i32,
                to,
                via.unwrap(),
                &mut *_write_future.bytes_written as *mut i32,
                write_tout,
                ffn,
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone())
                    as *mut c_void,
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
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this).clone())
                    as *mut c_void,
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
                Arc::<std::sync::Mutex<WriteState>>::into_raw(C::get_wstate(this.clone()).clone())
                    as *mut c_void,
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

        *lck = WriteState::WaitWrite {
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
    C: ?Send,
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
    C: IsSameType<ScionSocket>,
{
    let bytes_to_send: i32 = send_buff.len() as i32;
    let mut bytes_written: i32 = 0;

    while bytes_to_send > bytes_written {
        debug!("async_write_impl: {}/{}", bytes_written, bytes_to_send);
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

#[async_recursion]
async unsafe fn recursive_write<C>(
    this: Arc<Mutex<C>>,
    send_buff: &[u8],
    to: PanUDPAddr,
    via: Option<PanPath>,
    bytes_written: usize,
    bytes_to_send: usize,
) where
    C: Sync,
    C: Send,
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
    C: IsSameType<ScionSocket>,
{
    if bytes_written >= bytes_to_send {
        return;
    }

    let res = async_write_some_impl::<C>(
        this.clone(),
        &send_buff[bytes_written as usize..(bytes_to_send - bytes_written) as usize],
        to,
        via,
    )
    .await;

    match res {
        Ok(bytes) => {
            recursive_write(
                this,
                send_buff,
                to,
                via,
                bytes_written + bytes as usize,
                bytes_to_send,
            )
            .await;
        }
        Err(e) => {
            // Handle error (e.g., EOF, connection closed)
            eprintln!("Error reading from socket: {:?}", e);
            // ready(Err(e))
        }
    }
}

fn async_write_impl2<'a, C>(
    this: Arc<Mutex<C>>,
    send_buff: &'a [u8],
    to: PanUDPAddr,
    via: Option<PanPath>,
) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + Sync + 'a>>
where
    C: Send,
    C: Sync,
    C: 'a,
    C: Connection,
    C: IsSameType<Conn>,
    C: IsSameType<ListenConn>,
    C: IsSameType<ScionSocket>,
{
    unsafe { recursive_write(this, send_buff, to, via, 0, send_buff.len()) }
}

// actuall async_read_some_impl
unsafe fn async_read_impl<'b, C>(
    this: Arc<Mutex<C>>,
    // recv_buffer: &'b mut Vec<u8>, //  from: & mut PanUDPAddr,
    buff: &'b mut [u8],
) -> ReadFuture
where
    // B: Into<&'b mut [u8]>,
    // &'b mut [u8]: From<&'b mut B>,
    C: Connection,
    C: IsSameType<ListenConn>,
    C: IsSameType<Conn>,
    C: IsSameType<ScionSocket>,
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
    let mut lck = llck.lock().unwrap(); // prevent completer from running ahead

    let ffn: Option<unsafe extern "C" fn(*mut std::ffi::c_void, PanError)> = Some(read_completer);

    let mut p = Box::into_raw(_read_future.path) as *mut PanPath;
    let mut b = Box::into_raw(_read_future.bytes) as *mut i32;
    let mut f = Box::into_raw(_read_future.from) as *mut PanUDPAddr;

    debug!("initiate async_read operation ");
    let mut err: PanError = PAN_ERR_FAILED;

    if <C as IsSameType<ListenConn>>::IS_SAME_TYPE {
        err = PanListenConnReadFromAsyncVia(
            handle,
            buff.as_mut_ptr() as *mut c_void,
            buff.len() as i32,
            f,
            p,
            b,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ReadState>>::into_raw(C::get_rstate(this.clone()))
                as *mut c_void,
        );
    } else if <C as IsSameType<Conn>>::IS_SAME_TYPE {
        err = PanConnReadViaAsync(
            handle,
            buff.as_mut_ptr() as *mut c_void,
            buff.len() as i32,
            p,
            b,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ReadState>>::into_raw(C::get_rstate(this.clone()))
                as *mut c_void,
        );
    } else if <C as IsSameType<ScionSocket>>::IS_SAME_TYPE {
        err = PanScionSocketReadFromAsyncVia(
            handle,
            buff.as_mut_ptr() as *mut c_void,
            buff.len() as i32,
            f,
            p,
            b,
            read_tout,
            ffn,
            Arc::<std::sync::Mutex<ReadState>>::into_raw(C::get_rstate(this.clone()))
                as *mut c_void,
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
            // buffer: recv_buffer as *mut Vec<u8>,
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
            //   buffer: recv_buffer as *mut Vec<u8>,
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
    pub fn set_reply_selector(&mut self, s: Box<dyn ReplySelector + Send + Sync>) {
        self.selector = Some(s);
    }

    pub async fn async_write_some_to(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &[u8],
        to: PanUDPAddr,
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<ListenConn>(this, send_buff, to, None).await }
    }

    pub async fn async_write_some_to_via(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &Vec<u8>,
        to: PanUDPAddr,
        via: PanPath,
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<ListenConn>(this, send_buff, to, Some(via)).await }
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

    pub fn async_write_to2<'a>(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &'a [u8],
        to: &Endpoint,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + Sync + 'a>> {
        unsafe { async_write_impl2::<ListenConn>(this, send_buff, to.get_handle(), None) }
    }

    pub fn async_write_to_via2<'a>(
        this: Arc<Mutex<ListenConn>>,
        send_buff: &'a [u8],
        to: PanUDPAddr,
        via: PanPath,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + 'a>> {
        async_write_impl2::<ListenConn>(this, send_buff, to, Some(via))
    }

    pub fn async_read2(this: Arc<Mutex<ListenConn>>, recv_buf: &mut [u8]) -> ReadFuture {
        unsafe { async_read_impl::<ListenConn>(this, recv_buf) }
    }

    // actually async_read_some
    pub async fn async_read(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, panError> {
        match unsafe { async_read_impl::<ListenConn>(this, recv_buff).await } {
            Ok((i32, _, _)) => Ok(i32),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from
    pub async fn async_read_from(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr), panError> {
        match unsafe { async_read_impl::<ListenConn>(this, recv_buff).await } {
            Ok((i32, from, _)) => Ok((i32, from)),
            Err(e) => Err(e),
        }
    }

    // actually async_read_some_from_via
    pub async fn async_read_from_via(
        this: Arc<Mutex<ListenConn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanUDPAddr, PanPath), panError> {
        unsafe { async_read_impl::<ListenConn>(this, recv_buff).await }
    }

    /*
    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer).await
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data).await
    }*/

    pub fn set_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanListenConnSetDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn set_read_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanListenConnSetReadDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn set_write_deadline(&mut self, t: &std::time::Duration) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            PanListenConnSetWriteDeadline(self.get_handle(), t.as_millis().try_into().unwrap());
        }
    }

    pub fn close(&mut self) {
        unsafe {
            if self.is_valid() {
                PanListenConnClose(self.get_handle());
                self.h.reset1();
            }
        }
    }

    pub fn listen(&mut self, local: &str) -> Result<(), Box<dyn Error>> {
        unsafe {
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
    }

    pub fn get_local_endpoint(&self) -> Endpoint {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
            Endpoint::new(Pan_GoHandle::new1(
                PanListenConnLocalAddr(self.get_handle()) as u64,
            ))
        }
    }

    pub fn read(self: &mut Self, buffer: &mut [u8]) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
    }

    pub fn readFrom(
        self: &mut Self,
        buffer: &mut [u8],
        from: &mut Endpoint,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
    }

    // maybe better return tuple (i32, from, path) instead of out parameters ?!
    pub fn readFromVia(
        self: &mut Self,
        buffer: &mut [u8],
        from: &mut Endpoint,
        path: &mut Path,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
    }

    pub fn writeTo(self: &mut Self, buffer: &[u8], to: &Endpoint) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
    }

    pub fn writeToVia(
        self: &mut Self,
        buffer: &[u8],
        to: &Endpoint,
        path: &Path,
    ) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
    }

    pub fn create_sock_adapter(
        &self,
        go_socket_path: &str,
        c_socket_path: &str,
    ) -> Result<ListenSockAdapter, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid ListenConn ");
            }
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
}

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
    pub fn new(handle: Pan_GoHandle) -> ConnSockAdapter {
        Self { h: handle }
    }

    pub fn close(&mut self) {
        unsafe {
            if self.is_valid() {
                PanConnSockAdapterClose(self.get_handle());
                self.h.reset1();
            }
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
#[derive(Debug)]
pub struct Conn {
    h: Pan_GoHandle,
    policy: Option<Box<dyn PathPolicy + Sync + Send>>,
    selector: Option<Box<dyn PathSelector + Sync + Send>>,

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
    pub fn async_write_some_impl(
        this: Arc<Mutex<Conn>>,
        send_buff: &[u8],
        to: PanUDPAddr,
        via: Option<PanPath>,
    ) -> WriteFuture {
        unsafe { async_write_some_impl::<Conn>(this, send_buff, to, via) }
    }

    /*  pub fn async_write_impl(this: Arc<Mutex<Conn>>, send_buff: &[u8], to: PanUDPAddr, via: Option<PanPath>) ->WriteFuture
    {
        unsafe { async_write_impl::<Conn>(this,send_buff,to,via) }
    }*/

    pub async fn async_write_some(
        this: Arc<Mutex<Conn>>,
        send_buff: &[u8],
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<Conn>(this, send_buff, 0, None).await }
    }
    pub async fn async_write_some_via(
        this: Arc<Mutex<Conn>>,
        send_buff: &Vec<u8>,
        via: PanPath,
    ) -> Result<i32, panError> {
        unsafe { async_write_some_impl::<Conn>(this, send_buff, 0, Some(via)).await }
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

    pub fn async_write2<'a>(
        this: Arc<Mutex<Conn>>,
        send_buff: &'a [u8],
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + Sync + 'a>> {
        async_write_impl2::<Conn>(this, send_buff, 0, None)
    }

    pub fn async_write_via2<'a>(
        this: Arc<Mutex<Conn>>,
        send_buff: &'a [u8],
        via: PanPath,
    ) -> std::pin::Pin<Box<dyn futures::Future<Output = ()> + std::marker::Send + 'a>> {
        async_write_impl2::<Conn>(this, send_buff, 0, Some(via))
    }

    // actually async_read_some
    pub async fn async_read(
        this: Arc<Mutex<Conn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<i32, panError> {
        match unsafe { async_read_impl::<Conn>(this, recv_buff).await } {
            Ok((i32, _, _)) => Ok(i32),
            Err(e) => Err(e),
        }
    }

    pub fn async_read2(this: Arc<Mutex<Conn>>, recv_buf: &mut [u8]) -> ReadFuture {
        unsafe { async_read_impl::<Conn>(this, recv_buf) }
    }

    // actually async_read_some_via
    pub async fn async_read_via(
        this: Arc<Mutex<Conn>>,
        recv_buff: &mut Vec<u8>,
    ) -> Result<(i32, PanPath), panError> {
        match unsafe { async_read_impl::<Conn>(this, recv_buff).await } {
            Ok((i, _, p)) => Ok((i, p)),
            Err(e) => Err(e),
        }
    }

    pub fn close(&mut self) {
        unsafe {
            if self.is_valid() {
                PanConnClose(self.get_handle());
                self.h.reset1();
            }
        }
    }

    pub fn get_local_endpoint(&self) -> Endpoint {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
            Endpoint::new(Pan_GoHandle::new1(
                PanConnLocalAddr(self.get_handle()) as u64
            ))
        }
    }

    pub fn get_remote_endpoint(&self) -> Endpoint {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
            Endpoint::new(Pan_GoHandle::new1(
                PanConnRemoteAddr(self.get_handle()) as u64
            ))
        }
    }

    pub fn dial_str(&mut self, local: Option<&str>, remote: &str) -> Result<(), Box<dyn Error>> {
        let addr = resolve_udp_addr(remote)?;

        self.dial(local, &addr)
    }

    pub fn dial(
        self: &mut Self,
        local: Option<&str>,
        remote: &Endpoint,
    ) -> Result<(), Box<dyn Error>> {
        unsafe {
            let err = PanDialUDP(
                //    local.as_ptr() as *const i8,
                if local.is_some() {
                    local.unwrap().as_ptr() as *const i8
                } else {
                    std::ptr::null::<i8>()
                },
                remote.get_handle(),
                if self.policy.is_some() {
                    debug!("client dial with policy");
                    (self.policy.as_mut()).unwrap().get_handle()
                } else {
                    PAN_INVALID_HANDLE as usize
                },
                if self.selector.is_some() {
                    debug!("client dial with selector");
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
    }

    pub fn set_deadline(self: &mut Self, timeout: u32) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
            PanConnSetDeadline(self.get_handle(), timeout);
        }
    }

    pub fn set_read_deadline(self: &mut Self, timeout: u32) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
            PanConnSetReadDeadline(self.get_handle(), timeout);
        }
    }

    pub fn set_write_deadline(self: &mut Self, timeout: u32) {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
            PanConnSetWriteDeadline(self.get_handle(), timeout);
        }
    }

    pub fn write(self: &Self, buffer: &[u8]) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
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
    }

    pub fn writeVia(self: &Self, buffer: &[u8], path: &Path) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
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
    }

    pub fn read(self: &Self, buffer: &mut [u8]) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
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
    }

    pub fn readVia(self: &Self, buffer: &mut [u8], path: &mut Path) -> Result<i32, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
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
    }

    pub fn createSockAdaper(
        self: &mut Self,
        go_socket_path: &str,
        c_socket_path: &str,
    ) -> Result<ConnSockAdapter, Box<dyn Error>> {
        unsafe {
            if !self.is_valid() {
                panic!(" attempt to invoke method on invalid Conn ");
            }
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
}

impl Default for Conn {
    fn default() -> Self {
        unsafe {
            Self {
                h: Pan_GoHandle::default(),
                selector: None,
                policy: None,
                mtx_read: Arc::new(Mutex::new(ReadState::Initial)),
                mtx_write: Arc::new(Mutex::new(WriteState::Initial)),
                async_read_timeout: 100,  //ms
                async_write_timeout: 100, //ms
            }
        }
    }
}

impl Conn {
    pub fn set_policy(&mut self, pol: Box<dyn PathPolicy + Send + Sync>) {
        self.policy = Some(pol);
    }

    pub fn set_selector(&mut self, selector: Box<dyn PathSelector + Send + Sync>) {
        self.selector = Some(selector);
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
