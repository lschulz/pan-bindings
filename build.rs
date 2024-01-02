extern crate bindgen;
extern crate cc;
use cc::*;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

extern crate cmake;
use cmake::Config;

use bindgen::CargoCallbacks;

use walkdir::WalkDir;

fn find_file(start_dir: Option<&str>, fname: &str) -> std::io::Result<PathBuf> {
    for entry in WalkDir::new(start_dir.unwrap_or("."))
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name().to_string_lossy();

        if fname == f_name {
            return Ok(entry.into_path().clone());
        }
    }

    Err(std::io::Error::new(io::ErrorKind::Other, "file not found"))
}

fn main() {
    println!("enter top level BUILD-SCRIPT");

    let dir: PathBuf = env::current_dir().unwrap();
    let out_di = env::var("OUT_DIR").unwrap().to_string();
    std::env::set_var("OUTER_OUT_DIR", &out_di);
    std::env::set_var("PROJECT_DIR", dir.to_str().unwrap());
    println!("DIR: {:?}", dir);
    println!("OUT_DIR: {:?}", out_di);

    let mut cmake_cfg = Config::new(".");

    cmake_cfg.define("CARGO_BUILD", "1");
    let dst = cmake_cfg.build();

    let out_dir = env::var("OUT_DIR").unwrap();

    let mut libpan_name: String = "libpan.a".to_string();
    let mut pan_name: String = "pan".to_string();

    let profile = std::env::var("PROFILE").unwrap();
    match profile.as_str() {
        "debug" => {
            libpan_name = "libpand.a".to_string();
            pan_name = "pand".to_string();
        }
        "release" => {}
        _ => {}
    }

    let mut pan_path = find_file(Some(&out_dir), &libpan_name).unwrap();
    pan_path.pop();
    println!("PAN_PATH: {}", pan_path.to_str().unwrap());

    println!("cargo:rustc-link-search=all={}", &out_dir);
    println!("cargo:rustc-link-search=all={}", pan_path.to_str().unwrap());
    println!("cargo:rustc-link-search=all={}/lib", &out_dir);
    println!("cargo:rustc-link-search=all={}/build/go", &out_dir);
    println!("cargo:rustc-link-search=all=/lib/x86_64-linux-gnu");

    println!("cargo:rustc-link-lib=static:+bundle={}", &pan_name);
    //  println!("cargo:rustc-link-lib=stdc++");
    //println!("cargo:rustc-link-lib=go_handle");
    //println!("cargo:rustc-link-lib=pan");

    // println!("cargo:rustc-flags=-l go_handle.a -l pand.a  -L ../build/go -L tmp "); // -Wl,-Bstatic

    // Tell cargo to invalidate the built crate whenever the header changes.
    println!("cargo:rerun-if-changed=./build");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        .clang_arg("-DBINDGEN")
        //  .clang_arg("-xc++")
        //  .clang_arg("-std=c++11")
        .clang_arg("-I ./include")
        .clang_arg("-I ./include/pan")
        .header("./include/pan/pan_cdefs.h")
        .header("./include/pan/pan.h")
        .parse_callbacks(Box::new(CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(out_dir).join("bindings.rs");
    bindings
        .write_to_file(out_path.clone())
        .expect("Couldn't write bindings!");

    std::fs::copy(
        out_path.clone(),
        PathBuf::from("./rust/src").join("bindings.rs"),
    );
    // .expect("cannot copy generated bindings to where lib.rs expects them");
}
