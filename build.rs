extern crate bindgen;

use std::env;
use std::fs;
use std::path::PathBuf;

extern crate cmake;
use cmake::Config;

use bindgen::CargoCallbacks;

fn main() {
    println!("enter top level BUILD-SCRIPT");

    let dir :PathBuf = env::current_dir().unwrap();
    std::env::set_var("OUTER_OUT_DIR", env::var("OUT_DIR").unwrap().to_string() );
    std::env::set_var("PROJECT_DIR", dir.to_str().unwrap() );
    println!( "DIR: {:?}" ,dir );



    let mut cmake_cfg = Config::new(".");

    cmake_cfg.define("CARGO_BUILD","1");
    let dst = cmake_cfg.build();

    match std::process::Command::new("mkdir").arg("tmp").output() {
        Ok(o) => {
            print!("mkdir output: {:?}\n", o);
        }
        Err(e) => {
            panic!("mkdir failed: {}", e);
        }
    }

    let out_dir = env::var("OUT_DIR").unwrap();

    // This is the directory where the `c` library is located.
    let libdir_path = PathBuf::from("./tmp")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize path");

    println!("libdir_path: {}", libdir_path.display());
    // This is the path to the `c` headers file.
    let headers_path_str = "./include/pan/go_handle.hpp"; // headers_path.to_str().expect("Path is not a valid string");

    // This is the path to the intermediate object file for our library.
    let obj_path = libdir_path.join("go_handle.o");
    // This is the path to the static library file.
    let lib_path = libdir_path.join("libgo_handle.a");

    //  clang -c -o tmp/go_handle.o ../cpp/go_handle.cpp -I ../include
    let res = std::process::Command::new("clang++")
        .arg("-c")
        .arg("-I")
        .arg("./include/pan")
        //.arg("-I ./include/pan/pan.h")
        //.arg("-I ./include/pan/go_handle.hpp")
        .arg("-o")
        .arg(&obj_path)
        .arg("./cpp/go_handle.cpp")
        .arg("-DBINDGEN")
        .output();
    // if !res.expect("cannot execute clang").status.success()

    match res {
        Ok(o) => {
            print!("output: {:?}\n", o);
        }
        Err(e) => {
            // doesnt work for some reason :(
            // you have to enter the above command manually

            //panic!("could not compile object file: {}",res.err().unwrap());
            panic!("could not compile object file: {}", e);
        }
    }

    // ar rcs tmp/libgo_handle.a tmp/go_handle.o
    let res1 = std::process::Command::new("ar")
        .arg("rcs")
        .arg(lib_path)
        .arg(obj_path)
        .output();
    if !res1.is_ok() {
        // Panic if the command was not successful.
        panic!("could not emit library file: {}", res1.err().unwrap());
    }

    /* match fs::copy("../build/go/libpand.a","tmp/libpand.a")
    {
        Err( err ) => { panic!("could not copy file"); }
        Ok( o) =>{}
    }
    */

    // println!("cargo:rustc-link-search=all={},../build/go", libdir_path.to_str().unwrap());

    println!("cargo:rustc-link-search=all=tmp");
    println!("cargo:rustc-link-search=all={}", &out_dir);
    println!("cargo:rustc-link-search=all=./build/go");
    println!("cargo:rustc-link-search=all=/lib/x86_64-linux-gnu");

    //  println!("cargo:rustc-link-search=../build/go");

    println!("cargo:rustc-link-lib=static:+bundle=go_handle");
    println!("cargo:rustc-link-lib=static:+bundle=pan");
    println!("cargo:rustc-link-lib=stdc++");
    //println!("cargo:rustc-link-lib=go_handle");
    //println!("cargo:rustc-link-lib=pan");

    // println!("cargo:rustc-flags=-l go_handle.a -l pand.a  -L ../build/go -L tmp "); // -Wl,-Bstatic

    // Tell cargo to invalidate the built crate whenever the header changes.
    println!("cargo:rerun-if-changed={}", headers_path_str);
    println!("cargo:rerun-if-changed=./build");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .clang_arg("-DBINDGEN")
        .clang_arg("-xc++")
        .clang_arg("-std=c++11")
        .clang_arg("-I ./include")
        .clang_arg("-I ./include/pan")
        .header("./include/pan/pan_cdefs.h")
        .header("./include/pan/pan.h")
        .header(headers_path_str)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(out_dir).join("bindings.rs");
    bindings
        .write_to_file(out_path.clone())
        .expect("Couldn't write bindings!");

        std::fs::copy(out_path.clone(), PathBuf::from("./rust/src").join("bindings.rs")  )
        .expect("cannot copy generated bindings to where lib.rs expects them");
    
}
