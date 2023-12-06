extern crate bindgen;

use std::env;
use std::fs;
use std::path::PathBuf;

use bindgen::CargoCallbacks;

fn main() {

    let out_dir = env::var("OUT_DIR").unwrap();

    // This is the directory where the `c` library is located.
    let libdir_path = PathBuf::from("tmp")
        // Canonicalize the path as `rustc-link-search` requires an absolute
        // path.
        .canonicalize()
        .expect("cannot canonicalize path");

println!("libdir_path: {}",libdir_path.display() );
    // This is the path to the `c` headers file.
    let headers_path =  libdir_path.join("hello.h");
    let headers_path_str = "../include/go_handle.hpp"; // headers_path.to_str().expect("Path is not a valid string");

    // This is the path to the intermediate object file for our library.
    let obj_path = libdir_path.join("go_handle.o");
    // This is the path to the static library file.
    let lib_path = libdir_path.join("libgo_handle.a");



    //  clang -c -o tmp/go_handle.o ../cpp/go_handle.cpp -I ../include
    if !std::process::Command::new("clang++")
        .arg("-c")
        .arg("-o")       
        .arg(&obj_path)
        .arg("../cpp/go_handle.cpp")
        .arg("-I ../include")
        .output()
        .expect("could not spawn `clang`")
        .status
        .success()
    {
        // doesnt work for some reason :(
        // you have to enter the above command manually
       //  panic!("could not compile object file");
    }

    // ar rcs tmp/libgo_handle.a tmp/go_handle.o
    if !std::process::Command::new("ar")
        .arg("rcs")
        .arg(lib_path)
        .arg(obj_path)
        .output()
        .expect("could not spawn `ar`")
        .status
        .success()
    {
        // Panic if the command was not successful.
        // panic!("could not emit library file");
    }


   /* match fs::copy("../build/go/libpand.a","tmp/libpand.a") 
    {
        Err( err ) => { panic!("could not copy file"); }
        Ok( o) =>{}
    }
    */

       
       // println!("cargo:rustc-link-search=all={},../build/go", libdir_path.to_str().unwrap());

    println!("cargo:rustc-link-search=all=tmp");
    println!("cargo:rustc-link-search=all=../build/go");
    println!("cargo:rustc-link-search=all=/lib/x86_64-linux-gnu");

      //  println!("cargo:rustc-link-search=../build/go");

        println!("cargo:rustc-link-lib=static:+bundle=go_handle");
        println!("cargo:rustc-link-lib=static:+bundle=pan");
        println!("cargo:rustc-link-lib=stdc++");


        
       // println!("cargo:rustc-flags=-l go_handle.a -l pand.a  -L ../build/go -L tmp "); // -Wl,-Bstatic

        // Tell cargo to invalidate the built crate whenever the header changes.
        println!("cargo:rerun-if-changed={}", headers_path_str);
        println!("cargo:rerun-if-changed=../build" );
        


    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(headers_path_str)
        .header("../include/pan_cdefs.h")
        .header("../include/pan.h")
        .clang_arg("-xc++")
        .clang_arg("-std=c++11")
       // .clang_arg("-std=c++11")
       //.clang_arg("-std=gnu++11")
        
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
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}