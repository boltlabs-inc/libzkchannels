extern crate bindgen;
extern crate cbindgen;

use std::env;

fn main() {
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search={}/deps/root/lib", project_dir); // the "-L" flag
    println!("cargo:rustc-link-lib=tokenm-utils"); // the "-l" flag

    // Create bindings
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("deps/root/include/emp-ag2pc/tokens.h")
        .clang_arg("-x")
        .clang_arg("c++")
        .trust_clang_mangling(false)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");

    // TODO: Create build for libtoken-utils here

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file("include/bindings.h");
}
