fn main() {
    glib_build_tools::compile_resources(
        &["resources"],
        "resources/deepwork.gresource.xml",
        "deepwork.gresource",
    );
    println!("cargo:rerun-if-changed=../../assets/icon.svg");
}
