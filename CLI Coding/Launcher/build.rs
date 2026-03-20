fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set("ProductName", "CLI Launcher");
        res.set("FileDescription", "CLI Coding Tool Launcher");
        res.set("CompanyName", "Intellicrack");
        res.set("LegalCopyright", "Intellicrack");
        res.compile().expect("Failed to compile Windows resources");
    }
}
