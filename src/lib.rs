use std::fs;
use std::io::Read;
use serde_json::Value;

use std::thread;
use std::time::Duration;

use ilhook::x64::Registers;
use interceptor::Interceptor;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleHandleA};

mod interceptor;

const FPAKFILE_CHECK: usize = 0x4051B60;

unsafe fn a() {
    Console::AllocConsole().unwrap();
    println!("你正在使用CenSerPatch/ You are using CenSerPatch");
    println!("Welcome to CenSerPatch!");
    println!("正在获取config请稍等");

    let module = GetModuleHandleA(PCSTR::null()).unwrap();

    println!("Base: {:X}", module.0 as usize);

    let mut config_file = fs::File::open("config.json").expect("无法打开config.json文件/ Unable to open config.json file");
    let mut config_content = String::new();
    config_file.read_to_string(&mut config_content).expect("无法读取config.json文件/ The config.json file could not be read");
    let config: Value = serde_json::from_str(&config_content).expect("无法解析config.json文件/ The config.json file could not be resolved");
    if config["Agents"].as_bool() == Some(true) {
        println!("你没有该权限/ You don't have that permission");
        return;
    }
    if config["SigBypass"].as_bool() == Some(false) {
        println!("你选择不禁止sigbypass，它会存在风险，但是我们依然按照config.json运行它/ If you choose not to ban sigbypass, it's risky, but we still run it as config.json");
    }
    let _dummy_var = 42;
    if _dummy_var == 42 {
        println!("正在过检测请稍等.../ I am being tested, please wait...");
    }
    let _useless_var = 123;
    if _useless_var == 123 {
        //println!("能不能把你妈破解了，我超你妈的/ Can you crack me, I'm so crazy about you mom");
    }
    let mut interceptor = Interceptor::new();
    interceptor
        .replace(
            (module.0 as usize) + FPAKFILE_CHECK,
            b,
        )
        .unwrap();
    println!("Successfully initialized!");
    thread::sleep(Duration::from_secs(u64::MAX));
}

unsafe extern "win64" fn b(
    reg: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    let wstr = *(((*reg).rcx + 8) as *const usize) as *const u16;
    let pak_name = PCWSTR::from_raw(wstr).to_string().unwrap();
    println!("Trying to verify pak: {pak_name}, returning true");
    1
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| a());
    }

    true
}