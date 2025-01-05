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

const FPAKFILE_CHECK: usize = 0x3FF8E50;

unsafe fn thread_func() {
    Console::AllocConsole().unwrap();
    println!("Wuthering Waves signature check bypass");
    println!("Don't forget to visit https://discord.gg/reversedrooms");

    let module = GetModuleHandleA(PCSTR::null()).unwrap();
    println!("Base: {:X}", module.0 as usize);

    // 读取配置文件
    let mut config_file = fs::File::open("config.json").expect("无法打开config.json文件");
    let mut config_content = String::new();
    config_file.read_to_string(&mut config_content).expect("无法读取config.json文件内容");
    let config: Value = serde_json::from_str(&config_content).expect("无法解析config.json文件");

    // 检查Agents字段是否为false
    if config["Agents"].as_bool() == Some(false) {
        println!("你没有该权限");
        return;
    }

    let mut interceptor = Interceptor::new();
    interceptor
        .replace(
            (module.0 as usize) + FPAKFILE_CHECK,
            fpakfile_check_replacement,
        )
        .unwrap();

    println!("Successfully initialized!");
    thread::sleep(Duration::from_secs(u64::MAX));
}

unsafe extern "win64" fn fpakfile_check_replacement(
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
        thread::spawn(|| thread_func());
    }

    true
}
