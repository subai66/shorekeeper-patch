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
use windows::Win32::System::Diagnostics::Debug::{CheckRemoteDebuggerPresent, GetCurrentProcess};

mod interceptor;

const FPAKFILE_CHECK: usize = 0x3FF8E50;

unsafe fn thread_func() {
    Console::AllocConsole().unwrap();
    println!("你正在使用CenSerPatch/ You are using CenSerPatch");
    println!("Welcome to CenSerPatch!");
    println!("正在获取config请稍等");

    let mut is_debugged: BOOL = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugged);
    if is_debugged != 0 {
        println!("你正在尝试破解,你的行为已被禁止。/ You're trying to hack and your actions have been banned.");
        return;
    }

    let module = GetModuleHandleA(PCSTR::null()).unwrap();
    println!("Base: {:X}", module.0 as usize);

    // 读取配置文件
    let mut config_file = fs::File::open("config.json").expect("无法打开config.json文件/ Unable to open config.json file");
    let mut config_content = String::new();
    config_file.read_to_string(&mut config_content).expect("无法读取config.json文件内容/ Unable to read config.json file contents");
    let config: Value = serde_json::from_str(&config_content).expect("无法解析config.json文件/ The config.json file could not be resolved");

    if config["Agents"].as_bool() == Some(true) {
        println!("你没有该权限/ You don't have that permission");
        return;
    }

    println!("请勿倒卖本程序，否则后果自负。");

    if config["SigBypass"].as_bool() == Some(false) {
        println!("你选择不禁止sigbypass，它会存在风险，但是我们依然按照config.json运行它/ If you choose not to ban sigbypass, it's risky, but we still run it as config.json");
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
