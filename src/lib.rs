use std::thread;
use std::time::Duration;
use std::fs::File;
use std::io::Write;

use ilhook::x64::Registers;
use interceptor::Interceptor;
use windows::core::PCWSTR;
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::LibraryLoader::GetModuleFileNameA;
use windows::Win32::Foundation::HINSTANCE;

mod interceptor;

const FPAKFILE_CHECK: usize = 0x3DE6650;
const EXPECTED_DLL_NAME: &str = "censerpatch.dll"; // 修改为期望的 DLL 名称

fn log(message: &str) {
    let mut file = File::create("log.txt").expect("Failed to create log file");
    writeln!(file, "{}", message).expect("Failed to write to log file");
}

unsafe fn thread_func(module: HINSTANCE) {
    log("Thread started");

    if Console::AllocConsole().is_err() {
        eprintln!("Failed to allocate console.");
        log("Failed to allocate console");
        return;
    }

    // 获取当前 DLL 文件名
    let mut buffer = vec![0u8; 1024]; // 文件名缓冲区

    let length = GetModuleFileNameA(module, buffer.as_mut_slice());
    if length == 0 {
        eprintln!("Failed to get module file name.");
        log("Failed to get module file name");
        return;
    }

    // 从字节缓冲区转换为字符串，获取文件名
    let dll_name = String::from_utf8_lossy(&buffer[..length as usize]);
    let dll_file_name = dll_name.split('\\').last().unwrap_or_default().to_lowercase();

    // 调试输出
    println!("Expected DLL Name: {}", EXPECTED_DLL_NAME.to_lowercase());
    println!("Actual DLL File Name: {}", dll_file_name);

    // 验证 DLL 文件名是否正确
    if dll_file_name != EXPECTED_DLL_NAME.to_lowercase() {
        eprintln!("您当前版本为修改版本，疑似被黑客修改，版本不安全，请相关渠道下载安全版本 Your current version is a modified version, which is suspected to have been modified by hackers and is not secure, please download the security version from the relevant channels");
        println!("DLL file name verification failed");
        return;
    }

    // 打印欢迎信息 - 当文件名验证通过时
    println!("You are using CenSerPatch");
    println!("它是免费的，如果你是通过购买获得的那么你已受骗 It's free, and if you got it through a purchase then you've been scammed");

    println!("Base: {:X}", module.0 as usize);

    // 创建拦截器并进行函数替换
// 创建拦截器并进行函数替换
let mut interceptor = Interceptor::new();
if let Err(err) = interceptor.replace(
    (module.0 as usize) + FPAKFILE_CHECK,
    fpakfile_check_replacement,
) {
    eprintln!("Failed to replace function: {}", err);
    println!("Failed to replace function: {}", err);
    return;
}
println!("Function replaced successfully");

    // 线程休眠，防止退出
    thread::sleep(Duration::from_secs(u64::MAX));
}

unsafe extern "win64" fn fpakfile_check_replacement(
    reg: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    println!("Entering fpakfile_check_replacement");

    let wstr = *(((*reg).rcx + 8) as *const usize) as *const u16;
    println!("wstr address: {:p}", wstr);

    let pak_name = match PCWSTR::from_raw(wstr).to_string() {
        Ok(name) => name,
        Err(e) => {
            println!("Failed to convert wstr to string: {}", e);
            return 0;
        }
    };
    println!("Verify successful Paks: {pak_name}, SHA1 ACE has been returned and verified");

    1
}
#[no_mangle]
unsafe extern "system" fn DllMain(hinst_dll: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        if std::env::args().any(|arg| arg == "-CenSerPatch") {
            println!("DllMain: DLL_PROCESS_ATTACH");
            thread::spawn(move || thread_func(hinst_dll));
        } else {
            println!("DllMain: DLL_PROCESS_ATTACH, but injection is disabled");
        }
    }

    true
}