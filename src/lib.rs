use std::thread;
use std::time::Duration;
use std::path::Path;

use ilhook::x64::Registers;
use interceptor::Interceptor;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::{GetModuleHandleA, GetModuleFileNameA}};

mod interceptor;

const FPAKFILE_CHECK: usize = 0x3DE6650;
const EXPECTED_DLL_NAME: &str = "CenSerPatch.dll"; // 修改为期望的 DLL 名称

unsafe fn thread_func() {
    if Console::AllocConsole().is_err() {
        eprintln!("Failed to allocate console.");
        return;
    }
    
    // 获取当前 DLL 文件名
    let mut buffer = vec![0u8; 260]; // 文件名缓冲区
    let module = GetModuleHandleA(PCSTR::null()).unwrap();
    
    let length = GetModuleFileNameA(module, buffer.as_mut_slice());
    if length == 0 {
        eprintln!("Failed to get module file name.");
        return;
    }

    // 从字节缓冲区转换为字符串
    let dll_name = String::from_utf8_lossy(&buffer[..length as usize]);
    let dll_file_name = Path::new(&dll_name).file_name().unwrap_or_default().to_string_lossy();

    // 验证 DLL 文件名是否正确
    if dll_file_name != EXPECTED_DLL_NAME {
        eprintln!("您当前版本为修改版本，疑似被黑客修改，版本不安全，请相关渠道下载安全版本 Your current version is a modified version, which is suspected to have been modified by hackers and is not secure, please download the security version from the relevant channels");
        return;
    }

    // 打印欢迎信息
    println!("You are using CenSerPatch");
    println!("它是免费的，如果你是通过购买获得的那么你已受骗 It's free, and if you got it through a purchase then you've been scammed");

    println!("Base: {:X}", module.0 as usize);

    // 创建拦截器并进行函数替换
    let mut interceptor = Interceptor::new();
    if let Err(err) = interceptor.replace(
        (module.0 as usize) + FPAKFILE_CHECK,
        fpakfile_check_replacement,
    ) {
        eprintln!("Failed to replace function: {}", err);
        return;
    }

    println!("Successfully crossed the SIG Verified ACE!");

    // 线程休眠，防止退出
    thread::sleep(Duration::from_secs(u64::MAX));
}

unsafe extern "win64" fn fpakfile_check_replacement(
    reg: *mut Registers,
    _: usize,
    _: usize,
) -> usize {
    let wstr = *(((*reg).rcx + 8) as *const usize) as *const u16;
    let pak_name = PCWSTR::from_raw(wstr).to_string().unwrap();
    println!("Verify successful Paks: {pak_name}, SHA1 ACE has been returned and verified");

    1
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        thread::spawn(|| thread_func());
    }

    true
}
