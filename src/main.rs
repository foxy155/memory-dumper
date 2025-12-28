use std::alloc::handle_alloc_error;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot,
    Process32FirstW,
    Process32NextW,
    PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,

};
use windows::Win32::System::Threading::{
    OpenProcess,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    PROCESS_VM_OPERATION,
    PROCESS_QUERY_INFORMATION

};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory
};
use windows::Win32::System::Memory::{
    VirtualQueryEx,
    MEMORY_BASIC_INFORMATION,
    MEM_COMMIT,
    PAGE_GUARD,
    PAGE_NOACCESS
};
use windows::Win32::Foundation::{
    CloseHandle
};
use std::io;


fn main() {
    println!("welcome to cheat engine CLI cuz i am too lazy to make a GUI");
    println!("listing processes . . .");

    let mut dumps = Vec::<RegionDump>::new();

    //list processes
    unsafe {
        //take snapshot
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        //prepare the process struct
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        //get the first process
        if Process32FirstW(snapshot.clone().unwrap(), &mut entry).is_ok() {
            loop {
                // Convert the UTF-16 filename to Rust String
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)]
                );
                println!("PID: {} name: {}",entry.th32ProcessID, name);
                if !Process32NextW(snapshot.clone().unwrap(), &mut entry).is_ok() {
                    break;
                }
            }
        }
    }
    println!("done");
    println!("insert PID of the process");


    //input 0
    let mut input0 = String::new();
    match io::stdin().read_line(&mut input0) {
        Ok(_) => {
            let trimmed = input0.trim();
            if trimmed.is_empty() {
                println!("nothing to do");
            }else {
                input0 = trimmed.to_string();
            }
        }
        Err(error) => eprintln!("error: {}", error),
    }


    //input 1
    println!("insert PID of the process");
    let mut input1 = String::new();
    match io::stdin().read_line(&mut input1) {
        Ok(_) => {
            let trimmed = input1.trim();
            if trimmed.is_empty() {
                println!("nothing to do");
            }else {
                input1 = trimmed.to_string();
            }
        }
        Err(error) => eprintln!("error: {}", error),
    }


    match openprocess(input0, input1) {
        Ok(handle) => {
            if handle.is_invalid() {
                panic!("can't open process");
            }
            unsafe {
                let regions = query_regions(handle);
                for region in &regions {
                    if region.State == MEM_COMMIT && region.Protect.0 & PAGE_GUARD.0 == 0 && region.Protect != PAGE_NOACCESS
                    {
                        if let Some(bytes) = read_regions(handle, region.BaseAddress as usize, region.RegionSize) {
                            dumps.push(RegionDump{base: region.BaseAddress as usize, bytes});
                        }
                    }
                }
            };
        }
        Err(_) => panic!("can't open process"),
    }




}

fn openprocess(mut PID: String, mut name: String) -> Result<windows::Win32::Foundation::HANDLE, io::Error>

{
    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            PID.parse::<u32>().unwrap()
        ).unwrap();
        return Ok(handle);
    }
}

unsafe fn read_regions(handle: windows::Win32::Foundation::HANDLE,
address: usize,
size: usize,)->Option<Vec<u8>>
{
    let mut buffer = vec![0u8; size];
    let mut bytes_Read = 0usize;
    let result = ReadProcessMemory(
        handle,
        address as *const _,
        buffer.as_mut_ptr() as *mut _,
        size,
        Some(&mut bytes_Read)
    );
    if result.is_ok() && bytes_Read > 0 {
        buffer.truncate(bytes_Read);
        Some(buffer)
    }else {
        None
    }
}

unsafe fn query_regions(
    Process : windows::Win32::Foundation::HANDLE,
) -> Vec<MEMORY_BASIC_INFORMATION>{
    let mut regions = Vec::<MEMORY_BASIC_INFORMATION>::new();

    let mut address = 0usize;
    let mut info = MEMORY_BASIC_INFORMATION::default();

    while VirtualQueryEx(
        Process,
        Some(address as *const _),
        &mut info,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>()

    )!= 0{
        regions.push(info);
    }
    regions
}
struct RegionDump {
    base : usize,
    bytes: Vec<u8>
}