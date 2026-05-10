use libc::{_SC_PAGESIZE, PROT_EXEC, PROT_READ, PROT_WRITE, c_void, mprotect, sysconf};
use std::{fs, ptr};

fn page_size() -> usize {
    let v = unsafe { sysconf(_SC_PAGESIZE) };
    if v > 0 { v as usize } else { 4096 }
}

/// Parses /proc/self/maps to get the current memory protection for an address.
fn get_mem_prot(addr: usize) -> Option<i32> {
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        let Some((start_str, end_str)) = range.split_once('-') else { continue };
        
        let Ok(start) = usize::from_str_radix(start_str, 16) else { continue };
        let Ok(end) = usize::from_str_radix(end_str, 16) else { continue };

        if (start..end).contains(&addr) {
            let mut prot = 0;
            if perms.contains('r') { prot |= PROT_READ; }
            if perms.contains('w') { prot |= PROT_WRITE; }
            if perms.contains('x') { prot |= PROT_EXEC; }
            return Some(prot);
        }
    }
    None
}

/// Safely reads a u32, verifying mapping and readability.
pub unsafe fn read_u32(addr: usize) -> Result<u32, &'static str> {
    let prot = get_mem_prot(addr).ok_or("unmapped address")?;
    if (prot & PROT_READ) == 0 {
        return Err("unreadable address");
    }
    Ok(unsafe { ptr::read_unaligned(addr as *const u32) })
}

/// Safely writes a u32 by temporarily adding RWX permissions and then restoring.
pub unsafe fn write_u32(addr: usize, value: u32) -> Result<(), &'static str> {
    let orig_prot = get_mem_prot(addr).ok_or("unmapped address")?;
    
    let ps = page_size();
    let start = addr - (addr % ps);
    // Generic math to calculate spanned page length (works for non-power-of-2 page sizes)
    let len = ((addr % ps + 4 + ps - 1) / ps) * ps;

    // 1. Unlock memory (preserve original + RW)
    let unlock_prot = PROT_READ | PROT_WRITE;
    if unsafe { mprotect(start as *mut c_void, len, unlock_prot) } != 0 {
        return Err("mprotect unlock failed");
    }

    // 2. Overwrite instructions
    unsafe { ptr::write_unaligned(addr as *mut u32, value) };

    // 3. Restore original protection (Fail-secure)
    if unsafe { mprotect(start as *mut c_void, len, orig_prot) } != 0 {
        eprintln!("[dofslim] FATAL: Failed to restore W^X protection for {addr:#x}. Aborting.");
        std::process::abort(); 
    }
    
    Ok(())
}