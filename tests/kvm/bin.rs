#![feature(linkage, naked_functions, asm)]
// In this example we will construct a single CPU x86 VM which will execute
// "inb 0x01" at ring 0 with paging disabled

extern crate kvm;
extern crate memmap;
extern crate x86;

use kvm::{Capability, Exit, IoDirection, System, Vcpu, VirtualMachine};
use std::mem;
use memmap::{Mmap, Protection};
use std::fs::File;
use std::io::{BufRead, BufReader};

use x86::shared::control_regs;
use x86::bits64::paging;

#[naked]
unsafe extern "C" fn use_the_port() {
    asm!("inb $0, %al" :: "i"(0x01) :: "volatile");
}

#[test]
fn io_example() {
    // Initialize the KVM system
    let sys = System::initialize().unwrap();

    // Create a Virtual Machine
    let mut vm = VirtualMachine::create(&sys).unwrap();

    // Ensure that the VM supports memory backing with user memory
    assert!(vm.check_capability(Capability::UserMemory) > 0);
    // Set the 2 MB range to start at physical address 0
    let f = File::open("/proc/self/maps").unwrap();
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let line = line.unwrap();
        println!("{}", line);
        let mut s = line.split(' ');
        let mut s2 = s.next().unwrap().split('-');
        let begin = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        let end = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        if end < 0x800000000000 {
            let perm = s.next().unwrap();
            println!("{:#X}-{:#X} {}", begin, end, perm);
            let slice = {
                let begin_ptr: *mut u8 = begin as *const u8 as _;
                unsafe { ::std::slice::from_raw_parts_mut(begin_ptr, end - begin) }
            };
            vm.set_user_memory_region(begin as _, slice, 0).unwrap();
        }
    }

    // Create a new VCPU
    let mut vcpu = Vcpu::create(&mut vm).unwrap();

    // Set supported CPUID (KVM fails without doing this)
    let mut cpuid = sys.get_supported_cpuid().unwrap();
    vcpu.set_cpuid2(&mut cpuid).unwrap();

    // Setup the special registers
    let mut sregs = vcpu.get_sregs().unwrap();

    // Set the code segment to have base 0, limit 4GB (flat segmentation)
    sregs.cs.base = 0x0;
    sregs.cs.limit = 0xffffffff;
    sregs.cs.selector = 0x8;
    sregs.cs._type = 0xb;
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;
    sregs.cs.s = 1;
    sregs.cs.l = 0;
    sregs.cs.g = 1;
    sregs.cs.avl = 0;

    // We don't need to populate the GDT if we have our segments setup
    // cr0 - protected mode on, paging disabled

    let cr0 = control_regs::CR0_ENABLE_PAGING | control_regs::CR0_ALIGNMENT_MASK | control_regs::CR0_WRITE_PROTECT | control_regs::CR0_NUMERIC_ERROR | control_regs::CR0_EXTENSION_TYPE | control_regs::CR0_MONITOR_COPROCESSOR | control_regs::CR0_PROTECTED_MODE;
    sregs.cr0 = cr0.bits() as u64;

    let cr4 = control_regs::CR4_ENABLE_GLOBAL_PAGES | control_regs::CR4_ENABLE_PAE | control_regs::CR4_ENABLE_PSE;
    sregs.cr4 = cr4.bits() as u64;

    // Construct identity map
    let mut allocations = Vec::with_capacity(512+1);
    let mut pml4_mem = Mmap::anonymous(4096, Protection::ReadWrite).unwrap();
    let pml4 = unsafe { mem::transmute::<*mut u8, &mut paging::PML4>(pml4_mem.mut_ptr()) };
    allocations.push(pml4_mem);
    for i in 0..512 {
        let mut pdpt_mem = Mmap::anonymous(4096, Protection::ReadWrite).unwrap();
        let pdpt = unsafe { mem::transmute::<*mut u8, &mut paging::PDPT>(pdpt_mem.mut_ptr()) };
        for j in 0..512 {
            let offset = j * (1024*1024*1024) + i * 512 * (1024*1024*1024);
            pdpt[j] = paging::PDPTEntry::new(paging::PAddr::from_u64(offset as u64), paging::PDPT_P | paging::PDPT_RW | paging::PDPT_PS);
        }
        pml4[i] = paging::PML4Entry::new(paging::PAddr::from_u64(pdpt as *const _ as u64), paging::PML4_P | paging::PML4_RW);
        allocations.push(pdpt_mem);
    }
    sregs.cr3 = &pml4 as *const _ as _;

    // Set the special registers
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = &use_the_port as *const _ as _;
    println!("regs.rip = {:X}", regs.rip);
    regs.rflags = 0x2;
    vcpu.set_regs(&regs).unwrap();

    // Actually run the VCPU
    let run = unsafe { vcpu.run() }.unwrap();

    // Ensure that the exit reason we get back indicates that the I/O
    // instruction was executed
    println!("{:?}", run);
    assert!(run.exit_reason == Exit::Io);
    let io = unsafe { *run.io() };
    assert!(io.direction == IoDirection::In);
    assert!(io.size == 1);
    assert!(io.port == 0x1);
    unsafe {
        println!("{:#?}", *run.io());
    }
}