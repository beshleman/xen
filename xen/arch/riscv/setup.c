/*
 * xen/arch/arm/setup.c
 *
 * Early bringup code for an ARMv7-A with virt extensions.
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/compile.h>
#include <xen/domain_page.h>
#include <xen/grant_table.h>
#include <xen/types.h>
#include <xen/string.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/err.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <xen/pfn.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <xen/trace.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/setup.h>
#include <asm/setup.h>
#include <xsm/xsm.h>

/* The lucky hart to first increment this variable will boot the other cores */
atomic_t hart_lottery;
unsigned long boot_cpu_hartid;

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    snprintf(s, sizeof(s), "xen-%d.%d-riscv ", major, minor);
    safe_strcat(*info, s);
}

static void __init setup_mm(void)
{
    paddr_t ram_start, ram_end, ram_size;
    unsigned long heap_end;
    unsigned long heap_start;
    unsigned long ram_pages;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned long boot_mfn_start, boot_mfn_end;

    /*
    This is the memory layout for the qemu/virt board.
    We will hard code these values for our ram mem range.

    static const struct MemmapEntry {
        hwaddr base;
        hwaddr size;
    } virt_memmap[] = {
        [VIRT_DEBUG] =       {        0x0,         0x100 },
        [VIRT_MROM] =        {     0x1000,       0x11000 },
        [VIRT_TEST] =        {   0x100000,        0x1000 },
        [VIRT_CLINT] =       {  0x2000000,       0x10000 },
        [VIRT_PLIC] =        {  0xc000000,     0x4000000 },
        [VIRT_UART0] =       { 0x10000000,         0x100 },
        [VIRT_VIRTIO] =      { 0x10001000,        0x1000 },
        [VIRT_DRAM] =        { 0x80000000,           0x0 },
        [VIRT_PCIE_MMIO] =   { 0x40000000,    0x40000000 },
        [VIRT_PCIE_PIO] =    { 0x03000000,    0x00010000 },
        [VIRT_PCIE_ECAM] =   { 0x30000000,    0x10000000 },};
    */
    /* How much ram do we have? */
    ram_start = 0x0; /* TODO: extract from fdt*/
    ram_size  = 0x80000000UL; /* TODO: extract from fdt */
    ram_end   = ram_start + ram_size;

    /* How many pages of ram? */
    total_pages = ram_pages = ram_size >> PAGE_SHIFT;

    /* Comments from ARM's setup.c ...
     *
     * If the user has not requested otherwise via the command line
     * then locate the xenheap using these constraints:
     *
     *  - must be 32 MiB aligned
     *  - must not include Xen itself or the boot modules
     *  - must be at most 1GB or 1/32 the total RAM in the system if less
     *  - must be at least 32M
     *
     * We try to allocate the largest xenheap possible within these
     * constraints.
     */
    heap_pages = ram_pages;
    xenheap_pages = (heap_pages/32 + 0x1fffUL) & ~0x1fffUL;
    xenheap_pages = max(xenheap_pages, 32UL<<(20-PAGE_SHIFT));
    xenheap_pages = min(xenheap_pages, 1UL<<(30-PAGE_SHIFT));
    domheap_pages = heap_pages - xenheap_pages;

    /* Find a range of memory that is the size of the heap and does not contain memory used
     * by the rest of the system.  heap_end is the end of that range.
     * TODO: find this range programatically
     */
    /* Hardcoded to be ~1.75GB below DRAM controller for QEMU/virt TODO: don't do this */
    heap_end = 0x70000000;

    /* heap_end >> PAGE_SHIFT == The number of pages from 0 to the
     * paddr(heap_end) 
     */
    heap_start = heap_end - (xenheap_pages << PAGE_SHIFT);
    setup_xenheap_mappings(heap_start, xenheap_pages);

    /*
     * Need a single mapped page for populating bootmem_region_list.
     */
    boot_mfn_start = mfn_x(xenheap_mfn_end) - 1;
    boot_mfn_end = mfn_x(xenheap_mfn_end);

    init_boot_pages(pfn_to_paddr(boot_mfn_start), pfn_to_paddr(boot_mfn_end));

    /* TODO: Add non-xenheap memory */
    /* TODO: Setup frame tables? Frame table covers all of RAM region, including holes */
       
    max_page = PFN_DOWN(ram_end);

    /* Add xenheap memory that was not already added to the boot
       allocator. */
    init_xenheap_pages(mfn_to_maddr(xenheap_mfn_start),
                       pfn_to_paddr(boot_mfn_start));
}

void __init start_xen(void)
{
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };


    setup_mm();
    vm_init();
    // setup_pagetables(0x80200000);

    ns16550.io_base = 0x10000000;
    ns16550.irq     = 10;
    ns16550.baud    = 115200;
    ns16550_init(0, &ns16550);
    console_init_preirq();

    printk("RISC-V Xen Boot!\n");

    preinit_xen_time();
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
