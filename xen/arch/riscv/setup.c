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

struct memory_bank {
    unsigned long start;
    unsigned long size;
};

struct memory_bank banks[] = {
    /* memory-node from dts.  Ram */

#define TEMP_OFF 0x0300000
    /* Hardcode to be offset from Xen load addr space */
    {.start = 0x00080000000 + TEMP_OFF, .size=0x8000000 - TEMP_OFF},
};

static int nr_banks = (int) ARRAY_SIZE(banks);

static void __init init_pdx(void)
{
    paddr_t bank_start, bank_size, bank_end;

    /*
     * Arm does not have any restrictions on the bits to compress. Pass 0 to
     * let the common code further restrict the mask.
     *
     * If the logic changes in pfn_pdx_hole_setup we might have to
     * update this function too.
     */
    uint64_t mask = pdx_init_mask(0x0);
    int bank;

    for ( bank = 0 ; bank < nr_banks; bank++ )
    {
        bank_start = banks[bank].start;
        bank_size = banks[bank].size;

        mask |= bank_start | pdx_region_mask(bank_start, bank_size);
    }

    for ( bank = 0 ; bank < nr_banks; bank++ )
    {
        bank_start = banks[bank].start;
        bank_size = banks[bank].size;

        if (~mask & pdx_region_mask(bank_start, bank_size))
            mask = 0;
    }

    pfn_pdx_hole_setup(mask >> PAGE_SHIFT);

    for ( bank = 0 ; bank < nr_banks; bank++ )
    {
        bank_start = banks[bank].start;
        bank_size = banks[bank].size;
        bank_end = bank_start + bank_size;

        set_pdx_range(paddr_to_pfn(bank_start),
                      paddr_to_pfn(bank_end));
    }
}

static void __init setup_mm(void)
{
    paddr_t ram_start, ram_end, ram_size;
    unsigned long heap_start;
    unsigned long ram_pages;
    unsigned long heap_pages, xenheap_pages, domheap_pages;
    unsigned long boot_mfn_start, boot_mfn_end;
    int i;

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
    /* These values are hardcoded for the riscv-virt QEMU device */
    /* How much ram do we have? */
    init_pdx();

    /* 0x80000000 - 0x80200000 is PMP protected by OpenSBI
     * so exclude it from the ram range (any attempt at using it
     * will trigger an access fault
     */

    ram_start = banks[0].start;
    ram_size  = banks[0].size;
    ram_end   = ram_start + ram_size;

    for ( i = 1; i < nr_banks; i++ )
    {
        unsigned long bank_start = banks[i].start;
        unsigned long bank_size = banks[i].size;
        unsigned long bank_end = bank_start + bank_size;

        ram_size  = ram_size + bank_size;
        ram_start = min(ram_start,bank_start);
        ram_end   = max(ram_end,bank_end);
    }

    /* How many pages of ram? */
    total_pages = ram_pages = ram_size >> PAGE_SHIFT;

    /* What size of heap?
     * TODO: derive heap sizes from dtb
     * Comments from ARM's setup.c ...
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
    /* Where to place heap? */
    /* TODO: Find a range of memory that is the size of the heap and does
     * not contain memory used by any other part of the system.
     */

    heap_start = ram_end - (xenheap_pages << PAGE_SHIFT);
    setup_xenheap_mappings(heap_start, xenheap_pages);

    setup_domheap_pagetables();

    /*
     * Need a single mapped page for populating bootmem_region_list.
     * Plus other pages (TODO: calculate from fdt)
     */
    boot_mfn_start = mfn_x(xenheap_mfn_end) - ((30 << 20) >> PAGE_SHIFT) - 1;
    boot_mfn_end = mfn_x(xenheap_mfn_end);

    init_boot_pages(pfn_to_paddr(boot_mfn_start), pfn_to_paddr(boot_mfn_end));

    /* TODO: Add non-xenheap memory, use dt for unreserved space */

    max_page = PFN_DOWN(ram_end);

    setup_frametable_mappings(ram_start, ram_end);

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

    setup_virtual_regions(NULL, NULL);
    setup_mm();
    end_boot_allocator();

    vm_init();


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
