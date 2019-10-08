/*
 * xen/arch/riscv/setup.c
 *
 * Early bringup code for a RISC-V RV32/64 with hypervisor
 * extensions (code H).
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
unsigned long total_pages;

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    snprintf(s, sizeof(s), "xen-%d.%d-riscv ", major, minor);
    safe_strcat(*info, s);
}

/* TODO: remove all of this before RFC'ing 
 * TODO: Hardcode a PDX offset/hole and try to understand what it does
 */
struct memory_bank {
    unsigned long start;
    unsigned long size;
};

struct memory_bank banks[] = {
    /* memory-node from dts.  Ram */

#define OPENSBI_OFFSET 0x0200000
#define XEN_OFFSET     (12 << 20)

    /* Hardcode to be offset from Xen load addr space */
    {.start = 0x00080000000 + OPENSBI_OFFSET + XEN_OFFSET, .size=0x8000000 - OPENSBI_OFFSET - XEN_OFFSET},
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

    init_pdx();

    /* 0x80000000 - 0x80200000 is PMP protected by OpenSBI
     * so exclude it from the ram range (any attempt at using it
     * will trigger a PMP fault)
     */

    ram_start = banks[0].start;
    ram_size  = banks[0].size;
    ram_end   = ram_start + ram_size;
    total_pages = ram_size >> PAGE_SHIFT;

    setup_xenheap_mappings(ram_start>>PAGE_SHIFT, total_pages);
    xenheap_virt_end = XENHEAP_VIRT_START + ram_end - ram_start;
    xenheap_mfn_end = maddr_to_mfn(ram_end);
    init_boot_pages(mfn_to_maddr(xenheap_mfn_start),
                    mfn_to_maddr(xenheap_mfn_end));
    max_page = PFN_DOWN(ram_end);
    setup_frametable_mappings(0, ram_end);
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

    /* Setup UART */
    ns16550.io_base = 0x10000000;
    ns16550.irq     = 10;
    ns16550.baud    = 115200;
    ns16550_init(0, &ns16550);
    console_init_preirq();

    printk("RISC-V Xen Boot!\n");
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
