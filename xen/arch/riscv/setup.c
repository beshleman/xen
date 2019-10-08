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

void __init start_xen(void)
{
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };

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
