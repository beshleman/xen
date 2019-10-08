/**
 * Copyright (c) 2018 Anup Patel.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * @file cpu_mmu_initial_pgtbl.c
 * @author Anup Patel (anup@brainfault.org)
 * @brief Initial page table setup at boot-time
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
#include <asm/current.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <xsm/xsm.h>

/*
 * xen_second_pagetable is indexed with the VPN[2] page table entry field
 * xen_first_pagetable is accessed from the VPN[1] page table entry field
 * xen_zeroeth_pagetable is accessed from the VPN[0] page table entry field
 */
unsigned long xen_second_pagetable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static unsigned long xen_first_pagetable[PAGE_ENTRIES * 2] __attribute__((__aligned__(4096*2)));
static unsigned long xen_zeroeth_pagetable[PAGE_ENTRIES * 5] __attribute__((__aligned__(4096)));

void __init clear_pagetables(void)
{
    unsigned long i;

    for (i=0; i<ARRAY_SIZE(xen_second_pagetable); i++) {
        xen_second_pagetable[i] = 0ULL;
    }

    for (i=0; i<ARRAY_SIZE(xen_first_pagetable); i++) {
        xen_first_pagetable[i] = 0ULL;
    }

    for (i=0; i<ARRAY_SIZE(xen_zeroeth_pagetable); i++) {
        xen_zeroeth_pagetable[i] = 0ULL;
    }
}


void __attribute__ ((section(".entry"))) setup_pagetables(unsigned long *second,
                                                          unsigned long *first,
                                                          unsigned long *zeroeth,
                                                          unsigned long map_start,
                                                          unsigned long map_end,
                                                          unsigned long pa_start) {
    unsigned long page_addr;
    unsigned long index2;
    unsigned long index1;
    unsigned long index0;

    /* align start addresses */
    map_start &= PGTBL_L0_MAP_MASK;
    pa_start &= PGTBL_L0_MAP_MASK;

    page_addr = map_start;
    while (page_addr < map_end) {
        /* Setup level2 table */
        index2 = (page_addr & PGTBL_L2_INDEX_MASK) >> PGTBL_L2_INDEX_SHIFT;
        index1 = (page_addr & PGTBL_L1_INDEX_MASK) >> PGTBL_L1_INDEX_SHIFT;
        index0 = (page_addr & PGTBL_L0_INDEX_MASK) >> PGTBL_L0_INDEX_SHIFT;

        /* Allocate new level1 table */
        second[index2] = (unsigned long) &first[index1];
        second[index2] = second[index2] >> PGTBL_PAGE_SIZE_SHIFT;
        second[index2] = second[index2] << PGTBL_PTE_ADDR_SHIFT;
        second[index2] |= PGTBL_PTE_VALID_MASK;

        /* Setup level1 table */
        /* Allocate new level0 table */
        first[index1] = (unsigned long) &zeroeth[index0];
        first[index1] = first[index1] >> PGTBL_PAGE_SIZE_SHIFT;
        first[index1] = first[index1] << PGTBL_PTE_ADDR_SHIFT;
        first[index1] |= PGTBL_PTE_VALID_MASK;

        /* Setup level0 table */
        if (!(zeroeth[index0] & PGTBL_PTE_VALID_MASK)) {
                /* Update level0 table */
                zeroeth[index0] = (page_addr - map_start) + pa_start;
                zeroeth[index0] = zeroeth[index0] >> PGTBL_PAGE_SIZE_SHIFT;
                zeroeth[index0] = zeroeth[index0] << PGTBL_PTE_ADDR_SHIFT;
                zeroeth[index0] |= PGTBL_PTE_EXECUTE_MASK;
                zeroeth[index0] |= PGTBL_PTE_WRITE_MASK;
                zeroeth[index0] |= PGTBL_PTE_READ_MASK;
                zeroeth[index0] |= PGTBL_PTE_VALID_MASK;
        }

        /* Point to next page */
        page_addr += PGTBL_L0_BLOCK_SIZE;
    }
}

/* Note: This functions must be called with MMU disabled from
 * primary CPU only.
 * Note: This functions cannot refer to any global variable &
 * functions to ensure that it can execute from anywhere.
 */
#define to_load_pa(va)	({ \
			unsigned long _tva = (unsigned long) (va); \
			if (_exec_start <= _tva && _tva < _exec_end) { \
				_tva = _tva - _exec_start + _load_start; \
			} \
			_tva; \
			})
#define to_exec_va(va)	({ \
			unsigned long _tva = (unsigned long) (va); \
			if (_load_start <= _tva && _tva < _load_end) { \
				_tva = _tva - _load_start + _exec_start; \
			} \
			_tva; \
			})

extern unsigned long _text_start;
extern unsigned long _text_end;
extern unsigned long _cpuinit_start;
extern unsigned long _cpuinit_end;
extern unsigned long _spinlock_start;
extern unsigned long _spinlock_end;
extern unsigned long _init_start;
extern unsigned long _init_end;
extern unsigned long _rodata_start;
extern unsigned long _rodata_end;

void __attribute__ ((section(".entry")))
    _setup_initial_pgtbl(unsigned long _load_start, unsigned long _load_end,
			 unsigned long _exec_start, unsigned long _exec_end)
{
    unsigned long *second;
    unsigned long *first;
    unsigned long *zeroeth;

    second = (unsigned long *)to_load_pa(&xen_second_pagetable);
    first = (unsigned long *)to_load_pa(&xen_first_pagetable);
    zeroeth = (unsigned long *)to_load_pa(&xen_zeroeth_pagetable);

    /* For now assume 3-level page table */
    /* Map physical = logical
     * Note: This mapping is used at boot time only
     */
    setup_pagetables(second, first, zeroeth, _load_start, _load_end, _load_start);

    /* Map to logical addresses which are
     * covered by read-only linker sections
     * Note: This mapping is used at runtime
     */
    setup_pagetables(second, first, zeroeth, _load_start, _load_end, _load_start);
    setup_pagetables(second, first, zeroeth, 
                       to_exec_va(&_text_start),
                       to_exec_va(&_text_end),
                       to_load_pa(&_text_start));
    setup_pagetables(second, first, zeroeth,
                       to_exec_va(&_init_start),
                       to_exec_va(&_init_end),
                       to_load_pa(&_init_start));
    setup_pagetables(second, first, zeroeth,
                       to_exec_va(&_cpuinit_start),
                       to_exec_va(&_cpuinit_end),
                       to_load_pa(&_cpuinit_start));
    setup_pagetables(second, first, zeroeth,
                       to_exec_va(&_spinlock_start),
                       to_exec_va(&_spinlock_end),
                       to_load_pa(&_spinlock_start));
    setup_pagetables(second, first, zeroeth,
                       to_exec_va(&_rodata_start),
                       to_exec_va(&_rodata_end),
                       to_load_pa(&_rodata_start));
    setup_pagetables(second, first, zeroeth, _exec_start, _exec_end, _load_start);
}
