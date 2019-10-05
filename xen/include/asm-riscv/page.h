/*
 * Copyright (C) 2009 Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2017 XiaojingZhu <zhuxiaoj@ict.ac.cn>
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

#ifndef _ASM_RISCV_PAGE_H
#define _ASM_RISCV_PAGE_H

#include <public/xen.h>
#include <xen/const.h>
#include <xen/config.h>
#include <asm/riscv_encoding.h>
#include <asm/asm.h>

/*
 * PAGE_OFFSET -- the first address of the first page of memory.
 * When not using MMU this corresponds to the first free page in
 * physical memory (aligned on a page boundary).
 */
#define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)

#define PAGE_ENTRIES    1024

#define KERN_VIRT_SIZE (-PAGE_OFFSET)

/* Taken from Xvisor */
#define PGTBL_INITIAL_TABLE_COUNT           8 
#define PGTBL_TABLE_SIZE                0x00001000
#define PGTBL_TABLE_SIZE_SHIFT              12
#ifdef CONFIG_RISCV_64
#define PGTBL_TABLE_ENTCNT              512
#define PGTBL_TABLE_ENTSZ               8
#else
#define PGTBL_TABLE_ENTCNT              1024
#define PGTBL_TABLE_ENTSZ               4
#endif
#define PGTBL_PAGE_SIZE                 0x00001000
#define PGTBL_PAGE_SIZE_SHIFT               12

#ifdef CONFIG_RISCV_64
/* L3 index Bit[47:39] */
#define PGTBL_L3_INDEX_MASK             0x0000FF8000000000ULL
#define PGTBL_L3_INDEX_SHIFT                39
#define PGTBL_L3_BLOCK_SIZE             0x0000008000000000ULL
#define PGTBL_L3_MAP_MASK               (~(PGTBL_L3_BLOCK_SIZE - 1))
/* L2 index Bit[38:30] */
#define PGTBL_L2_INDEX_MASK             0x0000007FC0000000ULL
#define PGTBL_L2_INDEX_SHIFT                30
#define PGTBL_L2_BLOCK_SIZE             0x0000000040000000ULL
#define PGTBL_L2_MAP_MASK               (~(PGTBL_L2_BLOCK_SIZE - 1))
/* L1 index Bit[29:21] */
#define PGTBL_L1_INDEX_MASK             0x000000003FE00000ULL
#define PGTBL_L1_INDEX_SHIFT                21
#define PGTBL_L1_BLOCK_SHIFT                21
#define PGTBL_L1_BLOCK_SIZE             0x0000000000200000ULL
#define PGTBL_L1_MAP_MASK               (~(PGTBL_L1_BLOCK_SIZE - 1))
/* L0 index Bit[20:12] */
#define PGTBL_L0_INDEX_MASK             0x00000000001FF000ULL
#define PGTBL_L0_INDEX_SHIFT                12
#define PGTBL_L0_BLOCK_SHIFT                12
#define PGTBL_L0_BLOCK_SIZE             0x0000000000001000ULL
#define PGTBL_L0_MAP_MASK               (~(PGTBL_L0_BLOCK_SIZE - 1))
#else
/* L1 index Bit[31:22] */
#define PGTBL_L1_INDEX_MASK             0xFFC00000UL
#define PGTBL_L1_INDEX_SHIFT                22
#define PGTBL_L1_BLOCK_SHIFT                22
#define PGTBL_L1_BLOCK_SIZE             0x00400000UL
#define PGTBL_L1_MAP_MASK               (~(PGTBL_L1_BLOCK_SIZE - 1))
/* L0 index Bit[21:12] */
#define PGTBL_L0_INDEX_MASK             0x003FF000UL
#define PGTBL_L0_INDEX_SHIFT                12
#define PGTBL_L0_BLOCK_SHIFT                12
#define PGTBL_L0_BLOCK_SIZE             0x00001000UL
#define PGTBL_L0_MAP_MASK               (~(PGTBL_L0_BLOCK_SIZE - 1))
#endif

#define PGTBL_PTE_ADDR_MASK             0x003FFFFFFFFFFC00ULL
#define PGTBL_PTE_ADDR_SHIFT                10
#define PGTBL_PTE_RSW_MASK              0x0000000000000300ULL
#define PGTBL_PTE_RSW_SHIFT             8
#define PGTBL_PTE_DIRTY_MASK                0x0000000000000080ULL
#define PGTBL_PTE_DIRTY_SHIFT               7
#define PGTBL_PTE_ACCESSED_MASK             0x0000000000000040ULL
#define PGTBL_PTE_ACCESSED_SHIFT            6
#define PGTBL_PTE_GLOBAL_MASK               0x0000000000000020ULL
#define PGTBL_PTE_GLOBAL_SHIFT              5
#define PGTBL_PTE_USER_MASK             0x0000000000000010ULL
#define PGTBL_PTE_USER_SHIFT                4
#define PGTBL_PTE_EXECUTE_MASK              0x0000000000000008ULL
#define PGTBL_PTE_EXECUTE_SHIFT             3
#define PGTBL_PTE_WRITE_MASK                0x0000000000000004ULL
#define PGTBL_PTE_WRITE_SHIFT               2
#define PGTBL_PTE_READ_MASK             0x0000000000000002ULL
#define PGTBL_PTE_READ_SHIFT                1
#define PGTBL_PTE_PERM_MASK             (PGTBL_PTE_EXECUTE_MASK | \
                             PGTBL_PTE_WRITE_MASK | \
                             PGTBL_PTE_READ_MASK)
#define PGTBL_PTE_VALID_MASK                0x0000000000000001ULL
#define PGTBL_PTE_VALID_SHIFT               0

/* Calculate the offsets into the pagetables for a given VA */
#define zeroeth_linear_offset(va) ((va) >> PGTBL_L0_INDEX_SHIFT)
#define first_linear_offset(va) ((va) >> PGTBL_L1_INDEX_SHIFT)
#define second_linear_offset(va) ((va) >> PGTBL_L2_INDEX_SHIFT)
#define third_linear_offset(va) ((va) >> PGTBL_L3_INDEX_SHIFT)

#define TABLE_OFFSET(offs) ((unsigned int)(offs) & PGTBL_PTE_ADDR_MASK)
#define first_table_offset(va)  TABLE_OFFSET(first_linear_offset(va))
#define second_table_offset(va) TABLE_OFFSET(second_linear_offset(va))
#define third_table_offset(va)  TABLE_OFFSET(third_linear_offset(va))
#define zeroeth_table_offset(va)  TABLE_OFFSET(zeroeth_linear_offset(va))

#define pgtbl_v0_index(va) zeroeth_linear_offset((va) & PGTBL_L0_INDEX_MASK)
#define pgtbl_v1_index(va) first_linear_offset((va) & PGTBL_L1_INDEX_MASK)
#define pgtbl_v2_index(va) second_linear_offset((va) & PGTBL_L2_INDEX_MASK)
#define pgtbl_v3_index(va) third_linear_offset((va) & PGTBL_L3_INDEX_MASK)

#ifndef __ASSEMBLY__

#define PAGE_UP(addr)	(((addr)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))
#define PAGE_DOWN(addr)	((addr)&(~((PAGE_SIZE)-1)))

/* align addr on a size boundary - adjust address up/down if needed */
#define _ALIGN_UP(addr, size)	(((addr)+((size)-1))&(~((size)-1)))
#define _ALIGN_DOWN(addr, size)	((addr)&(~((size)-1)))

/* align addr on a size boundary - adjust address up if needed */
#define _ALIGN(addr, size)	_ALIGN_UP(addr, size)

#define clear_page(pgaddr)			memset((pgaddr), 0, PAGE_SIZE)
#define copy_page(to, from)			memcpy((to), (from), PAGE_SIZE)

#define clear_user_page(pgaddr, vaddr, page)	memset((pgaddr), 0, PAGE_SIZE)
#define copy_user_page(vto, vfrom, vaddr, topg) \
			memcpy((vto), (vfrom), PAGE_SIZE)

/*
 * Attribute Indexes.
 *
 */
#define MT_NORMAL        0x0

#define _PAGE_XN_BIT    3
#define _PAGE_RO_BIT    4
#define _PAGE_XN    (1U << _PAGE_XN_BIT)
#define _PAGE_RO    (1U << _PAGE_RO_BIT)
#define PAGE_XN_MASK(x) (((x) >> _PAGE_XN_BIT) & 0x1U)
#define PAGE_RO_MASK(x) (((x) >> _PAGE_RO_BIT) & 0x1U)

/*
 * _PAGE_DEVICE and _PAGE_NORMAL are convenience defines. They are not
 * meant to be used outside of this header.
 */
#define _PAGE_DEVICE    _PAGE_XN
#define _PAGE_NORMAL    MT_NORMAL

#define PAGE_HYPERVISOR_RO      (_PAGE_NORMAL|_PAGE_RO|_PAGE_XN)
#define PAGE_HYPERVISOR_RX      (_PAGE_NORMAL|_PAGE_RO)
#define PAGE_HYPERVISOR_RW      (_PAGE_NORMAL|_PAGE_XN)

#define PAGE_HYPERVISOR         PAGE_HYPERVISOR_RW
#define PAGE_HYPERVISOR_NOCACHE (_PAGE_DEVICE)
#define PAGE_HYPERVISOR_WC      (_PAGE_DEVICE)

/* Note: we use 1/8th or 12.5% of VAPOOL memory as translation table pool.
 * For example if VAPOOL is 8 MB then translation table pool will be 1 MB
 * or 1 MB / 4 KB = 256 translation tables
 */
#define PGTBL_MAX_TABLE_COUNT 	(CONFIG_VAPOOL_SIZE_MB << \
					(20 - 3 - PGTBL_TABLE_SIZE_SHIFT))

#define PGTBL_MAX_TABLE_SIZE	(PGTBL_MAX_TABLE_COUNT * PGTBL_TABLE_SIZE)
#define PGTBL_INITIAL_TABLE_SIZE (PGTBL_INITIAL_TABLE_COUNT * PGTBL_TABLE_SIZE)

/* Invalidate all instruction caches in Inner Shareable domain to PoU */
static inline void invalidate_icache(void)
{
    asm volatile ("fence.i" ::: "memory");
}

static inline int invalidate_dcache_va_range(const void *p, unsigned long size)
{
	/* TODO */
	return 0;
}

static inline int clean_dcache_va_range(const void *p, unsigned long size)
{
    /* TODO */
    return 0;
}

static inline int clean_and_invalidate_dcache_va_range
    (const void *p, unsigned long size)
{
	/* TODO */
    return 0;
}

/*
 * Use struct definitions to apply C type checking
 */

/* Page Global Directory entry */
typedef struct {
	unsigned long pgd;
} pgd_t;

/* Page Table entry */
typedef struct {
	unsigned long pte;
} pte_t;

typedef struct {
	unsigned long pgprot;
} pgprot_t;

typedef struct page *pgtable_t;

#define pte_val(x)	((x).pte)
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __pte(x)	((pte_t) { (x) })
#define __pgd(x)	((pgd_t) { (x) })
#define __pgprot(x)	((pgprot_t) { (x) })

#ifdef CONFIG_64BIT
#define PTE_FMT "%016lx"
#else
#define PTE_FMT "%08lx"
#endif

extern unsigned long va_pa_offset;
extern unsigned long pfn_base;

extern unsigned long max_low_pfn;
extern unsigned long min_low_pfn;

#define __pa(x)		((unsigned long)(x) - va_pa_offset)
#define __va(x)		((void *)((unsigned long) (x) + va_pa_offset))

#define pfn_valid(pfn) \
	(((pfn) >= pfn_base) && (((pfn)-pfn_base) < max_mapnr))

#define ARCH_PFN_OFFSET		(pfn_base)

#endif /* __ASSEMBLY__ */

#define PAGE_ALIGN(x) (((x) + PAGE_SIZE - 1) & PAGE_MASK)

#define virt_addr_valid(vaddr)	(pfn_valid(virt_to_pfn(vaddr)))

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

/* Flush the dcache for an entire page. */
void flush_page_to_ram(unsigned long mfn, bool sync_icache);

static inline uint64_t va_to_par(vaddr_t va)
{
    register unsigned long __mepc asm ("a2") = va;
    register unsigned long __mstatus asm ("a3");
    register unsigned long __bsstatus asm ("a4");
    unsigned long val;
    unsigned long rvc_mask = 3, tmp;
    asm ("csrrs %[mstatus], "STR(CSR_MSTATUS)", %[mprv]\n"
        "csrrs %[bsstatus], "STR(CSR_BSSTATUS)", %[smxr]\n"
        "and %[tmp], %[addr], 2\n"
        "bnez %[tmp], 1f\n"
#if RISCV_64
        STR(LWU) " %[insn], (%[addr])\n"
#else
        STR(LW) " %[insn], (%[addr])\n"
#endif
        "and %[tmp], %[insn], %[rvc_mask]\n"
        "beq %[tmp], %[rvc_mask], 2f\n"
        "sll %[insn], %[insn], %[xlen_minus_16]\n"
        "srl %[insn], %[insn], %[xlen_minus_16]\n"
        "j 2f\n"
        "1:\n"
        "lhu %[insn], (%[addr])\n"
        "and %[tmp], %[insn], %[rvc_mask]\n"
        "bne %[tmp], %[rvc_mask], 2f\n"
        "lhu %[tmp], 2(%[addr])\n"
        "sll %[tmp], %[tmp], 16\n"
        "add %[insn], %[insn], %[tmp]\n"
        "2: csrw "STR(CSR_BSSTATUS)", %[bsstatus]\n"
        "csrw "STR(CSR_MSTATUS)", %[mstatus]"
    : [mstatus] "+&r" (__mstatus), [bsstatus] "+&r" (__bsstatus),
      [insn] "=&r" (val), [tmp] "=&r" (tmp)
    : [mprv] "r" (MSTATUS_MPRV | SSTATUS_MXR), [smxr] "r" (SSTATUS_MXR),
      [addr] "r" (__mepc), [rvc_mask] "r" (rvc_mask),
      [xlen_minus_16] "i" (__riscv_xlen - 16));

    return val;
}

/* Write a pagetable entry. */
static inline void write_pte(pte_t *p, pte_t pte)
{
    /* Inspired from the ARMv7 function write_pte().
     * Is sfence.vma the best fence to use here?
     * Must all previous pagetbl instructions be ordered too?
    asm volatile (
        "sfence.vma;\n"
        "sd %0 (%1);\n"
        "sfence.vma %0;\n"
        : : "r" (pte), "r" (p) : "memory");
     */

    asm volatile ("sfence.vma");
    *p = pte;
    asm volatile ("sfence.vma");
}

#endif /* _ASM_RISCV_PAGE_H */
