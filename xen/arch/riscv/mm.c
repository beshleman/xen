#include <xen/compile.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/p2m.h>
#include <public/domctl.h>
#include <asm/page.h>
#include <xen/preempt.h>
#include <xen/errno.h>
#include <xen/grant_table.h>
#include <xen/softirq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <public/memory.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <xsm/xsm.h>
#include <xen/pfn.h>
#include <xen/sizes.h>
#include <asm/setup.h>

/* TODO: remove these if they're not needed pte_t boot_pgtable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
pte_t boot_first[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
pte_t boot_first_id[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
*/

/* Limits of the Xen heap */
mfn_t xenheap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t xenheap_mfn_end __read_mostly;
vaddr_t xenheap_virt_end __read_mostly;
vaddr_t xenheap_virt_start __read_mostly;

/* Limits of frametable */
unsigned long frametable_virt_end __read_mostly;
unsigned long frametable_base_pdx;


/*
 * xen_second_pagetable is indexed with the VPN[2] page table entry field
 * xen_first_pagetable is accessed from the VPN[1] page table entry field
 * xen_zeroeth_pagetable is accessed from the VPN[0] page table entry field
 */
unsigned long xen_second_pagetable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static unsigned long xen_first_pagetable[PAGE_ENTRIES * 2] __attribute__((__aligned__(4096*2)));
static unsigned long xen_zeroeth_pagetable[PAGE_ENTRIES * 2] __attribute__((__aligned__(4096)));

/* Used by _setup_initial_pagetables() */
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

unsigned long xen_start;
unsigned long xen_end;

static paddr_t phys_offset;
unsigned long max_page;
unsigned long total_pages;

void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
}

static inline pte_t mfn_to_xen_entry(mfn_t mfn, unsigned attr)
{
	pte_t pte;

	pte.pte = _PAGE_PRESENT | _PAGE_READ | _PAGE_WRITE | _PAGE_EXEC;

	return pte;
}

static inline pte_t pte_of_xenaddr(vaddr_t va)
{
    paddr_t ma = va + phys_offset;

    return mfn_to_xen_entry(maddr_to_mfn(ma), MT_NORMAL);
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, mfn_t mfn, unsigned int flags)
{

}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{

}

void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    void *v = map_domain_page(_mfn(mfn));

    unmap_domain_page(v);

    /*
     * For some of the instruction cache (such as VIPT), the entire I-Cache
     * needs to be flushed to guarantee that all the aliases of a given
     * physical address will be removed from the cache.
     * Invalidating the I-Cache by VA highly depends on the behavior of the
     * I-Cache (See D4.9.2 in ARM DDI 0487A.k_iss10775). Instead of using flush
     * by VA on select platforms, we just flush the entire cache here.
     */
    if ( sync_icache )
        invalidate_icache();
}

enum xenmap_operation {
    INSERT,
    REMOVE,
    MODIFY,
    RESERVE
};

static int create_xen_entries(enum xenmap_operation op,
                              unsigned long virt,
                              mfn_t mfn,
                              unsigned long nr_mfns,
                              unsigned int flags)
{
    int rc = 0;

    /* TODO */

    return rc;
}

int map_pages_to_xen(unsigned long virt,
                     mfn_t mfn,
                     unsigned long nr_mfns,
                     unsigned int flags)
{
    return create_xen_entries(INSERT, virt, mfn, nr_mfns, flags);
}

int populate_pt_range(unsigned long virt, unsigned long nr_mfns)
{
    return create_xen_entries(RESERVE, virt, INVALID_MFN, nr_mfns, 0);
}

int destroy_xen_mappings(unsigned long v, unsigned long e)
{
    return create_xen_entries(REMOVE, v, INVALID_MFN, (e - v) >> PAGE_SHIFT, 0);
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int flags)
{
    return create_xen_entries(MODIFY, s, INVALID_MFN, (e - s) >> PAGE_SHIFT,
                              flags);
}

void arch_dump_shared_mem_info(void)
{
}

int donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    ASSERT_UNREACHABLE();
    return -ENOSYS;
}

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -EOPNOTSUPP;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT_UNREACHABLE();
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    return gfn_x(d->arch.p2m.max_mapped_gfn);
}

void share_xen_page_with_guest(struct page_info *page, struct domain *d,
                               enum XENSHARE_flags flags)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

   	/* TODO */

    spin_unlock(&d->page_alloc_lock);
}

int xenmem_add_to_physmap_one(
    struct domain *d,
    unsigned int space,
    union xen_add_to_physmap_batch_extra extra,
    unsigned long idx,
    gfn_t gfn)
{
	/* TODO */

	return 0;
}

long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    return 0;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + 1) & PGC_count_mask) <= 1) )
            return NULL;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}

void put_page(struct page_info *page)
{
    unsigned long nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) != 0);
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        free_domheap_page(page);
    }
}

int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( owner != NULL )
        put_page(page);

    return 0;
}

/* Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy. */
int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

void put_page_type(struct page_info *page)
{
    return;
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void *ioremap_attr(paddr_t pa, size_t len, unsigned int attributes)
{
    mfn_t mfn = _mfn(PFN_DOWN(pa));
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);
    void *ptr = __vmap(&mfn, nr, 1, 1, attributes, VMAP_DEFAULT);

    if ( ptr == NULL )
        return NULL;

    return ptr + offs;
}

void *ioremap(paddr_t pa, size_t len)
{
    return ioremap_attr(pa, len, PAGE_HYPERVISOR_NOCACHE);
}

void gnttab_clear_flags(struct domain *d, unsigned long nr, uint16_t *addr)
{
    /*
     * Note that this cannot be clear_bit(), as the access must be
     * confined to the specified 2 bytes.
     */
    uint16_t mask = ~(1 << nr), old;

    do {
        old = *addr;
    } while (cmpxchg(addr, old, old & mask) != old);
}

void gnttab_mark_dirty(struct domain *d, mfn_t mfn)
{
    /* XXX: mark dirty */
    static int warning;
    if (!warning) {
        gdprintk(XENLOG_WARNING, "gnttab_mark_dirty not implemented yet\n");
        warning = 1;
    }
}

int create_grant_host_mapping(unsigned long addr, mfn_t frame,
                              unsigned int flags, unsigned int cache_flags)
{
    int rc;
    p2m_type_t t = p2m_grant_map_rw;

    if ( cache_flags  || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        t = p2m_grant_map_ro;

    rc = guest_physmap_add_entry(current->domain, gaddr_to_gfn(addr),
                                 frame, 0, t);

    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_host_mapping(unsigned long addr, mfn_t mfn,
                               unsigned long new_addr, unsigned int flags)
{
    gfn_t gfn = gaddr_to_gfn(addr);
    struct domain *d = current->domain;
    int rc;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    rc = guest_physmap_remove_page(d, gfn, mfn, 0);

    return rc ? GNTST_general_error : GNTST_okay;
}

bool is_iomem_page(mfn_t mfn)
{
    return !mfn_valid(mfn);
}

unsigned long get_upper_mfn_bound(void)
{
    /* No memory hotplug yet, so current memory limit is the final one. */
    return max_page - 1;
}

void setup_pagetables(unsigned long boot_phys_offset)
{
    (void) boot_phys_offset;

    /* TODO */
}



/* Creates megapages of 2MB size based on sv39 spec */
void setup_gigapages(
                    unsigned long virtual_start, 
                    unsigned long physical_start,
                    unsigned long page_cnt)
{
    unsigned long frame_addr = physical_start;
    unsigned long end = physical_start + (page_cnt << PAGE_SHIFT);
    unsigned long vaddr = virtual_start;
    unsigned long pte;
    unsigned long index2;
    //unsigned long index1;

    while(frame_addr < end) {
        index2 = (vaddr & PGTBL_L2_INDEX_MASK) >> PGTBL_L2_INDEX_SHIFT;
        
        /* Setup gigapage level2 table */
        pte = frame_addr;

        /* Align ppn */
        pte &= PGTBL_L2_MAP_MASK;

        /* Shifts to turn into pte */
        pte =  (pte >> PGTBL_PAGE_SIZE_SHIFT) << PGTBL_PTE_ADDR_SHIFT;
        pte |= PGTBL_PTE_VALID_MASK;
        pte |= PGTBL_PTE_EXECUTE_MASK;
        pte |= PGTBL_PTE_WRITE_MASK;
        pte |= PGTBL_PTE_READ_MASK;
        xen_second_pagetable[index2] = pte;

        frame_addr += PGTBL_L2_BLOCK_SIZE;
        vaddr += PGTBL_L2_BLOCK_SIZE;
    }

    asm volatile ("sfence.vma");
}

void setup_xenheap_mappings(unsigned long heap_start, unsigned long page_cnt)
{
    setup_gigapages(
                    XENHEAP_VIRT_START, 
                    heap_start,
                    page_cnt);

    xenheap_virt_end = XENHEAP_VIRT_START + (page_cnt * PAGE_SIZE);
    xenheap_mfn_start = _mfn(heap_start >> PAGE_SHIFT);
    xenheap_mfn_end = _mfn((heap_start >> PAGE_SHIFT) + page_cnt);
}

void __init clear_pagetables(unsigned long load_addr, unsigned long linker_addr)
{
    unsigned long *p;
    unsigned long page;
    unsigned long i;

    page = (unsigned long)&xen_second_pagetable[0];
    p = (unsigned long *)(page + load_addr - linker_addr);
    for (i=0; i<ARRAY_SIZE(xen_second_pagetable); i++) {
        p[i] = 0ULL;
    }

    page = (unsigned long)&xen_first_pagetable[0];
    p = (unsigned long *)(page + load_addr - linker_addr);
    for (i=0; i<ARRAY_SIZE(xen_first_pagetable); i++) {
        p[i] = 0ULL;
    }

    page = (unsigned long)&xen_zeroeth_pagetable[0];
    p = (unsigned long *)(page + load_addr - linker_addr);
    for (i=0; i<ARRAY_SIZE(xen_zeroeth_pagetable); i++) {
        p[i] = 0ULL;
    }
}

void __attribute__ ((section(".entry")))
setup_initial_pagetables(unsigned long *second,
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
        index2 = (page_addr & PGTBL_L2_INDEX_MASK) >> PGTBL_L2_INDEX_SHIFT;
        index1 = (page_addr & PGTBL_L1_INDEX_MASK) >> PGTBL_L1_INDEX_SHIFT;
        index0 = (page_addr & PGTBL_L0_INDEX_MASK) >> PGTBL_L0_INDEX_SHIFT;

        /* Setup level2 table */
        second[index2] = (unsigned long) &first[index1];
        second[index2] = second[index2] >> PGTBL_PAGE_SIZE_SHIFT;
        second[index2] = second[index2] << PGTBL_PTE_ADDR_SHIFT;
        second[index2] |= PGTBL_PTE_VALID_MASK;

        /* Setup level1 table */
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

/* Note: load_addr() and linker_addr() are to be called only when the MMU is disabled 
 * and only when executing from the primary CPU.
 *
 * Note: This functions cannot refer to any global variable &
 * functions to ensure that it can execute from anywhere.
 */

/* Convert an addressed layed out at link time to the address where it was loaded
 * by the bootloader.
 */
#define load_addr(linker_address)	({ \
			unsigned long __linker_address = (unsigned long) (linker_address); \
			if (linker_addr_start <= __linker_address && __linker_address < linker_addr_end) { \
				__linker_address = __linker_address - linker_addr_start + load_addr_start; \
			} \
			__linker_address; \
			})

/* Convert boot-time Xen address from where it was loaded by the boot loader to the address it was layed out
 * at link-time.
 */
#define linker_addr(load_address)       ({ \
			unsigned long __load_address = (unsigned long) (load_address); \
			if (load_addr_start <= __load_address && __load_address < load_addr_end) { \
				__load_address = __load_address - load_addr_start + linker_addr_start; \
			} \
			__load_address; \
			})

/*
 * 1) Build the page tables for Xen that map the following:
 *   1.1)  The physical location of Xen (where the bootloader loaded it)
 *   1.2)  The link-time location of Xen (where linker expected Xen's
 *         addresses to be)
 * 2) Load the page table into the SATP and enable the MMU
 */
void __attribute__ ((section(".entry")))
    _setup_initial_pagetables(unsigned long load_addr_start, unsigned long load_addr_end,
			 unsigned long linker_addr_start, unsigned long linker_addr_end)
{
    unsigned long *second;
    unsigned long *first;
    unsigned long *zeroeth;

    clear_pagetables(load_addr_start, linker_addr_start);

    /* Get the addresses where the page tables were loaded */
    second = (unsigned long *)load_addr(&xen_second_pagetable);
    first = (unsigned long *)load_addr(&xen_first_pagetable);
    zeroeth = (unsigned long *)load_addr(&xen_zeroeth_pagetable);

    /* Create a mapping of the load time address range to... the load time address range.
     * This mapping is used at boot time only.
     */
    setup_initial_pagetables(second, first, zeroeth, load_addr_start, load_addr_end, load_addr_start);

    /* Create a mapping of all of Xen's link-time addresses to where they were actually loaded.
     * This mapping is used at runtime.
     */
    setup_initial_pagetables(second, first, zeroeth, 
                       linker_addr(&_text_start),
                       linker_addr(&_text_end),
                       load_addr(&_text_start));
    setup_initial_pagetables(second, first, zeroeth,
                       linker_addr(&_init_start),
                       linker_addr(&_init_end),
                       load_addr(&_init_start));
    setup_initial_pagetables(second, first, zeroeth,
                       linker_addr(&_cpuinit_start),
                       linker_addr(&_cpuinit_end),
                       load_addr(&_cpuinit_start));
    setup_initial_pagetables(second, first, zeroeth,
                       linker_addr(&_spinlock_start),
                       linker_addr(&_spinlock_end),
                       load_addr(&_spinlock_start));
    setup_initial_pagetables(second, first, zeroeth,
                       linker_addr(&_rodata_start),
                       linker_addr(&_rodata_end),
                       load_addr(&_rodata_start));
    setup_initial_pagetables(second, first, zeroeth, linker_addr_start, linker_addr_end, load_addr_start);

    /* Ensure page table writes precede loading the SATP */
    asm volatile ("sfence.vma");

    /* Enable the MMU and load the pagetable */
    csr_write(satp, (load_addr(xen_second_pagetable) >> PAGE_SHIFT) | SATP_MODE);

    xen_start = load_addr_start;
    xen_end = load_addr_end;
}

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long nr_pdxs = mfn_to_pdx(mfn_add(maddr_to_mfn(pe), -1)) -
                            mfn_to_pdx(maddr_to_mfn(ps)) + 1;
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    mfn_t base_mfn;

    frametable_base_pdx = mfn_to_pdx(maddr_to_mfn(ps));
    /* Megapages for sv39 are 2MB so round up to 2MB */
    frametable_size = ROUNDUP(frametable_size, 2 << 20);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 2<<(20-12));

/*
    create_mappings(xen_second, FRAMETABLE_VIRT_START, mfn_x(base_mfn),
                    frametable_size >> PAGE_SHIFT, mapping_size);
*/
    setup_gigapages(FRAMETABLE_VIRT_START,
                    ((unsigned long) mfn_x(base_mfn)) << PAGE_SHIFT, nr_pdxs);

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs * sizeof(struct page_info));
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
