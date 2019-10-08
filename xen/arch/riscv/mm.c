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

unsigned long frametable_virt_end __read_mostly;

pte_t boot_pgtable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
pte_t boot_first[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
pte_t boot_first_id[PAGE_ENTRIES] __attribute__((__aligned__(4096)));

/* Limits of the Xen heap */
mfn_t xenheap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t xenheap_mfn_end __read_mostly;
vaddr_t xenheap_virt_end __read_mostly;
vaddr_t xenheap_virt_start __read_mostly;

/* This needs to be set by the address at which the bootloade has loaded Xen */
static paddr_t phys_offset;

unsigned long max_page;
unsigned long total_pages;

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

void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
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

void xen_pt_update_entry_to_addr(unsigned long vaddr, unsigned long paddr)
{
    (void) vaddr;
    (void) paddr;
}

void xen_pt_identity_map(unsigned long vaddr)
{
    xen_pt_update_entry_to_addr(vaddr, vaddr);
}

void __init setup_xenheap_mappings(unsigned long heap_start, unsigned long nr_frames)
{
    unsigned long i;
    unsigned long vaddr = 0;
    unsigned long paddr = heap_start;

    for (i=0; i<nr_frames; i++) {
        vaddr =  (i << PAGE_SHIFT) + XENHEAP_VIRT_START;
        paddr +=  i << PAGE_SHIFT;
        vaddr = paddr + XENHEAP_VIRT_START;
        xen_pt_update_entry_to_addr(vaddr, paddr);
    }

    BUG_ON(vaddr == 0);

    /* Record where the xenheap is, for translation routines. */
    xenheap_virt_end = vaddr;
    xenheap_mfn_start = _mfn(heap_start >> PAGE_SHIFT);
    xenheap_mfn_end = _mfn(paddr >> PAGE_SHIFT);
}

/* Map a frame table to cover physical addresses ps through pe */
void __init setup_frametable_mappings(paddr_t ps, paddr_t pe)
{
    unsigned long i;
    unsigned long paddr, vaddr;
    unsigned long nr_pdxs = mfn_to_pdx(mfn_add(maddr_to_mfn(pe), -1)) -
                            mfn_to_pdx(maddr_to_mfn(ps)) + 1;
    unsigned long frametable_size = nr_pdxs * sizeof(struct page_info);
    mfn_t base_mfn;
    const unsigned long mapping_size = frametable_size < MB(32) ? MB(2) : MB(32);

    /* Round up to 2M or 32M boundary, as appropriate. */
    frametable_size = ROUNDUP(frametable_size, mapping_size);
    base_mfn = alloc_boot_pages(frametable_size >> PAGE_SHIFT, 32<<(20-12));
    
    for (i=0; i<nr_pdxs; i = i + PAGE_SIZE) {
        vaddr =  i + XENHEAP_VIRT_START;
        paddr =  base_mfn.mfn + XENHEAP_VIRT_START;
        xen_pt_update_entry_to_addr(vaddr, paddr);
    }

/*
    create_mappings(FRAMETABLE_VIRT_START, mfn_x(base_mfn),
                    frametable_size >> PAGE_SHIFT);
*/

    memset(&frame_table[0], 0, nr_pdxs * sizeof(struct page_info));
    memset(&frame_table[nr_pdxs], -1,
           frametable_size - (nr_pdxs * sizeof(struct page_info)));

    frametable_virt_end = FRAMETABLE_VIRT_START + (nr_pdxs * sizeof(struct page_info));
}

/**
 * Build the page tables up starting with the zeroeth table, then the first, then second.
 * The zeroeth table will hold the physical frame numbers point to the Xen executable.
 */
void __init __setup_pagetables(unsigned long boot_phys_offset)
{
    (void) boot_phys_offset;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
