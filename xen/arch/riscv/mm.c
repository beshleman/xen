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

#ifdef NDEBUG
static inline void
__attribute__ ((__format__ (__printf__, 1, 2)))
mm_printk(const char *fmt, ...) {}
#else
#define mm_printk(fmt, args...)             \
    do                                      \
    {                                       \
        dprintk(XENLOG_ERR, fmt, ## args);  \
        WARN();                             \
    } while (0);
#endif

#define XEN_TABLE_MAP_FAILED 0
#define XEN_TABLE_SUPER_PAGE 1
#define XEN_TABLE_NORMAL_PAGE 2

#define DECLARE_OFFSETS(var, addr)          \
    const unsigned int var[4] = {           \
        pagetable_zeroeth_index(addr),          \
        pagetable_first_index(addr),            \
        pagetable_second_index(addr),           \
        pagetable_third_index(addr),            \
    }

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
pte_t xen_second_pagetable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static pte_t xen_first_pagetable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static pte_t xen_zeroeth_pagetable[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static pte_t xen_heap_megapages[PAGE_ENTRIES] __attribute__((__aligned__(4096)));
static pte_t xen_domheap_megapages[PAGE_ENTRIES] __attribute__((__aligned__(4096)));

#define THIS_CPU_PGTABLE xen_second_pagetable

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
unsigned long xen_link_start;
unsigned long xen_link_end;

paddr_t phys_offset;
unsigned long max_page;
unsigned long total_pages;

static inline pte_t mfn_to_pte(mfn_t mfn)
{
   return (pte_t) { .pte = mfn_x(mfn) };
}


void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
}

static inline pte_t mfn_to_xen_entry(mfn_t mfn)
{
    return mfn_to_pte(mfn);
}

static inline pte_t pte_of_xenaddr(vaddr_t va)
{
    paddr_t ma = va + phys_offset;

    return mfn_to_xen_entry(maddr_to_mfn(ma));
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, mfn_t mfn, unsigned int flags)
{

}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{

}

#ifdef CONFIG_DOMAIN_PAGE
void *map_domain_page_global(mfn_t mfn)
{
    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *va)
{
    vunmap(va);
}

/* Map a page of domheap memory */
void *map_domain_page(mfn_t mfn)
{
    unsigned long flags;
    pte_t *map = this_cpu(xen_dommap);
    unsigned long slot_mfn = mfn_x(mfn) & ~PAGE_MASK;
    vaddr_t va;
    pte_t pte;
    int i, slot;

    local_irq_save(flags);

    /* TODO:  implement a scheme to prevent re-mapping already
     * used pages.  ARM uses a scheme where they use unused bits
     * in the PTE to store a reference count and use that reference count
     * to determine availability, see the lpae_t field `avail`.  We
     * do not have extra bits in RISC-V sv39 (the reserved bits are to be 
     * zeroed to ensure forward compatibility, so another approach will
     * be necessary.  This must also be reflected in unmap_domain_page().
     */     
    for ( slot = (slot_mfn >> PAGE_SHIFT) % DOMHEAP_ENTRIES, i = 0;
          i < DOMHEAP_ENTRIES;
          slot = (slot + 1) % DOMHEAP_ENTRIES, i++ )
    {
            /* Commandeer this 2MB slot */
            pte = mfn_to_xen_entry(_mfn(slot_mfn));
            write_pte(map + slot, pte);
            break;
    }
    /* If the map fills up, the callers have misbehaved. */
    BUG_ON(i == DOMHEAP_ENTRIES);

    local_irq_restore(flags);

    va = (DOMHEAP_VIRT_START
          + (slot << PGTBL_L1_INDEX_SHIFT)
          + ((mfn_x(mfn) & PAGE_MASK) << PAGE_SHIFT));

    /*
     * TODO: use page-specific flushing
     */
    asm volatile ("sfence.vma");

    return (void *)va;
}

/* Release a mapping taken with map_domain_page() */
void unmap_domain_page(const void *va)
{
    unsigned long flags;
    pte_t *map = this_cpu(xen_dommap);
    int slot = ((unsigned long) va - DOMHEAP_VIRT_START) >> PGTBL_L1_INDEX_SHIFT;

    local_irq_save(flags);

    /* TODO: see the comment about map_domain_page() about designing an
     * alternative to reference counting */

    local_irq_restore(flags);
}

mfn_t domain_page_map_to_mfn(const void *ptr)
{
    (void) ptr;
    
    /* TODO */

    return (mfn_t) 0xDEADBEEF;
}
#endif

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

static int create_xen_table(pte_t *entry)
{
    void *p;
    pte_t pte;

    p = alloc_xenheap_page();
    if ( p == NULL )
        return -ENOMEM;

    clear_page(p);
    pte = mfn_to_xen_entry(maddr_to_mfn((unsigned long)p));
    pte.pte |= PTE_DEFAULT;

    /* Entries pointing to tables have their permissions set to 0 */
    write_pte(entry, pte);
    return 0;
}


static pte_t *xen_map_table(mfn_t mfn)
{
    return map_domain_page(mfn);
}

static void xen_unmap_table(const pte_t *table)
{
    unmap_domain_page(table);
}

/*
 * Take the currently mapped table, find the corresponding entry,
 * and map the next table, if available.
 *
 * The read_only parameters indicates whether intermediate tables should
 * be allocated when not present.
 *
 * Return values:
 *  XEN_TABLE_MAP_FAILED: Either read_only was set and the entry
 *  was empty, or allocating a new page failed.
 *  XEN_TABLE_NORMAL_PAGE: next level mapped normally
 *  XEN_TABLE_SUPER_PAGE: The next entry points to a superpage.
 */
static int xen_pt_next_level(unsigned int level,
                             pte_t **table, unsigned int offset)
{
    pte_t *entry;
    int ret;

    entry = *table + offset;

    if ( !pte_is_valid(entry) )
    {

/* TODO */
#if 0
        if ( read_only )
            return XEN_TABLE_MAP_FAILED;
#endif

        ret = create_xen_table(entry);
        if ( ret )
            return XEN_TABLE_MAP_FAILED;
    }

/* TODO */
#if 0
    /* The function xen_pt_next_level is never called at the 3rd level */
    if ( lpae_is_mapping(*entry, level) )
        return XEN_TABLE_SUPER_PAGE;
#endif

    xen_unmap_table(*table);
    *table = xen_map_table(pte_get_mfn(*entry));

    return XEN_TABLE_NORMAL_PAGE;
}

static bool xen_pt_check_entry(pte_t entry, mfn_t mfn, unsigned int flags)
{
    (void) entry;
    (void) mfn;
    (void) flags;

    /* TODO */

    return true;
}

static int xen_pt_update_entry(mfn_t root, unsigned long virt,
                               mfn_t mfn, unsigned int flags)
{
    int rc;
    unsigned int level;
    /* We only support 4KB mapping (i.e level 3) for now */
    unsigned int target = 3;
    pte_t *table;
    pte_t pte, *entry;

    /* convenience aliases */
    DECLARE_OFFSETS(offsets, (paddr_t)virt);

    table = xen_map_table(root);
    for (level = 3; level > 0; level--)
    {
        rc = xen_pt_next_level(level, &table, offsets[level]);
        if (rc == XEN_TABLE_MAP_FAILED)
        {
            /*
             * We are here because xen_pt_next_level has failed to map
             * the intermediate page table (e.g the table does not exist
             * and the pt is read-only). It is a valid case when
             * removing a mapping as it may not exist in the page table.
             * In this case, just ignore it.
             */
            if ( flags & _PAGE_PRESENT )
            {
                mm_printk("%s: Unable to map level %u\n", __func__, level);
                rc = -ENOENT;
                goto out;
            }
            else
            {
                rc = 0;
                goto out;
            }
        }
        else if (rc != XEN_TABLE_NORMAL_PAGE)
            break;
    }

    if (level != target)
    {
        mm_printk("%s: Shattering superpage is not supported\n", __func__);
        rc = -EOPNOTSUPP;
        goto out;
    }

    entry = table + offsets[level];

    rc = -EINVAL;
    if ( !xen_pt_check_entry(*entry, mfn, flags) )
        goto out;


#if 0
    /* We are removing the page */
    if ( !(flags & _PAGE_PRESENT) )
        memset(&pte, 0x00, sizeof(pte));
    else
    {
        /* We are inserting a mapping => Create new pte. */
        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            pte = mfn_to_xen_entry(mfn, PAGE_AI_MASK(flags));

            /* Third level entries set pte.pt.table = 1 */
            pte.pt.table = 1;
        }
        else /* We are updating the permission => Copy the current pte. */
            pte = *entry;

        /* Set permission */
        pte.pt.ro = PAGE_RO_MASK(flags);
        pte.pt.xn = PAGE_XN_MASK(flags);
    }
#endif

    write_pte(entry, pte);

    rc = 0;

out:
    xen_unmap_table(table);

    return rc;
}

static DEFINE_SPINLOCK(xen_pt_lock);

static int create_xen_entries(enum xenmap_operation op,
                              unsigned long virt,
                              mfn_t mfn,
                              unsigned long nr_mfns,
                              unsigned int flags)
{
    int rc = 0;
    unsigned long addr = virt, addr_end = addr + nr_mfns * PAGE_SIZE;

    /*
     * TODO: research if this comment describes our approach with RISC-V
     *
     * For arm32, page-tables are different on each CPUs. Yet, they share
     * some common mappings. It is assumed that only common mappings
     * will be modified with this function.
     *
     * XXX: Add a check.
     */
    const mfn_t root = _mfn(virt_to_mfn(THIS_CPU_PGTABLE));

    switch (op) {
    case INSERT:
        break;
    default:
        rc = 1;
        break;
    }

    if ( !IS_ALIGNED(virt, PAGE_SIZE) )
    {
        mm_printk("The virtual address is not aligned to the page-size.\n");
        return -EINVAL;
    }

    spin_lock(&xen_pt_lock);

    for ( ; addr < addr_end; addr += PAGE_SIZE )
    {
        rc = xen_pt_update_entry(root, addr, mfn, flags);
        if ( rc )
            break;

        if ( !mfn_eq(mfn, INVALID_MFN) )
            mfn = mfn_add(mfn, 1);
    }

    /*
     * Flush the TLBs even in case of failure because we may have
     * partially modified the PT. This will prevent any unexpected
     * behavior afterwards.
     *
     * TODO: look into PTE-based sfence.vma instead of this one
     */
    asm volatile ("sfence.vma");

    spin_unlock(&xen_pt_lock);

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

/* Creates megapages of 2MB size based on sv39 spec */
/* TODO: make page_cnt not expect 4KB pages, change to 2MB pages? */
 void setup_heap_megapages(unsigned long virtual_start, 
                           unsigned long physical_start,
                           unsigned long page_cnt)
{
    unsigned long frame_addr = physical_start;
    unsigned long end = physical_start + (page_cnt << PAGE_SHIFT);
    unsigned long vaddr = virtual_start;
    unsigned long paddr;
    unsigned long index;
    pte_t *p;

    /* TODO: BUG_ON physical start is not megapage aligned */

    paddr = phys_offset + ((unsigned long)xen_heap_megapages);
    index = pagetable_second_index(vaddr);
    p = &xen_second_pagetable[index];
    p->pte = addr_to_ppn(paddr);
    p->pte |= PTE_VALID;

    while(frame_addr < end) {
        index = pagetable_first_index(vaddr);
        p = &xen_heap_megapages[index];
        p->pte = paddr_to_megapage_ppn(frame_addr);
        p->pte |= PTE_DEFAULT;

        frame_addr += PGTBL_L1_BLOCK_SIZE;
        vaddr += PGTBL_L1_BLOCK_SIZE;
    }

    asm volatile ("sfence.vma");
}

/* Creates gigapages of 1GB size based on sv39 spec */
/* TODO: make page_cnt not expect 4KB pages, change to 1GB pages? */
 void setup_gigapages(unsigned long virtual_start, 
                      unsigned long physical_start,
                      unsigned long page_cnt)
{
    unsigned long end = physical_start + (page_cnt << PAGE_SHIFT);
    unsigned long frame_addr = physical_start;
    unsigned long vaddr = virtual_start;
    pte_t *p;

    /* TODO: BUG_ON physical_start not aligned */
    while(frame_addr < end) {
        p = &xen_second_pagetable[pagetable_second_index(vaddr)];
        p->pte = paddr_to_gigapage_ppn(frame_addr);
        p->pte |= PTE_DEFAULT;

        frame_addr += PGTBL_L2_BLOCK_SIZE;
        vaddr += PGTBL_L2_BLOCK_SIZE;
    }

    asm volatile ("sfence.vma");
}

void setup_xenheap_mappings(unsigned long heap_start, unsigned long page_cnt)
{
    setup_heap_megapages(XENHEAP_VIRT_START, 
                         heap_start,
                         page_cnt);

    xenheap_virt_end = XENHEAP_VIRT_START + (page_cnt * PAGE_SIZE);
    xenheap_mfn_start = _mfn(heap_start >> PAGE_SHIFT);
    xenheap_mfn_end = _mfn((heap_start >> PAGE_SHIFT) + page_cnt);
}

void setup_domheap_pagetables(void)
{

    (void)xen_domheap_megapages;
}

void setup_pagetables(unsigned long boot_phys_offset)
{
    (void) boot_phys_offset;

    /* TODO */
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
setup_initial_pagetables(pte_t *second,
                         pte_t *first,
                         pte_t *zeroeth,
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
        index2 = pagetable_second_index(page_addr);
        index1 = pagetable_first_index(page_addr);
        index0 = pagetable_zeroeth_index(page_addr);

        /* Setup level2 table */
        second[index2] = paddr_to_pte((unsigned long) &first[index1]);
        second[index2].pte |= PTE_VALID;

        /* Setup level1 table */
        first[index1] = paddr_to_pte((unsigned long) &zeroeth[index0]);
        first[index1].pte |= PTE_VALID;

        /* Setup level0 table */
        if (!(zeroeth[index0].pte & PGTBL_PTE_VALID_MASK)) {
                /* Update level0 table */
                zeroeth[index0] = paddr_to_pte((page_addr - map_start) + pa_start);
                zeroeth[index0].pte |= PTE_DEFAULT;
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
    pte_t *second;
    pte_t *first;
    pte_t *zeroeth;

    clear_pagetables(load_addr_start, linker_addr_start);

    /* Get the addresses where the page tables were loaded */
    second = (pte_t *) load_addr(&xen_second_pagetable);
    first = (pte_t *) load_addr(&xen_first_pagetable);
    zeroeth = (pte_t *) load_addr(&xen_zeroeth_pagetable);

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
    xen_link_start = linker_addr_start;
    xen_link_end = linker_addr_end;

    phys_offset = load_addr_start > linker_addr_start
                    ? load_addr_start - linker_addr_start
                    : linker_addr_start - load_addr_start;
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
