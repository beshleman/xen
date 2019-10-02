#ifndef _RISCV_GUEST_ATOMICS_H
#define _RISCV_GUEST_ATOMICS_H

/*
 * TODO: implement guest atomics
 */
#define guest_set_bit(d, nr, p)         \
    do { \
        (void) d;       \
        (void) nr;      \
        (void) p;       \
    } while(0)

#define guest_clear_bit(d, nr, p)   \
    do { \
        (void) d;       \
        (void) nr;      \
        (void) p;       \
    } while(0)

#define guest_change_bit(d, nr, p)  (0)
#define guest_test_bit(d, nr, p)    (0)
#define guest_test_and_set_bit(d, nr, p) (0)
#define guest_test_and_clear_bit(d, nr, p) (0)
#define guest_test_and_change_bit(d, nr, p) (0)
#define guest_cmpxchg(d, ptr, o, n) (0)

#endif /* _RISCV_GUEST_ATOMICS_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
