#include <xen/compile.h>
#include <asm/page.h>

#define sym_offs(sym)     ((sym) - __XEN_VIRT_START)

        .section .efi.pe.header, "a", @progbits

GLOBAL(efi_pe_head)
        /*
         * Legacy EXE header.
         *
         * Most of it is copied from binutils package, version 2.30,
         * include/coff/pe.h:struct external_PEI_filehdr and
         * bfd/peXXigen.c:_bfd_XXi_only_swap_filehdr_out().
         *
         * Page is equal 512 bytes here.
         * Paragraph is equal 16 bytes here.
         */
        .short  0x5a4d                               /* EXE magic number. */
        .short  0x90                                 /* Bytes on last page of file. */
        .short  0x3                                  /* Pages in file. */
        .short  0                                    /* Relocations. */
        .short  0x4                                  /* Size of header in paragraphs. */
        .short  0                                    /* Minimum extra paragraphs needed. */
        .short  0xffff                               /* Maximum extra paragraphs needed. */
        .short  0                                    /* Initial (relative) SS value. */
        .short  0xb8                                 /* Initial SP value. */
        .short  0                                    /* Checksum. */
        .short  0                                    /* Initial IP value. */
        .short  0                                    /* Initial (relative) CS value. */
        .short  0x40                                 /* File address of relocation table. */
        .short  0                                    /* Overlay number. */
        .fill   4, 2, 0                              /* Reserved words. */
        .short  0                                    /* OEM identifier. */
        .short  0                                    /* OEM information. */
        .fill   10, 2, 0                             /* Reserved words. */
        .long   Lpe_header - efi_pe_head             /* File address of the PE header. */

Lpe_header:
        /*
         * PE/COFF header.
         *
         * The PE/COFF format is defined by Microsoft, and is available from
         * https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
         *
         * Some ideas are taken from Linux kernel and Xen ARM64.
         */
        .ascii  "PE\0\0"                             /* PE signature. */
        .short  0x8664                               /* Machine: IMAGE_FILE_MACHINE_AMD64 */
        .short  1                                    /* NumberOfSections. */
        .long   XEN_COMPILE_POSIX_TIME               /* TimeDateStamp. */
        .long   0                                    /* PointerToSymbolTable. */
        .long   0                                    /* NumberOfSymbols. */
        .short  Lsection_table - Loptional_header      /* SizeOfOptionalHeader. */
        .short  0x226                                /* Characteristics:
                                                      *   IMAGE_FILE_EXECUTABLE_IMAGE |
                                                      *   IMAGE_FILE_LARGE_ADDRESS_AWARE |
                                                      *   IMAGE_FILE_DEBUG_STRIPPED |
                                                      *   IMAGE_FILE_LINE_NUMS_STRIPPED
                                                      */

Loptional_header:
        .short  0x20b                                /* PE format: PE32+ */
        .byte   0                                    /* MajorLinkerVersion. */
        .byte   0                                    /* MinorLinkerVersion. */
        .long   __2M_rwdata_end - efi_pe_head_end    /* SizeOfCode. */
        .long   0                                    /* SizeOfInitializedData. */
        .long   0                                    /* SizeOfUninitializedData. */
        .long   sym_offs(efi_mb_start)               /* AddressOfEntryPoint. */
        .long   sym_offs(start)                      /* BaseOfCode. */
        .quad   sym_offs(__image_base__)             /* ImageBase. */
        .long   XEN_LOAD_ALIGN                       /* SectionAlignment. */
        .long   XEN_FILE_ALIGN                       /* FileAlignment. */
        .short  2                                    /* MajorOperatingSystemVersion. */
        .short  0                                    /* MinorOperatingSystemVersion. */
        .short  XEN_VERSION                          /* MajorImageVersion. */
        .short  XEN_SUBVERSION                       /* MinorImageVersion. */
        .short  2                                    /* MajorSubsystemVersion. */
        .short  0                                    /* MinorSubsystemVersion. */
        .long   0                                    /* Win32VersionValue. */
        .long   __pe_SizeOfImage                     /* SizeOfImage. */
        .long   efi_pe_head_end - efi_pe_head        /* SizeOfHeaders. */
        .long   0                                    /* CheckSum. */
        .short  0xa                                  /* Subsystem: EFI application. */
        .short  0                                    /* DllCharacteristics. */
        .quad   0                                    /* SizeOfStackReserve. */
        .quad   0                                    /* SizeOfStackCommit. */
        .quad   0                                    /* SizeOfHeapReserve. */
        .quad   0                                    /* SizeOfHeapCommit. */
        .long   0                                    /* LoaderFlags. */
        .long   0x6                                  /* NumberOfRvaAndSizes. */

        /* Data Directories. */
        .quad   0                                    /* Export Table. */
        .quad   0                                    /* Import Table. */
        .quad   0                                    /* Resource Table. */
        .quad   0                                    /* Exception Table. */
        .quad   0                                    /* Certificate Table. */
        .quad   0                                    /* Base Relocation Table. */

Lsection_table:
        .ascii  ".text\0\0\0"                        /* Name. */
        .long   __2M_rwdata_end - efi_pe_head_end    /* VirtualSize. */
        .long   sym_offs(start)                      /* VirtualAddress. */
        .long   __pe_text_raw_end - efi_pe_head_end  /* SizeOfRawData. */
        .long   efi_pe_head_end - efi_pe_head        /* PointerToRawData. */
        .long   0                                    /* PointerToRelocations. */
        .long   0                                    /* PointerToLinenumbers. */
        .short  0                                    /* NumberOfRelocations. */
        .short  0                                    /* NumberOfLinenumbers. */
        .long   0xe0500020                           /* Characteristics:
                                                      *   IMAGE_SCN_CNT_CODE |
                                                      *   IMAGE_SCN_ALIGN_16BYTES |
                                                      *   IMAGE_SCN_MEM_EXECUTE |
                                                      *   IMAGE_SCN_MEM_READ |
                                                      *   IMAGE_SCN_MEM_WRITE
                                                      */

        .align XEN_FILE_ALIGN
GLOBAL(efi_pe_head_end)

        .text

