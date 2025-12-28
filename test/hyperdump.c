/*
 * Hypercall 100 Register Dumper - Standalone Version
 * Executes hypercall 100 and dumps all CPU registers
 * Useful for VM escape research and hypervisor analysis
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>

/* KVM device path */
#define KVM_DEVICE "/dev/kvm"
#define KVM_PROBE_DEVICE "/dev/kvm_probe_dev"

/* Register structure */
struct register_dump {
    /* General Purpose Registers */
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip, rflags;
    
    /* Segment Registers */
    uint64_t cs, ds, es, fs, gs, ss;
    
    /* Control Registers */
    uint64_t cr0, cr2, cr3, cr4, cr8;
    
    /* Debug Registers */
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
    
    /* Model Specific Registers */
    uint64_t efer, star, lstar, cstar, sfmask;
    uint64_t kernel_gs_base, gs_base;
    uint64_t sysenter_cs, sysenter_esp, sysenter_eip;
    
    /* FPU/MMX/SSE registers */
    uint8_t fpu_state[512];
    uint8_t xmm[16][16];
    
    /* Hypervisor info */
    uint64_t hypercall_result;
    char hypervisor_signature[16];
    uint64_t hypervisor_base;
    
    /* Status flags */
    int vmexit_reason;
    int instruction_length;
    int error_code;
    int success;
};

/* Signal handler for illegal instructions */
static volatile int got_sigill = 0;
void sigill_handler(int sig) {
    got_sigill = 1;
    printf("[!] SIGILL caught - Hypercall not supported\n");
}

/* Print hex dump */
void hex_dump(const void *data, size_t size) {
    const unsigned char *bytes = (const unsigned char *)data;
    for (size_t i = 0; i < size; i += 16) {
        printf("%04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) printf("%02x ", bytes[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = bytes[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

/* Execute hypercall 100 and capture registers */
int execute_hypercall_100(struct register_dump *regs) {
    printf("[*] Preparing to execute hypercall 100 (vmcall/vmmcall)\n");
    
    /* Save original signal handler */
    struct sigaction old_sa, new_sa;
    sigaction(SIGILL, NULL, &old_sa);
    
    /* Set up SIGILL handler */
    new_sa = old_sa;
    new_sa.sa_handler = sigill_handler;
    new_sa.sa_flags = SA_RESTART;
    sigaction(SIGILL, &new_sa, NULL);
    
    /* Clear the flag */
    got_sigill = 0;
    
    printf("[*] Executing vmcall with RAX=100...\n");
    
    /* Execute hypercall 100 and capture as many registers as possible */
    asm volatile(
        /* Save general purpose registers */
        "push %%rbx\n\t"
        "push %%rcx\n\t"
        "push %%rdx\n\t"
        "push %%rsi\n\t"
        "push %%rdi\n\t"
        "push %%rbp\n\t"
        "push %%r8\n\t"
        "push %%r9\n\t"
        "push %%r10\n\t"
        "push %%r11\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        
        /* Execute hypercall 100 */
        "mov $100, %%rax\n\t"
        "vmcall\n\t"
        
        /* Capture return registers */
        "mov %%rax, %0\n\t"
        "mov %%rbx, %1\n\t"
        "mov %%rcx, %2\n\t"
        "mov %%rdx, %3\n\t"
        "mov %%rsi, %4\n\t"
        "mov %%rdi, %5\n\t"
        
        /* Restore general purpose registers */
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%r11\n\t"
        "pop %%r10\n\t"
        "pop %%r9\n\t"
        "pop %%r8\n\t"
        "pop %%rbp\n\t"
        "pop %%rdi\n\t"
        "pop %%rsi\n\t"
        "pop %%rdx\n\t"
        "pop %%rcx\n\t"
        "pop %%rbx\n\t"
        
        : "=m" (regs->rax), "=m" (regs->rbx), "=m" (regs->rcx),
          "=m" (regs->rdx), "=m" (regs->rsi), "=m" (regs->rdi)
        : 
        : "rax", "memory"
    );
    
    /* Capture other registers */
    asm volatile(
        "mov %%r8, %0\n\t"
        "mov %%r9, %1\n\t"
        "mov %%r10, %2\n\t"
        "mov %%r11, %3\n\t"
        "mov %%r12, %4\n\t"
        "mov %%r13, %5\n\t"
        "mov %%r14, %6\n\t"
        "mov %%r15, %7\n\t"
        : "=r" (regs->r8), "=r" (regs->r9), "=r" (regs->r10),
          "=r" (regs->r11), "=r" (regs->r12), "=r" (regs->r13),
          "=r" (regs->r14), "=r" (regs->r15)
        : 
    );
    
    asm volatile(
        "mov %%rbp, %0\n\t"
        "mov %%rsp, %1\n\t"
        "lea (%%rip), %2\n\t"
        "pushfq\n\t"
        "pop %3\n\t"
        : "=r" (regs->rbp), "=r" (regs->rsp), "=r" (regs->rip),
          "=r" (regs->rflags)
        : 
    );
    
    /* Try to get segment registers (some may be restricted) */
    asm volatile(
        "mov %%cs, %0\n\t"
        "mov %%ds, %1\n\t"
        "mov %%es, %2\n\t"
        "mov %%fs, %3\n\t"
        "mov %%gs, %4\n\t"
        "mov %%ss, %5\n\t"
        : "=r" (regs->cs), "=r" (regs->ds), "=r" (regs->es),
          "=r" (regs->fs), "=r" (regs->gs), "=r" (regs->ss)
        : 
    );
    
    /* Try to get control registers (may require kernel mode) */
    regs->cr0 = 0;
    regs->cr2 = 0;
    regs->cr3 = 0;
    regs->cr4 = 0;
    
    /* Check if we got SIGILL */
    regs->success = !got_sigill;
    regs->hypercall_result = regs->rax;
    
    /* Restore signal handler */
    sigaction(SIGILL, &old_sa, NULL);
    
    return regs->success;
}

/* Alternative: Use KVM ioctl to get more register info */
int get_kvm_registers(struct register_dump *regs) {
    int kvm_fd = open(KVM_DEVICE, O_RDWR);
    if (kvm_fd < 0) {
        printf("[-] Cannot open %s: %s\n", KVM_DEVICE, strerror(errno));
        return -1;
    }
    
    /* Check KVM version */
    int ret = ioctl(kvm_fd, 0xAE00, 0); /* KVM_GET_API_VERSION */
    if (ret < 0) {
        close(kvm_fd);
        return -1;
    }
    
    printf("[+] KVM API version: %d\n", ret);
    
    /* Get supported CPUID */
    struct {
        uint32_t nent;
        uint32_t padding;
        struct {
            uint32_t function;
            uint32_t index;
            uint32_t eax;
            uint32_t ebx;
            uint32_t ecx;
            uint32_t edx;
            uint32_t padding;
        } entries[100];
    } cpuid_data = { .nent = 100 };
    
    if (ioctl(kvm_fd, 0x4000AE05, &cpuid_data) >= 0) { /* KVM_GET_SUPPORTED_CPUID */
        printf("[+] CPUID support detected\n");
        for (int i = 0; i < cpuid_data.nent && i < 10; i++) {
            if (cpuid_data.entries[i].function == 0x40000000) {
                memcpy(regs->hypervisor_signature, &cpuid_data.entries[i].ebx, 4);
                memcpy(regs->hypervisor_signature + 4, &cpuid_data.entries[i].ecx, 4);
                memcpy(regs->hypervisor_signature + 8, &cpuid_data.entries[i].edx, 4);
                regs->hypervisor_signature[12] = '\0';
                printf("[+] Hypervisor signature: %s\n", regs->hypervisor_signature);
            }
        }
    }
    
    close(kvm_fd);
    return 0;
}

/* Try to read MSRs (requires root) */
void read_msrs(struct register_dump *regs) {
    FILE *msr_file;
    char msr_path[64];
    uint64_t value;
    
    /* Try to read EFER MSR (0xC0000080) */
    snprintf(msr_path, sizeof(msr_path), "/dev/cpu/0/msr");
    msr_file = fopen(msr_path, "rb");
    
    if (msr_file) {
        if (fseek(msr_file, 0xC0000080, SEEK_SET) == 0) {
            if (fread(&value, sizeof(value), 1, msr_file) == 1) {
                regs->efer = value;
                printf("[+] EFER MSR: 0x%016llx\n", value);
            }
        }
        fclose(msr_file);
    }
}

/* Display register dump */
void display_registers(struct register_dump *regs) {
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║               HYPERCALL 100 REGISTER DUMP               ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
    
    printf("[STATUS] Hypercall %s\n", 
           regs->success ? "EXECUTED SUCCESSFULLY" : "FAILED (Not supported)");
    printf("[RESULT] RAX after vmcall: 0x%016llx\n\n", regs->hypercall_result);
    
    printf("GENERAL PURPOSE REGISTERS:\n");
    printf("┌────────────────────────────────────────────────────────────┐\n");
    printf("│ RAX: 0x%016llx  RBX: 0x%016llx │\n", regs->rax, regs->rbx);
    printf("│ RCX: 0x%016llx  RDX: 0x%016llx │\n", regs->rcx, regs->rdx);
    printf("│ RSI: 0x%016llx  RDI: 0x%016llx │\n", regs->rsi, regs->rdi);
    printf("│ RBP: 0x%016llx  RSP: 0x%016llx │\n", regs->rbp, regs->rsp);
    printf("│ R8:  0x%016llx  R9:  0x%016llx │\n", regs->r8, regs->r9);
    printf("│ R10: 0x%016llx  R11: 0x%016llx │\n", regs->r10, regs->r11);
    printf("│ R12: 0x%016llx  R13: 0x%016llx │\n", regs->r12, regs->r13);
    printf("│ R14: 0x%016llx  R15: 0x%016llx │\n", regs->r14, regs->r15);
    printf("│ RIP: 0x%016llx  RFLAGS: 0x%016llx │\n", regs->rip, regs->rflags);
    printf("└────────────────────────────────────────────────────────────┘\n\n");
    
    printf("SEGMENT REGISTERS:\n");
    printf("  CS: 0x%04llx  DS: 0x%04llx  ES: 0x%04llx  FS: 0x%04llx  GS: 0x%04llx  SS: 0x%04llx\n",
           regs->cs & 0xFFFF, regs->ds & 0xFFFF, regs->es & 0xFFFF,
           regs->fs & 0xFFFF, regs->gs & 0xFFFF, regs->ss & 0xFFFF);
    
    if (regs->cr0 != 0 || regs->cr2 != 0 || regs->cr3 != 0 || regs->cr4 != 0) {
        printf("\nCONTROL REGISTERS:\n");
        printf("  CR0: 0x%016llx  CR2: 0x%016llx\n", regs->cr0, regs->cr2);
        printf("  CR3: 0x%016llx  CR4: 0x%016llx\n", regs->cr3, regs->cr4);
    }
    
    if (regs->efer != 0) {
        printf("\nMODEL SPECIFIC REGISTERS:\n");
        printf("  EFER: 0x%016llx\n", regs->efer);
        printf("    NXE (11): %s\n", (regs->efer & (1ULL << 11)) ? "ENABLED" : "DISABLED");
        printf("    LMA (10): %s\n", (regs->efer & (1ULL << 10)) ? "ENABLED" : "DISABLED");
        printf("    LME (8):  %s\n", (regs->efer & (1ULL << 8)) ? "ENABLED" : "DISABLED");
        printf("    SCE (0):  %s\n", (regs->efer & (1ULL << 0)) ? "ENABLED" : "DISABLED");
    }
    
    printf("\nANALYSIS:\n");
    printf("  ──────────────────────────────────────────────────────\n");
    
    /* Check virtualization support */
    uint32_t ecx;
    asm volatile("cpuid" : "=c"(ecx) : "a"(1) : "rbx", "rdx");
    
    if (ecx & (1 << 5)) {
        printf("  [✓] VMX support detected (Intel VT-x)\n");
    } else {
        printf("  [✗] No VMX support\n");
    }
    
    /* Check if we're in a VM */
    uint32_t hypervisor_present;
    asm volatile("cpuid" : "=b"(hypervisor_present) : "a"(1) : "rcx", "rdx");
    
    if ((hypervisor_present >> 31) & 1) {
        printf("  [✓] Running in a hypervisor\n");
        
        /* Get hypervisor vendor */
        char vendor[13] = {0};
        asm volatile(
            "cpuid\n\t"
            : "=b"(*((uint32_t*)vendor)),
              "=c"(*((uint32_t*)(vendor+4))),
              "=d"(*((uint32_t*)(vendor+8)))
            : "a"(0x40000000)
        );
        printf("  [ℹ] Hypervisor vendor: %s\n", vendor);
    } else {
        printf("  [✗] Not running in a hypervisor (bare metal)\n");
    }
    
    printf("\nMEMORY MAPPINGS AROUND CRITICAL REGIONS:\n");
    printf("  ──────────────────────────────────────────────────────\n");
    
    /* Show memory around key registers */
    printf("  RIP (0x%016llx) points to:\n", regs->rip);
    printf("  RSP (0x%016llx) stack region\n", regs->rsp);
    
    if (regs->rip > 0xffffffff80000000) {
        printf("  [ℹ] RIP in kernel space\n");
    } else {
        printf("  [ℹ] RIP in user space\n");
    }
    
    printf("\nEXPLOITATION NOTES:\n");
    printf("  ──────────────────────────────────────────────────────\n");
    if (regs->success) {
        printf("  [✓] Hypercall 100 is handled by hypervisor\n");
        printf("  [ℹ] RAX contains hypercall return value: 0x%llx\n", regs->rax);
        printf("  [ℹ] Check if hypervisor has custom hypercall handler\n");
    } else {
        printf("  [✗] Hypercall 100 not supported\n");
        printf("  [ℹ] May cause #UD (Invalid Opcode) exception\n");
        printf("  [ℹ] Try other hypercall numbers or KVM ioctls\n");
    }
    
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║                     DUMP COMPLETE                       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
}

/* Advanced: Try to trigger VM exit and capture exit reason */
void test_vmexit_handling(void) {
    printf("\n[*] Testing VM exit handling...\n");
    
    /* Try various instructions that cause VM exits */
    uint64_t rax_before, rax_after;
    
    asm volatile(
        "mov %%rax, %0\n\t"
        "cpuid\n\t"
        "mov %%rax, %1\n\t"
        : "=r"(rax_before), "=r"(rax_after)
        : 
        : "rbx", "rcx", "rdx"
    );
    
    printf("[+] CPUID executed (VM exit if in VMX non-root)\n");
    printf("    RAX before: 0x%016llx, after: 0x%016llx\n", rax_before, rax_after);
    
    /* Try reading CR3 (causes VM exit) */
    uint64_t cr3;
    asm volatile("mov %%cr3, %0\n\t" : "=r"(cr3));
    printf("[+] CR3 read: 0x%016llx\n", cr3);
}

int main(int argc, char *argv[]) {
    printf("[*] Hypercall 100 Register Dumper - Standalone\n");
    printf("[*] Build: %s %s\n", __DATE__, __TIME__);
    printf("[*] PID: %d\n", getpid());
    printf("[*] UID: %d\n", getuid());
    
    struct register_dump regs = {0};
    
    /* Try to get KVM info first */
    get_kvm_registers(&regs);
    
    /* Try to read MSRs if root */
    if (getuid() == 0) {
        read_msrs(&regs);
    }
    
    /* Execute hypercall 100 */
    printf("\n");
    if (!execute_hypercall_100(&regs)) {
        printf("[!] Hypercall 100 not supported or failed\n");
        printf("[!] Trying alternative hypercall numbers...\n");
        
        /* Try common hypercall numbers */
        for (int i = 1; i <= 10; i++) {
            uint64_t result;
            asm volatile(
                "mov %1, %%rax\n\t"
                "vmcall\n\t"
                "mov %%rax, %0\n\t"
                : "=r"(result)
                : "r"((uint64_t)i)
                : "memory"
            );
            printf("  Hypercall %2d -> RAX: 0x%016llx\n", i, result);
        }
    }
    
    /* Display results */
    display_registers(&regs);
    
    /* Additional VM exit tests */
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_vmexit_handling();
    }
    
    /* Save to file if requested */
    if (argc > 1 && strcmp(argv[1], "--save") == 0) {
        char filename[256];
        snprintf(filename, sizeof(filename), "hyperdump_%d.bin", getpid());
        FILE *f = fopen(filename, "wb");
        if (f) {
            fwrite(&regs, sizeof(regs), 1, f);
            fclose(f);
            printf("[+] Register dump saved to %s\n", filename);
        }
    }
    
    return 0;
}
