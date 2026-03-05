/*
 * lwipopts.h
 *
 * Konfigurasi lwIP untuk Android VPN (NO_SYS = 0 agar lwIP bisa
 * menggunakan sys_arch POSIX threads).
 *
 * Letakkan file ini di direktori yang sama dengan lwip_tunnel.c
 * (app/src/main/jni/) sehingga -I path CMake menemukannya.
 */

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

/* ── Threading ─────────────────────────────────────────────────────────────
 * NO_SYS=0  → gunakan lwIP dengan OS/thread support (pthreads)
 * Diperlukan agar sys_check_timeouts() dan sys_mbox bekerja.
 */
#define NO_SYS                      0
#define SYS_LIGHTWEIGHT_PROT        1
#define LWIP_TCPIP_CORE_LOCKING     1

/* ── Memory ─────────────────────────────────────────────────────────────── */
#define MEM_LIBC_MALLOC             1   /* gunakan malloc/free standard */
#define MEMP_MEM_MALLOC             1
#define MEM_SIZE                    (256 * 1024)

/* ── pbuf ───────────────────────────────────────────────────────────────── */
#define PBUF_POOL_SIZE              64
#define PBUF_POOL_BUFSIZE           1600

/* ── TCP ────────────────────────────────────────────────────────────────── */
#define LWIP_TCP                    1
#define TCP_MSS                     1460
#define TCP_WND                     (32 * TCP_MSS)
#define TCP_SND_BUF                 (16 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * TCP_SND_BUF) / TCP_MSS)
#define MEMP_NUM_TCP_SEG            TCP_SND_QUEUELEN

/* ── UDP ────────────────────────────────────────────────────────────────── */
#define LWIP_UDP                    1
#define LWIP_DNS                    0   /* DNS dihandle lewat pdnsd/relay */

/* ── IPv4 ───────────────────────────────────────────────────────────────── */
#define LWIP_IPV4                   1
#define IP_FORWARD                  0
#define IP_REASSEMBLY               1
#define IP_FRAG                     1

/* ── ARP ────────────────────────────────────────────────────────────────── */
#define LWIP_ARP                    0   /* TUN device — tidak ada ARP */
#define LWIP_ETHERNET               0

/* ── Checksum (Android menggunakan hardware offload) ────────────────────── */
#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_UDP            1
#define CHECKSUM_GEN_TCP            1
#define CHECKSUM_CHECK_IP           1
#define CHECKSUM_CHECK_UDP          1
#define CHECKSUM_CHECK_TCP          1

/* ── Debug (nonaktifkan di release) ─────────────────────────────────────── */
#define LWIP_DEBUG                  0

/* ── Stats ──────────────────────────────────────────────────────────────── */
#define LWIP_STATS                  0

/* ── Callbacks ──────────────────────────────────────────────────────────── */
#define LWIP_CALLBACK_API           1

#endif /* __LWIPOPTS_H__ */
