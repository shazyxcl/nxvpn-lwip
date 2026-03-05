/*
 * socks5_relay.c
 *
 * Menerima setiap koneksi TCP/UDP baru dari lwIP, lalu membuat koneksi
 * ke SOCKS5 server dan melakukan relay data dua arah.
 *
 * Arsitektur per-koneksi:
 *   [lwIP TCP PCB] <---> [relay_conn] <---> [SOCKS5 socket (POSIX)]
 *
 * Setiap relay_conn dikelola dalam satu thread POSIX.
 * UDP diteruskan lewat udpgw protocol (kompatibel badvpn-udpgw).
 */

#include "socks5_relay.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <android/log.h>

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/sys.h"

#define TAG "socks5_relay"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define SOCKS5_VER          0x05
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_CMD_UDP      0x03
#define SOCKS5_ATYP_IPV4    0x01
#define SOCKS5_ATYP_IPV6    0x04
#define SOCKS5_AUTH_NONE    0x00
#define RELAY_BUF_SIZE      65536

/* ─────────────────────────────────────────────────────────────────────────── */
/* Konfigurasi global                                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static char     g_socks_host[128]   = {0};
static int      g_socks_port        = 0;
static char     g_udpgw_addr[128]   = {0};   /* "host:port" atau kosong */
static char     g_dns_addr[128]     = {0};   /* "host:port" atau kosong */
static int      g_transparent_dns  = 0;
static volatile int g_relay_active  = 0;

/* ─────────────────────────────────────────────────────────────────────────── */
/* Struktur relay per-koneksi TCP                                               */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef struct relay_conn {
    struct tcp_pcb *pcb;       /* lwIP PCB sisi tun */
    int             socks_fd;  /* socket ke SOCKS5 server */
    pthread_t       thread;
    pthread_mutex_t mutex;
    int             closed;

    /* Buffer dari lwIP menunggu dikirim ke SOCKS5 */
    uint8_t  recv_buf[RELAY_BUF_SIZE];
    int      recv_len;
    int      recv_ready;      /* 1 = ada data menunggu */
    pthread_cond_t recv_cond;
} relay_conn_t;

/* ─────────────────────────────────────────────────────────────────────────── */
/* Utilitas: buat socket blocking ke SOCKS5 server                             */
/* ─────────────────────────────────────────────────────────────────────────── */

static int connect_to_socks5(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGE("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)g_socks_port);
    if (inet_pton(AF_INET, g_socks_host, &addr.sin_addr) != 1) {
        LOGE("inet_pton failed for %s", g_socks_host);
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOGE("connect to SOCKS5 %s:%d failed: %s",
             g_socks_host, g_socks_port, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* SOCKS5 handshake + CONNECT ke dst_ip:dst_port                               */
/* ─────────────────────────────────────────────────────────────────────────── */

static int socks5_connect(int fd, uint32_t dst_ip_net, uint16_t dst_port_net) {
    uint8_t buf[256];

    /* ── Greeting ── */
    buf[0] = SOCKS5_VER;
    buf[1] = 1;                 /* 1 method */
    buf[2] = SOCKS5_AUTH_NONE;
    if (send(fd, buf, 3, 0) != 3) return -1;

    if (recv(fd, buf, 2, MSG_WAITALL) != 2) return -1;
    if (buf[0] != SOCKS5_VER || buf[1] != SOCKS5_AUTH_NONE) {
        LOGE("SOCKS5 auth rejected");
        return -1;
    }

    /* ── CONNECT request ── */
    buf[0] = SOCKS5_VER;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;              /* RSV */
    buf[3] = SOCKS5_ATYP_IPV4;
    memcpy(buf + 4, &dst_ip_net, 4);
    memcpy(buf + 8, &dst_port_net, 2);

    if (send(fd, buf, 10, 0) != 10) return -1;

    /* ── Response ── */
    if (recv(fd, buf, 10, MSG_WAITALL) != 10) return -1;
    if (buf[1] != 0x00) {
        LOGE("SOCKS5 CONNECT rejected, code=%d", buf[1]);
        return -1;
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* lwIP callbacks (dipanggil dari konteks lwIP / I/O thread)                   */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Forward declaration */
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb,
                          struct pbuf *p, err_t err);
static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len);
static void  tcp_err_cb (void *arg, err_t err);

/* ─────────────────────────────────────────────────────────────────────────── */
/* Thread per-koneksi: relay antara lwIP dan SOCKS5                            */
/* ─────────────────────────────────────────────────────────────────────────── */

static void relay_close(relay_conn_t *conn) {
    pthread_mutex_lock(&conn->mutex);
    if (conn->closed) {
        pthread_mutex_unlock(&conn->mutex);
        return;
    }
    conn->closed = 1;
    pthread_mutex_unlock(&conn->mutex);

    if (conn->socks_fd >= 0) {
        shutdown(conn->socks_fd, SHUT_RDWR);
        close(conn->socks_fd);
        conn->socks_fd = -1;
    }

    /* Tutup lwIP PCB dari konteks lwIP — gunakan LWIP_LOCK jika pakai
     * LWIP_TCPIP_CORE_LOCKING */
    LOCK_TCPIP_CORE();
    if (conn->pcb != NULL) {
        tcp_arg(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_err(conn->pcb, NULL);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
    }
    UNLOCK_TCPIP_CORE();
}

/*
 * Thread: socks5 → lwIP  (baca dari SOCKS5, kirim ke tun via lwIP TCP)
 */
static void *relay_socks_to_lwip(void *arg) {
    relay_conn_t *conn = (relay_conn_t *)arg;
    uint8_t buf[RELAY_BUF_SIZE];

    while (!conn->closed && g_relay_active) {
        ssize_t n = recv(conn->socks_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            LOGD("socks5→lwip: recv returned %zd", n);
            break;
        }

        LOCK_TCPIP_CORE();
        if (conn->pcb == NULL || conn->closed) {
            UNLOCK_TCPIP_CORE();
            break;
        }

        err_t err = tcp_write(conn->pcb, buf, (u16_t)n, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            tcp_output(conn->pcb);
        } else {
            LOGE("tcp_write error: %d", err);
            UNLOCK_TCPIP_CORE();
            break;
        }
        UNLOCK_TCPIP_CORE();
    }

    relay_close(conn);
    return NULL;
}

/*
 * Thread utama per-koneksi: inisialisasi SOCKS5 lalu spawn socks→lwip thread
 */
static void *relay_thread_func(void *arg) {
    relay_conn_t *conn = (relay_conn_t *)arg;

    /* Sambungkan ke SOCKS5 */
    conn->socks_fd = connect_to_socks5();
    if (conn->socks_fd < 0) {
        LOGE("relay_thread: connect_to_socks5 failed");
        relay_close(conn);
        free(conn);
        return NULL;
    }

    /* Dapatkan dst IP dan port dari PCB */
    uint32_t dst_ip   = 0;
    uint16_t dst_port = 0;

    LOCK_TCPIP_CORE();
    if (conn->pcb) {
        dst_ip   = conn->pcb->remote_ip.addr;   /* sudah network byte order di lwIP */
        dst_port = htons(conn->pcb->remote_port);
    }
    UNLOCK_TCPIP_CORE();

    if (socks5_connect(conn->socks_fd, dst_ip, dst_port) != 0) {
        LOGE("relay_thread: socks5_connect failed");
        relay_close(conn);
        free(conn);
        return NULL;
    }

    LOGD("relay: SOCKS5 connected to %u.%u.%u.%u:%u",
         (dst_ip)&0xff, (dst_ip>>8)&0xff,
         (dst_ip>>16)&0xff, (dst_ip>>24)&0xff,
         ntohs(dst_port));

    /* Spawn thread socks→lwip */
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, relay_socks_to_lwip, conn);
    pthread_attr_destroy(&attr);

    /* Thread ini: lwIP→socks (data dari tun dikirim ke SOCKS5) */
    while (!conn->closed && g_relay_active) {
        pthread_mutex_lock(&conn->mutex);
        while (!conn->recv_ready && !conn->closed) {
            pthread_cond_wait(&conn->recv_cond, &conn->mutex);
        }
        if (conn->closed) {
            pthread_mutex_unlock(&conn->mutex);
            break;
        }

        uint8_t tmp[RELAY_BUF_SIZE];
        int len = conn->recv_len;
        memcpy(tmp, conn->recv_buf, len);
        conn->recv_ready = 0;
        conn->recv_len   = 0;
        pthread_mutex_unlock(&conn->mutex);

        /* Kirim ke SOCKS5 */
        int sent = 0;
        while (sent < len) {
            ssize_t n = send(conn->socks_fd, tmp + sent, len - sent, 0);
            if (n <= 0) {
                goto done;
            }
            sent += (int)n;
        }

        /* Beritahu lwIP bahwa buffer sudah diterima */
        LOCK_TCPIP_CORE();
        if (conn->pcb)
            tcp_recved(conn->pcb, (u16_t)len);
        UNLOCK_TCPIP_CORE();
    }

done:
    relay_close(conn);
    free(conn);
    return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* lwIP TCP callbacks                                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb,
                          struct pbuf *p, err_t err)
{
    relay_conn_t *conn = (relay_conn_t *)arg;
    if (!conn) return ERR_OK;

    if (p == NULL || err != ERR_OK) {
        /* Koneksi ditutup oleh sisi tun */
        if (p) pbuf_free(p);
        relay_close(conn);
        return ERR_OK;
    }

    /* Kumpulkan data dari pbuf chain */
    uint8_t tmp[RELAY_BUF_SIZE];
    uint16_t total = 0;
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        if (total + q->len > sizeof(tmp)) break;
        memcpy(tmp + total, q->payload, q->len);
        total += q->len;
    }
    pbuf_free(p);

    /* Kirim sinyal ke relay thread */
    pthread_mutex_lock(&conn->mutex);
    memcpy(conn->recv_buf, tmp, total);
    conn->recv_len   = total;
    conn->recv_ready = 1;
    pthread_cond_signal(&conn->recv_cond);
    pthread_mutex_unlock(&conn->mutex);

    return ERR_OK;
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)pcb; (void)len;
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
    relay_conn_t *conn = (relay_conn_t *)arg;
    if (conn) {
        LOGD("tcp_err_cb: err=%d", err);
        conn->pcb = NULL;   /* PCB sudah invalid */
        relay_close(conn);
    }
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* lwIP TCP accept callback — dipanggil tiap ada koneksi TCP baru dari tun     */
/* ─────────────────────────────────────────────────────────────────────────── */

static err_t tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || newpcb == NULL) return ERR_VAL;
    if (!g_relay_active) return ERR_ABRT;

    LOGD("tcp_accept_cb: new connection from %u.%u.%u.%u:%u",
         ip4_addr1(&newpcb->remote_ip), ip4_addr2(&newpcb->remote_ip),
         ip4_addr3(&newpcb->remote_ip), ip4_addr4(&newpcb->remote_ip),
         newpcb->remote_port);

    relay_conn_t *conn = (relay_conn_t *)calloc(1, sizeof(relay_conn_t));
    if (!conn) {
        tcp_abort(newpcb);
        return ERR_MEM;
    }

    conn->pcb      = newpcb;
    conn->socks_fd = -1;
    conn->closed   = 0;
    conn->recv_ready = 0;
    conn->recv_len   = 0;
    pthread_mutex_init(&conn->mutex, NULL);
    pthread_cond_init(&conn->recv_cond, NULL);

    tcp_arg (newpcb, conn);
    tcp_recv(newpcb, tcp_recv_cb);
    tcp_sent(newpcb, tcp_sent_cb);
    tcp_err (newpcb, tcp_err_cb);
    tcp_setprio(newpcb, TCP_PRIO_MIN);

    /* Spawn relay thread */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&conn->thread, &attr, relay_thread_func, conn) != 0) {
        LOGE("pthread_create for relay failed");
        free(conn);
        tcp_abort(newpcb);
        pthread_attr_destroy(&attr);
        return ERR_MEM;
    }
    pthread_attr_destroy(&attr);

    return ERR_OK;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* UDP relay via udpgw                                                          */
/*                                                                              */
/* Protokol udpgw (badvpn):                                                     */
/*   [2B len][1B flags][2B conn_id][4B dst_ip][2B dst_port][payload]           */
/* ─────────────────────────────────────────────────────────────────────────── */

#define UDPGW_FLAG_KEEPALIVE  (1<<0)
#define UDPGW_FLAG_REBIND     (1<<1)
#define UDPGW_FLAG_DNS        (1<<2)
#define UDPGW_HEADER_SIZE     9  /* flags(1)+conn_id(2)+dst_ip(4)+dst_port(2) */

static int           g_udpgw_fd       = -1;
static pthread_t     g_udpgw_thread;
static struct udp_pcb *g_udp_pcb      = NULL;
static uint16_t      g_udpgw_conn_id  = 0;

static int connect_udpgw(void) {
    if (g_udpgw_addr[0] == '\0') return -1;

    char host[128] = {0};
    int  port      = 7300;
    char *colon = strrchr(g_udpgw_addr, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - g_udpgw_addr);
        strncpy(host, g_udpgw_addr, hlen);
        port = atoi(colon + 1);
    } else {
        strncpy(host, g_udpgw_addr, sizeof(host)-1);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    LOGI("udpgw connected to %s:%d", host, port);
    return fd;
}

/*
 * udpgw → lwIP UDP: thread yang menerima paket dari udpgw server
 * dan mengirimkannya kembali ke stack lwIP sebagai UDP.
 */
static void *udpgw_recv_thread(void *arg) {
    (void)arg;
    uint8_t buf[RELAY_BUF_SIZE];

    while (g_relay_active && g_udpgw_fd >= 0) {
        /* Baca 2-byte length header */
        uint16_t pkt_len = 0;
        if (recv(g_udpgw_fd, &pkt_len, 2, MSG_WAITALL) != 2) break;
        pkt_len = ntohs(pkt_len);
        if (pkt_len < UDPGW_HEADER_SIZE || pkt_len > sizeof(buf)) break;

        if (recv(g_udpgw_fd, buf, pkt_len, MSG_WAITALL) != pkt_len) break;

        /* Parse header */
        /* uint8_t  flags    = buf[0]; */
        /* uint16_t conn_id  = ntohs(*(uint16_t *)(buf+1)); */
        uint32_t src_ip   = *(uint32_t *)(buf + 3);
        uint16_t src_port = *(uint16_t *)(buf + 7);

        uint16_t payload_len = pkt_len - UDPGW_HEADER_SIZE;
        uint8_t *payload     = buf + UDPGW_HEADER_SIZE;

        /* Inject ke lwIP UDP */
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, payload_len, PBUF_RAM);
        if (!p) continue;
        memcpy(p->payload, payload, payload_len);

        LOCK_TCPIP_CORE();
        if (g_udp_pcb) {
            ip_addr_t src_addr;
            ip_addr_set_ip4_u32(&src_addr, src_ip);
            udp_sendto(g_udp_pcb, p, &src_addr, ntohs(src_port));
        }
        UNLOCK_TCPIP_CORE();

        pbuf_free(p);
    }

    LOGD("udpgw_recv_thread exiting");
    if (g_udpgw_fd >= 0) { close(g_udpgw_fd); g_udpgw_fd = -1; }
    return NULL;
}

/*
 * lwIP UDP recv callback → kirim ke udpgw
 */
static void udp_recv_cb(void *arg, struct udp_pcb *pcb,
                         struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    (void)arg; (void)pcb;
    if (!p || g_udpgw_fd < 0) { if (p) pbuf_free(p); return; }

    uint16_t payload_len = p->tot_len;
    uint8_t pkt[2 + UDPGW_HEADER_SIZE + RELAY_BUF_SIZE];

    uint16_t pkt_body_len = UDPGW_HEADER_SIZE + payload_len;
    uint16_t len_be = htons(pkt_body_len);
    memcpy(pkt, &len_be, 2);

    /* flags */
    uint8_t flags = 0;
    if (g_transparent_dns &&
        (port == 53 || port == 5353))
        flags |= UDPGW_FLAG_DNS;

    pkt[2] = flags;

    uint16_t conn_id_be = htons(g_udpgw_conn_id++);
    memcpy(pkt + 3, &conn_id_be, 2);

    uint32_t dst_ip_be = ip_addr_get_ip4_u32(addr);
    memcpy(pkt + 5, &dst_ip_be, 4);

    uint16_t dst_port_be = htons(port);
    memcpy(pkt + 9, &dst_port_be, 2);

    /* Copy payload dari pbuf */
    uint8_t payload[RELAY_BUF_SIZE];
    pbuf_copy_partial(p, payload, payload_len, 0);
    memcpy(pkt + 2 + UDPGW_HEADER_SIZE, payload, payload_len);
    pbuf_free(p);

    send(g_udpgw_fd, pkt, 2 + pkt_body_len, 0);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Public API                                                                   */
/* ─────────────────────────────────────────────────────────────────────────── */

int socks5_relay_init(
        const char *socks_host,
        int         socks_port,
        const char *udpgw_addr,
        const char *dns_addr,
        int         transparent_dns)
{
    strncpy(g_socks_host, socks_host ? socks_host : "", sizeof(g_socks_host)-1);
    g_socks_port       = socks_port;
    strncpy(g_udpgw_addr, udpgw_addr ? udpgw_addr : "", sizeof(g_udpgw_addr)-1);
    strncpy(g_dns_addr,   dns_addr   ? dns_addr   : "", sizeof(g_dns_addr)-1);
    g_transparent_dns  = transparent_dns;
    g_relay_active     = 1;

    LOGI("socks5_relay_init: socks=%s:%d udpgw=%s dns=%s transpDns=%d",
         g_socks_host, g_socks_port, g_udpgw_addr, g_dns_addr, g_transparent_dns);

    return 0;
}

void socks5_relay_setup_lwip_callbacks(void) {
    /* ── TCP: listen di semua port ── */
    struct tcp_pcb *listen_pcb = tcp_new();
    if (!listen_pcb) {
        LOGE("tcp_new() failed");
        return;
    }

    /* bind ke 0.0.0.0:0 — lwIP akan intercept semua koneksi TCP */
    ip_addr_t any;
    ip_addr_set_any(0, &any);
    tcp_bind(listen_pcb, &any, 0);

    struct tcp_pcb *lpcb = tcp_listen(listen_pcb);
    if (!lpcb) {
        LOGE("tcp_listen() failed");
        tcp_close(listen_pcb);
        return;
    }

    tcp_accept(lpcb, tcp_accept_cb);
    LOGI("TCP relay listener setup OK");

    /* ── UDP: setup pcb untuk forward ── */
    if (g_udpgw_addr[0] != '\0') {
        g_udpgw_fd = connect_udpgw();
        if (g_udpgw_fd >= 0) {
            /* Spawn thread penerima dari udpgw */
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_create(&g_udpgw_thread, &attr, udpgw_recv_thread, NULL);
            pthread_attr_destroy(&attr);

            g_udp_pcb = udp_new();
            if (g_udp_pcb) {
                udp_bind(g_udp_pcb, IP_ADDR_ANY, 0);
                udp_recv(g_udp_pcb, udp_recv_cb, NULL);
                LOGI("UDP relay (udpgw) setup OK");
            }
        } else {
            LOGE("udpgw connect failed — UDP relay disabled");
        }
    }
}

void socks5_relay_cleanup(void) {
    g_relay_active = 0;

    if (g_udpgw_fd >= 0) {
        shutdown(g_udpgw_fd, SHUT_RDWR);
        close(g_udpgw_fd);
        g_udpgw_fd = -1;
    }

    LOCK_TCPIP_CORE();
    if (g_udp_pcb) {
        udp_remove(g_udp_pcb);
        g_udp_pcb = NULL;
    }
    UNLOCK_TCPIP_CORE();

    LOGI("socks5_relay_cleanup done");
}
