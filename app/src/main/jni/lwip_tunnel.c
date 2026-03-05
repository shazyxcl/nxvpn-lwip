/*
 * lwip_tunnel.c
 *
 * Native JNI layer yang menghubungkan Android VPN tun fd ke stack lwIP,
 * lalu meneruskan koneksi TCP/UDP ke SOCKS5 server.
 *
 * Dependency build (CMakeLists.txt):
 *   - lwIP (src/core, src/netif, src/api)
 *   - lwip-contrib/ports/unix/port (atau port Android custom)
 *
 * Build lewat CMake, output: liblwip_tunnel.so
 * Letakkan di: app/src/main/jniLibs/<abi>/liblwip_tunnel.so
 * atau compile via CMakeLists.txt dengan externalNativeBuild di build.gradle.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>

/* lwIP core headers */
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "netif/etharp.h"

/* tun2socks-style helper (implementasi sendiri) */
#include "socks5_relay.h"   /* lihat socks5_relay.h / socks5_relay.c di bawah */

#define TAG "lwip_tunnel_native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ── state global (satu instance saja) ───────────────────────────────────── */

static volatile int  g_running   = 0;
static int           g_tun_fd    = -1;
static struct netif  g_netif;
static pthread_t     g_io_thread;

typedef struct {
    int     tun_fd;
    int     mtu;
    char    ip[64];
    char    netmask[64];
    char    socks_addr[128];   /* "host:port" */
    char    dns_addr[128];     /* "host:port" atau kosong */
    char    udpgw_addr[128];   /* "host:port" atau kosong */
    int     transparent_dns;
} TunnelConfig;

static TunnelConfig g_cfg;

/* ── lwIP netif output: tulis IP packet ke tun fd ────────────────────────── */

static err_t tun_netif_output(struct netif *netif, struct pbuf *p,
                               const ip4_addr_t *ipaddr)
{
    (void)netif; (void)ipaddr;

    /* Kumpulkan pbuf chain ke satu buffer lalu write ke tun fd */
    uint8_t buf[65536];
    uint16_t total = 0;

    for (struct pbuf *q = p; q != NULL; q = q->next) {
        if (total + q->len > sizeof(buf)) break;
        memcpy(buf + total, q->payload, q->len);
        total += q->len;
    }

    ssize_t n = write(g_tun_fd, buf, total);
    if (n < 0) {
        LOGE("tun write error: %d", errno);
        return ERR_IF;
    }
    return ERR_OK;
}

/* ── lwIP netif init callback ─────────────────────────────────────────────── */

static err_t tun_netif_init(struct netif *netif)
{
    netif->name[0]    = 't';
    netif->name[1]    = 'n';
    netif->output     = tun_netif_output;
    netif->mtu        = (u16_t)g_cfg.mtu;
    netif->flags      = NETIF_FLAG_UP;
    return ERR_OK;
}

/* ── I/O thread: baca paket dari tun → inject ke lwIP ───────────────────── */

static void *io_thread_func(void *arg)
{
    (void)arg;
    uint8_t buf[65536];

    LOGI("I/O thread started, tun_fd=%d", g_tun_fd);

    while (g_running) {
        ssize_t n = read(g_tun_fd, buf, sizeof(buf));

        if (n <= 0) {
            if (g_running) LOGE("tun read error: %d", errno);
            break;
        }

        /* Bungkus dalam pbuf dan inject ke lwIP */
        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)n, PBUF_POOL);
        if (p == NULL) {
            LOGE("pbuf_alloc failed");
            continue;
        }

        memcpy(p->payload, buf, n);

        /* Input ke netif — lwIP akan dispatch ke TCP/UDP handler */
        if (g_netif.input(p, &g_netif) != ERR_OK) {
            pbuf_free(p);
        }

        /* Proses semua timer lwIP yang jatuh tempo */
        sys_check_timeouts();
    }

    LOGI("I/O thread exiting");
    return NULL;
}

/* ── Parse "host:port" ────────────────────────────────────────────────────── */

static void parse_addr(const char *addr_str, char *host_out, int *port_out)
{
    if (!addr_str || addr_str[0] == '\0') {
        host_out[0] = '\0';
        *port_out   = 0;
        return;
    }
    const char *colon = strrchr(addr_str, ':');
    if (colon) {
        size_t host_len = (size_t)(colon - addr_str);
        strncpy(host_out, addr_str, host_len);
        host_out[host_len] = '\0';
        *port_out = atoi(colon + 1);
    } else {
        strncpy(host_out, addr_str, 63);
        *port_out = 1080; /* default SOCKS5 */
    }
}

/* ── JNI: lwipTunnelStart ─────────────────────────────────────────────────── */

JNIEXPORT jint JNICALL
Java_com_nxdevelopers_nxvpn_tunnel_vpn_LwipTunnel_lwipTunnelStart(
        JNIEnv  *env,
        jobject  thiz,
        jint     tun_fd,
        jint     mtu,
        jstring  j_ip,
        jstring  j_netmask,
        jstring  j_socks_addr,
        jstring  j_dns_addr,
        jstring  j_udpgw_addr,
        jboolean transparent_dns)
{
    if (g_running) {
        LOGE("lwipTunnelStart: already running");
        return -1;
    }

    /* ── Salin konfigurasi ── */
    g_cfg.tun_fd          = tun_fd;
    g_cfg.mtu             = mtu;
    g_cfg.transparent_dns = (int)transparent_dns;

    const char *tmp;

    tmp = (*env)->GetStringUTFChars(env, j_ip, NULL);
    strncpy(g_cfg.ip, tmp, sizeof(g_cfg.ip) - 1);
    (*env)->ReleaseStringUTFChars(env, j_ip, tmp);

    tmp = (*env)->GetStringUTFChars(env, j_netmask, NULL);
    strncpy(g_cfg.netmask, tmp, sizeof(g_cfg.netmask) - 1);
    (*env)->ReleaseStringUTFChars(env, j_netmask, tmp);

    tmp = (*env)->GetStringUTFChars(env, j_socks_addr, NULL);
    strncpy(g_cfg.socks_addr, tmp, sizeof(g_cfg.socks_addr) - 1);
    (*env)->ReleaseStringUTFChars(env, j_socks_addr, tmp);

    if (j_dns_addr != NULL) {
        tmp = (*env)->GetStringUTFChars(env, j_dns_addr, NULL);
        strncpy(g_cfg.dns_addr, tmp, sizeof(g_cfg.dns_addr) - 1);
        (*env)->ReleaseStringUTFChars(env, j_dns_addr, tmp);
    } else {
        g_cfg.dns_addr[0] = '\0';
    }

    if (j_udpgw_addr != NULL) {
        tmp = (*env)->GetStringUTFChars(env, j_udpgw_addr, NULL);
        strncpy(g_cfg.udpgw_addr, tmp, sizeof(g_cfg.udpgw_addr) - 1);
        (*env)->ReleaseStringUTFChars(env, j_udpgw_addr, tmp);
    } else {
        g_cfg.udpgw_addr[0] = '\0';
    }

    g_tun_fd = tun_fd;

    /* ── Inisialisasi lwIP ── */
    lwip_init();

    ip4_addr_t ipaddr, netmask, gw;
    ip4addr_aton(g_cfg.ip, &ipaddr);
    ip4addr_aton(g_cfg.netmask, &netmask);
    IP4_ADDR(&gw, 0, 0, 0, 0);

    netif_add(&g_netif, &ipaddr, &netmask, &gw,
              NULL, tun_netif_init, ip_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    /* ── Inisialisasi SOCKS5 relay ── */
    char socks_host[128];
    int  socks_port;
    parse_addr(g_cfg.socks_addr, socks_host, &socks_port);

    if (socks5_relay_init(socks_host, socks_port,
                          g_cfg.udpgw_addr,
                          g_cfg.dns_addr,
                          g_cfg.transparent_dns) != 0) {
        LOGE("socks5_relay_init failed");
        return -2;
    }

    /* ── Pasang TCP/UDP accept callbacks ke lwIP ── */
    socks5_relay_setup_lwip_callbacks();

    /* ── Jalankan I/O thread ── */
    g_running = 1;
    if (pthread_create(&g_io_thread, NULL, io_thread_func, NULL) != 0) {
        LOGE("pthread_create failed");
        g_running = 0;
        return -3;
    }

    /* Blokir sampai stop dipanggil */
    pthread_join(g_io_thread, NULL);

    /* Cleanup */
    netif_remove(&g_netif);
    socks5_relay_cleanup();

    LOGI("lwipTunnelStart exiting normally");
    return 0;
}

/* ── JNI: lwipTunnelStop ─────────────────────────────────────────────────── */

JNIEXPORT void JNICALL
Java_com_nxdevelopers_nxvpn_tunnel_vpn_LwipTunnel_lwipTunnelStop(
        JNIEnv  *env,
        jobject  thiz)
{
    LOGI("lwipTunnelStop called");
    g_running = 0;

    /* Tutup tun fd agar read() di I/O thread segera return */
    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
    }
}
