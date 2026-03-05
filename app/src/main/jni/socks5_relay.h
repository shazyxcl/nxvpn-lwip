/*
 * socks5_relay.h
 *
 * Interface modul yang menerima koneksi TCP/UDP dari lwIP callbacks,
 * lalu meneruskannya ke SOCKS5 server di host:port.
 *
 * Implementasi lengkap ada di socks5_relay.c — file ini adalah header
 * yang di-include oleh lwip_tunnel.c.
 */

#ifndef SOCKS5_RELAY_H
#define SOCKS5_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Inisialisasi relay.
 *
 * @param socks_host      Hostname/IP SOCKS5 server
 * @param socks_port      Port SOCKS5 server
 * @param udpgw_addr      Alamat udpgw "host:port" — NULL jika tidak dipakai
 * @param dns_addr        Alamat DNS relay "host:port" — NULL jika tidak dipakai
 * @param transparent_dns 1 = teruskan DNS lewat udpgw secara transparan
 * @return 0 sukses, -1 gagal
 */
int socks5_relay_init(
        const char *socks_host,
        int         socks_port,
        const char *udpgw_addr,
        const char *dns_addr,
        int         transparent_dns
);

/**
 * Pasang lwIP TCP accept dan UDP recv callbacks sehingga setiap koneksi
 * baru dari stack lwIP diteruskan ke SOCKS5 server.
 *
 * Harus dipanggil SETELAH lwip_init() dan netif_add().
 */
void socks5_relay_setup_lwip_callbacks(void);

/**
 * Bersihkan semua resource (koneksi aktif, mutex, dll.).
 */
void socks5_relay_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* SOCKS5_RELAY_H */
