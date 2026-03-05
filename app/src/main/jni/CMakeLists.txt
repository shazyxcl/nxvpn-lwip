cmake_minimum_required(VERSION 3.22.1)
project(lwip_tunnel C)

# ─── Path ke source lwIP ─────────────────────────────────────────────────────
# Download lwIP 2.2.0 dari: https://download.savannah.nongnu.org/releases/lwip/
# Ekstrak ke: app/src/main/jni/lwip/
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)

set(LWIP_CORE_SRC
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/dns.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/raw.c
    ${LWIP_DIR}/src/core/stats.c
    ${LWIP_DIR}/src/core/sys.c
    ${LWIP_DIR}/src/core/altcp.c
    ${LWIP_DIR}/src/core/altcp_alloc.c
    ${LWIP_DIR}/src/core/altcp_tcp.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
)

set(LWIP_IPV4_SRC
    ${LWIP_DIR}/src/core/ipv4/autoip.c
    ${LWIP_DIR}/src/core/ipv4/dhcp.c
    ${LWIP_DIR}/src/core/ipv4/etharp.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv4/igmp.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
)

set(LWIP_ARCH_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/sys_arch.c
)

add_library(
    lwip_tunnel
    SHARED
    lwip_tunnel.c
    socks5_relay.c
    ${LWIP_CORE_SRC}
    ${LWIP_IPV4_SRC}
    ${LWIP_ARCH_SRC}
)

target_include_directories(lwip_tunnel PRIVATE
    ${LWIP_DIR}/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/arch
)

find_library(log-lib log)
target_link_libraries(lwip_tunnel ${log-lib})

target_compile_options(lwip_tunnel PRIVATE
    -Wall -Wno-unused-function -fvisibility=hidden
)
