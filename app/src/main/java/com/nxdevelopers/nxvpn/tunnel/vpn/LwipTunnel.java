package com.nxdevelopers.nxvpn.tunnel.vpn;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.util.Log;

/**
 * LwipTunnel — pengganti Tun2Socks menggunakan lwIP via JNI.
 *
 * Perbedaan utama dari Tun2Socks lama:
 *  - Tidak ada child process (Runtime.exec)
 *  - Tidak ada sendFd() via LocalSocket
 *  - Library dimuat via System.loadLibrary("lwip_tunnel")
 *  - JNI langsung membaca/menulis tun fd dan relay ke SOCKS5
 *
 * Signature konstruktor identik dengan Tun2Socks sehingga TunnelManager
 * hanya perlu mengganti nama class dan listener interface.
 */
public class LwipTunnel extends Thread {

    private static final String TAG     = "LwipTunnel";
    private static final String NATIVE_LIB = "lwip_tunnel";

    // ── Load native library ────────────────────────────────────────────────
    static {
        try {
            System.loadLibrary(NATIVE_LIB);
            Log.i(TAG, "liblwip_tunnel.so loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load liblwip_tunnel.so: " + e.getMessage());
        }
    }

    // ── Native method declarations ─────────────────────────────────────────

    /**
     * Memulai event-loop lwIP (blocking sampai lwipTunnelStop() dipanggil).
     *
     * @param tunFd          integer fd dari ParcelFileDescriptor
     * @param mtu            MTU tun interface
     * @param ipAddress      IP virtual router (mis. "10.0.0.2")
     * @param netmask        Netmask virtual (mis. "255.255.255.0")
     * @param socksAddr      "host:port" SOCKS5 server
     * @param dnsAddr        "host:port" DNS relay — boleh null
     * @param udpgwAddr      "host:port" udpgw server — boleh null
     * @param transparentDns true = teruskan DNS transparan lewat udpgw
     * @return 0 sukses, negatif jika error
     */
    private native int lwipTunnelStart(
            int     tunFd,
            int     mtu,
            String  ipAddress,
            String  netmask,
            String  socksAddr,
            String  dnsAddr,
            String  udpgwAddr,
            boolean transparentDns
    );

    /**
     * Menghentikan event-loop lwIP secara graceful.
     * Menutup tun fd sehingga read() di I/O thread langsung return.
     */
    private native void lwipTunnelStop();

    // ── Listener interface ─────────────────────────────────────────────────

    public interface OnLwipTunnelListener {
        void onStart();
        void onStop();
    }

    private OnLwipTunnelListener mListener;

    public void setOnLwipTunnelListener(OnLwipTunnelListener listener) {
        this.mListener = listener;
    }

    // ── Fields ─────────────────────────────────────────────────────────────

    private final Context               mContext;
    private final ParcelFileDescriptor  mVpnInterfaceFileDescriptor;
    private final int                   mVpnInterfaceMTU;
    private final String                mVpnIpAddress;
    private final String                mVpnNetMask;
    private final String                mSocksServerAddress;
    private final String                mUdpgwServerAddress;
    private final String                mDnsResolverAddress;
    private final boolean               mUdpgwTransparentDNS;

    private volatile boolean mRunning = false;

    // ── Constructor — signature identik dengan Tun2Socks ──────────────────

    public LwipTunnel(
            Context                context,
            ParcelFileDescriptor   vpnInterfaceFileDescriptor,
            int                    vpnInterfaceMTU,
            String                 vpnIpAddress,
            String                 vpnNetMask,
            String                 socksServerAddress,
            String                 udpgwServerAddress,
            String                 dnsResolverAddress,
            boolean                udpgwTransparentDNS
    ) {
        mContext                    = context;
        mVpnInterfaceFileDescriptor = vpnInterfaceFileDescriptor;
        mVpnInterfaceMTU            = vpnInterfaceMTU;
        mVpnIpAddress               = vpnIpAddress;
        mVpnNetMask                 = vpnNetMask;
        mSocksServerAddress         = socksServerAddress;
        mUdpgwServerAddress         = udpgwServerAddress;
        mDnsResolverAddress         = dnsResolverAddress;
        mUdpgwTransparentDNS        = udpgwTransparentDNS;
    }

    // ── Thread.run() ───────────────────────────────────────────────────────

    @Override
    public void run() {
        Log.d(TAG, "LwipTunnel starting");
        Log.d(TAG, "  tunFd        : " + (mVpnInterfaceFileDescriptor != null
                ? mVpnInterfaceFileDescriptor.getFd() : "null"));
        Log.d(TAG, "  mtu          : " + mVpnInterfaceMTU);
        Log.d(TAG, "  ipAddress    : " + mVpnIpAddress);
        Log.d(TAG, "  netmask      : " + mVpnNetMask);
        Log.d(TAG, "  socks        : " + mSocksServerAddress);
        Log.d(TAG, "  udpgw        : " + mUdpgwServerAddress);
        Log.d(TAG, "  dns          : " + mDnsResolverAddress);
        Log.d(TAG, "  transparDns  : " + mUdpgwTransparentDNS);

        if (mVpnInterfaceFileDescriptor == null) {
            Log.e(TAG, "tunFd is null — aborting");
            notifyStop();
            return;
        }

        mRunning = true;
        notifyStart();

        try {
            int result = lwipTunnelStart(
                    mVpnInterfaceFileDescriptor.getFd(),
                    mVpnInterfaceMTU,
                    mVpnIpAddress,
                    mVpnNetMask,
                    mSocksServerAddress,
                    mDnsResolverAddress,
                    mUdpgwServerAddress,
                    mUdpgwTransparentDNS
            );

            if (result != 0) {
                Log.e(TAG, "lwipTunnelStart returned error code: " + result);
            } else {
                Log.d(TAG, "lwipTunnelStart exited normally");
            }

        } catch (Exception e) {
            Log.e(TAG, "LwipTunnel exception: " + e.getMessage(), e);
        } finally {
            mRunning = false;
            notifyStop();
        }
    }

    // ── Stop / interrupt ───────────────────────────────────────────────────

    @Override
    public synchronized void interrupt() {
        super.interrupt();
        if (mRunning) {
            Log.d(TAG, "Calling lwipTunnelStop()");
            try {
                lwipTunnelStop();
            } catch (Exception e) {
                Log.e(TAG, "lwipTunnelStop() error: " + e.getMessage());
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private void notifyStart() {
        if (mListener != null) {
            try { mListener.onStart(); } catch (Exception ignored) {}
        }
    }

    private void notifyStop() {
        if (mListener != null) {
            try { mListener.onStop(); } catch (Exception ignored) {}
        }
    }
}
