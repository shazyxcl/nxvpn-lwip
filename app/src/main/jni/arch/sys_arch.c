/*
 * arch/sys_arch.c
 *
 * lwIP sys_arch implementation untuk Android menggunakan POSIX pthreads.
 *
 * Diperlukan karena lwipopts.h mengatur NO_SYS=0.
 * File ini menyediakan implementasi sys_mutex, sys_sem, sys_mbox,
 * dan sys_thread yang dibutuhkan lwIP.
 *
 * Letakkan di: app/src/main/jni/arch/sys_arch.c
 */

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/err.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <android/log.h>

#define TAG "lwip_arch"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ─── Mutex ─────────────────────────────────────────────────────────────── */

err_t sys_mutex_new(sys_mutex_t *mutex) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    int ret = pthread_mutex_init(mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    return (ret == 0) ? ERR_OK : ERR_MEM;
}

void sys_mutex_lock(sys_mutex_t *mutex) {
    pthread_mutex_lock(mutex);
}

void sys_mutex_unlock(sys_mutex_t *mutex) {
    pthread_mutex_unlock(mutex);
}

void sys_mutex_free(sys_mutex_t *mutex) {
    pthread_mutex_destroy(mutex);
}

int sys_mutex_valid(sys_mutex_t *mutex) {
    return (mutex != NULL);
}

void sys_mutex_set_invalid(sys_mutex_t *mutex) {
    (void)mutex;
}

/* ─── Semaphore ─────────────────────────────────────────────────────────── */

err_t sys_sem_new(sys_sem_t *sem, u8_t count) {
    if (sem_init(sem, 0, count) != 0) return ERR_MEM;
    return ERR_OK;
}

void sys_sem_signal(sys_sem_t *sem) {
    sem_post(sem);
}

u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout_ms) {
    if (timeout_ms == 0) {
        sem_wait(sem);
        return 0;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }

    if (sem_timedwait(sem, &ts) == 0) return 0;
    if (errno == ETIMEDOUT) return SYS_ARCH_TIMEOUT;
    return SYS_ARCH_TIMEOUT;
}

void sys_sem_free(sys_sem_t *sem) {
    sem_destroy(sem);
}

int sys_sem_valid(sys_sem_t *sem) {
    return (sem != NULL);
}

void sys_sem_set_invalid(sys_sem_t *sem) {
    (void)sem;
}

/* ─── Mbox (message box berbasis pipe sederhana) ─────────────────────────── */

#define MBOX_SIZE 64

typedef struct {
    void    *msgs[MBOX_SIZE];
    int      head, tail, count;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
    int valid;
} mbox_t;

err_t sys_mbox_new(sys_mbox_t *mbox, int size) {
    (void)size;
    mbox_t *m = (mbox_t *)calloc(1, sizeof(mbox_t));
    if (!m) return ERR_MEM;
    pthread_mutex_init(&m->mutex, NULL);
    pthread_cond_init(&m->not_empty, NULL);
    pthread_cond_init(&m->not_full, NULL);
    m->valid = 1;
    *mbox = m;
    return ERR_OK;
}

void sys_mbox_post(sys_mbox_t *mbox, void *msg) {
    mbox_t *m = (mbox_t *)*mbox;
    pthread_mutex_lock(&m->mutex);
    while (m->count == MBOX_SIZE)
        pthread_cond_wait(&m->not_full, &m->mutex);
    m->msgs[m->tail] = msg;
    m->tail = (m->tail + 1) % MBOX_SIZE;
    m->count++;
    pthread_cond_signal(&m->not_empty);
    pthread_mutex_unlock(&m->mutex);
}

err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg) {
    mbox_t *m = (mbox_t *)*mbox;
    pthread_mutex_lock(&m->mutex);
    if (m->count == MBOX_SIZE) {
        pthread_mutex_unlock(&m->mutex);
        return ERR_MEM;
    }
    m->msgs[m->tail] = msg;
    m->tail = (m->tail + 1) % MBOX_SIZE;
    m->count++;
    pthread_cond_signal(&m->not_empty);
    pthread_mutex_unlock(&m->mutex);
    return ERR_OK;
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg) {
    return sys_mbox_trypost(mbox, msg);
}

u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout_ms) {
    mbox_t *m = (mbox_t *)*mbox;
    pthread_mutex_lock(&m->mutex);

    if (timeout_ms == 0) {
        while (m->count == 0)
            pthread_cond_wait(&m->not_empty, &m->mutex);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }

        while (m->count == 0) {
            if (pthread_cond_timedwait(&m->not_empty, &m->mutex, &ts) == ETIMEDOUT) {
                pthread_mutex_unlock(&m->mutex);
                return SYS_ARCH_TIMEOUT;
            }
        }
    }

    if (msg) *msg = m->msgs[m->head];
    m->head = (m->head + 1) % MBOX_SIZE;
    m->count--;
    pthread_cond_signal(&m->not_full);
    pthread_mutex_unlock(&m->mutex);
    return 0;
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    mbox_t *m = (mbox_t *)*mbox;
    pthread_mutex_lock(&m->mutex);
    if (m->count == 0) {
        pthread_mutex_unlock(&m->mutex);
        return SYS_MBOX_EMPTY;
    }
    if (msg) *msg = m->msgs[m->head];
    m->head = (m->head + 1) % MBOX_SIZE;
    m->count--;
    pthread_cond_signal(&m->not_full);
    pthread_mutex_unlock(&m->mutex);
    return 0;
}

void sys_mbox_free(sys_mbox_t *mbox) {
    mbox_t *m = (mbox_t *)*mbox;
    if (!m) return;
    pthread_mutex_destroy(&m->mutex);
    pthread_cond_destroy(&m->not_empty);
    pthread_cond_destroy(&m->not_full);
    free(m);
    *mbox = NULL;
}

int sys_mbox_valid(sys_mbox_t *mbox) {
    return (*mbox != NULL);
}

void sys_mbox_set_invalid(sys_mbox_t *mbox) {
    *mbox = NULL;
}

/* ─── Thread ─────────────────────────────────────────────────────────────── */

sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread,
                             void *arg, int stacksize, int prio)
{
    (void)name; (void)stacksize; (void)prio;
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, (void *(*)(void *))thread, arg);
    pthread_attr_destroy(&attr);
    return (sys_thread_t)t;
}

/* ─── Timestamp ─────────────────────────────────────────────────────────── */

u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL);
}

/* ─── Init ───────────────────────────────────────────────────────────────── */

void sys_init(void) {
    /* tidak perlu inisialisasi tambahan untuk POSIX */
}

/* ─── Core lock (LWIP_TCPIP_CORE_LOCKING = 1) ───────────────────────────── */

static pthread_mutex_t s_core_mutex = PTHREAD_MUTEX_INITIALIZER;

void sys_lock_tcpip_core(void) {
    pthread_mutex_lock(&s_core_mutex);
}

void sys_unlock_tcpip_core(void) {
    pthread_mutex_unlock(&s_core_mutex);
}
