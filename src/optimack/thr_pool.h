#ifndef THR_POOL_H
#define THR_POOL_H
/*
 * Declarations for the clients of a thread pool.
 */

#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

/* pool_flags */
#define    POOL_WAIT    0x01        /* waiting in thr_pool_wait() */
#define    POOL_DESTROY    0x02        /* pool is being destroyed */

/*
 * The thr_pool_t type is opaque to the client.
 * It is created by thr_pool_create() and must be passed
 * unmodified to the remainder of the interfaces.
 */
/*
 * The thread pool, opaque to the clients.
 */
typedef struct thr_pool thr_pool_t;
typedef unsigned int uint_t;
/*
 * FIFO queued job
 */
typedef struct job job_t;
struct job {
        job_t    *job_next;        /* linked list of jobs */
        void    *(*job_func)(void *);    /* function to call */
        void    *job_arg;        /* its argument */
};

/*
 * List of active worker threads, linked through their stacks.
 */
typedef struct active active_t;
struct active {
        active_t    *active_next;    /* linked list of threads */ 
        pthread_t    active_tid;    /* active thread id */
};  

/*
 * The thread pool, opaque to the clients.
 */
struct thr_pool {
        thr_pool_t              *pool_forw;    /* circular linked list */
        thr_pool_t              *pool_back;    /* of all thread pools */
        pthread_mutex_t pool_mutex;    /* protects the pool data */
        pthread_cond_t  pool_busycv;    /* synchronization in pool_queue */
        pthread_cond_t  pool_workcv;    /* synchronization with workers */
        pthread_cond_t  pool_waitcv;    /* synchronization in pool_wait() */
        active_t                *pool_active;    /* list of threads performing work */
        job_t                   *pool_head;    /* head of FIFO job queue */
        job_t                   *pool_tail;    /* tail of FIFO job queue */
        pthread_attr_t  pool_attr;    /* attributes of the workers */
        int                     pool_flags;    /* see below */
        uint_t                  pool_linger;    /* seconds before idle workers exit */
        int                     pool_minimum;    /* minimum number of worker threads */
        int                     pool_maximum;    /* maximum number of worker threads */
        int                     pool_nthreads;    /* current number of worker threads */
        int                     pool_idle;    /* number of idle workers */

        pthread_cond_t*         pool_workcvs;    /* synchronization with workers */
        int                     last_worker;
        void* obj;
};  


/*
 * Create a thread pool.
 *    min_threads:    the minimum number of threads kept in the pool,
 *            always available to perform work requests.
 *    max_threads:    the maximum number of threads that can be
 *            in the pool, performing work requests.
 *    linger:        the number of seconds excess idle worker threads
 *            (greater than min_threads) linger before exiting.
 *    attr:        attributes of all worker threads (can be NULL);
 *            can be destroyed after calling thr_pool_create().
 * On error, thr_pool_create() returns NULL with errno set to the error code.
 */
extern thr_pool_t *thr_pool_create(uint_t min_threads, uint_t max_threads,
                uint_t linger, pthread_attr_t *attr);

/*
 * Enqueue a work request to the thread pool job queue.
 * If there are idle worker threads, awaken one to perform the job.
 * Else if the maximum number of workers has not been reached,
 * create a new worker thread to perform the job.
 * Else just return after adding the job to the queue;
 * an existing worker thread will perform the job when
 * it finishes the job it is currently performing.
 *
 * The job is performed as if a new detached thread were created for it:
 *    pthread_create(NULL, attr, void *(*func)(void *), void *arg);
 *
 * On error, thr_pool_queue() returns -1 with errno set to the error code.
 */
extern int thr_pool_queue(thr_pool_t *pool,
            void *(*func)(void *), void *arg);

/*
 * Wait for all queued jobs to complete.
 */
extern void thr_pool_wait(thr_pool_t *pool);

/*
 * Cancel all queued jobs and destroy the pool.
 */
extern void thr_pool_destroy(thr_pool_t *pool);


int establish_tcp_connection(int old_sockfd, char* remote_ip, unsigned short remote_port);

#endif