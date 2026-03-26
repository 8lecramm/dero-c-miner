/*
 * C-Miner - Main Mining Client
 * Core mining loop, network handling, and worker thread management
 */

#include "include/cminer.h"

/* Solution queue entry */
typedef struct
{
    char *json;
    uint8_t thread_id;
} SolutionQueueEntry;

/* Global miner state structure - encapsulates all shared state */
typedef struct
{
    _Atomic int hashrate;
    int hashrate_old;
    _Atomic int exit_flag;
    _Atomic bool connected;
    _Atomic uint16_t template_version;

    /* Job state - protected by job_lock */
    pthread_mutex_t job_lock;
    char *blob_hash;
    char *job_id;
    uint64_t height;
    double difficulty;
    uint32_t blocks_count;
    uint32_t miniblocks_count;
    uint32_t rejects_count;

    /* Network state */
    pthread_mutex_t net_lock;
    SSL_CTX *ssl_ctx;
    BIO *bio;
    time_t start_time;
    time_t current_time;
    uint8_t fail_counter;

    /* Solution queue - prevents mining threads from blocking on network I/O */
    pthread_mutex_t queue_lock;
    SolutionQueueEntry solution_queue[MAX_SOLUTION_QUEUE];
    uint32_t queue_head;
    uint32_t queue_tail;
} MinerState;

/* Thread-local mining parameters */
typedef struct
{
    MinerState *state;
    uint8_t thread_id;
    uint8_t *workspace;
    bool use_affinity;
    uint16_t cpu_id;
} ThreadContext;

static MinerState miner_state;
static ThreadContext thread_contexts[MAX_THREADS];
static pthread_t miner_threads[MAX_THREADS];
static cpu_set_t cpuset[MAX_THREADS];
static pthread_attr_t thread_attr;

/* Function prototypes */
char *generate_websocket_key(void);
static void on_signal_int(int sig);
static void *mine_block_worker(void *arg);
void send_template(MinerState *state, char *json, int tid);
void print_status(MinerState *state);
static int allocate_workspace(uint8_t **workplace, size_t size, bool try_hugepages);
static void free_workspace(uint8_t *workplace, size_t size);

static void on_signal_int(int sig)
{
    atomic_store(&miner_state.exit_flag, 1);
    printf("\nSIGINT received. Shutting down miner...\n");
}

/* Allocate workspace memory - tries huge pages first, falls back to regular paging */
static int allocate_workspace(uint8_t **workplace, size_t size, bool try_hugepages)
{
    if (!workplace)
        return -1;

    if (try_hugepages)
    {
        /* Try 2MB huge pages with proper alignment */
        *workplace = (uint8_t *)mmap(NULL, size,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB | MAP_POPULATE,
                                     -1, 0);
        if (*workplace != MAP_FAILED)
        {
            printf("Successfully allocated %zu bytes using 2MB huge pages\n", size);
            return 0;
        }
        printf("Failed to allocate huge pages (size=%zu), falling back to regular memory\n", size);
    }

    /* Fallback to regular memory mapping */
    *workplace = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (*workplace == MAP_FAILED)
    {
        fprintf(stderr, "Failed to allocate %zu bytes of memory\n", size);
        return -1;
    }
    printf("Successfully allocated %zu bytes using regular memory\n", size);
    return 0;
}

static void free_workspace(uint8_t *workplace, size_t size)
{
    if (workplace && workplace != MAP_FAILED)
    {
        munmap(workplace, size);
    }
}

int main(int argc, char **argv)
{
    signal(SIGINT, on_signal_int);

    int c = 0;
    char *node = NULL;
    char *wallet = NULL;
    uint8_t threads = 1;
    bool use_affinity = false;

    /* Parse command line arguments */
    while ((c = getopt(argc, argv, "w:n:t:a")) != -1)
    {
        switch (c)
        {
        case 'w':
            wallet = strdup(optarg);
            if (!wallet)
                goto error_exit;
            break;
        case 'n':
            node = strdup(optarg);
            if (!node)
                goto error_exit;
            break;
        case 't':
            threads = atoi(optarg);
            if (threads < 1 || threads > MAX_THREADS)
            {
                fprintf(stderr, "Invalid thread count. Must be 1-%d\n", MAX_THREADS);
                goto error_exit;
            }
            break;
        case 'a':
            use_affinity = true;
            break;
        case '?':
            fprintf(stderr, "Unknown option character %c\n", optopt);
            goto error_exit;
        default:
            goto error_exit;
        }
    }

    if (!node || !wallet)
    {
        fprintf(stderr, "Usage: %s -n <node> -w <wallet> [-t <threads>] [-a]\n", argv[0]);
        goto error_exit;
    }

    /* Initialize miner state */
    memset(&miner_state, 0, sizeof(MinerState));
    atomic_store(&miner_state.hashrate, 0);
    atomic_store(&miner_state.exit_flag, 0);
    atomic_store(&miner_state.connected, false);
    atomic_store(&miner_state.template_version, 0);
    miner_state.hashrate_old = 0;
    miner_state.difficulty = 1000;
    pthread_mutex_init(&miner_state.job_lock, NULL);
    pthread_mutex_init(&miner_state.net_lock, NULL);
    pthread_mutex_init(&miner_state.queue_lock, NULL);
    miner_state.queue_head = 0;
    miner_state.queue_tail = 0;

    hash_init();
    print_salsa20_info();

    /* Initialize OpenSSL */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    /* Create SSL context */
    miner_state.ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (!miner_state.ssl_ctx)
    {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        goto error_cleanup;
    }

    /* Allocate workspace for all threads */
    size_t mem_per_thread = WORKSIZE;
    size_t total_mem = mem_per_thread * threads;
    uint8_t *workplace = NULL;

    if (allocate_workspace(&workplace, total_mem, true) != 0)
    {
        goto error_cleanup;
    }

    /* Get available CPUs for affinity */
    long numprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (threads > numprocs)
    {
        printf("Warning: Specified threads (%d) exceeds available CPUs (%ld)\n", threads, numprocs);
        printf("Setting threads to %ld\n", numprocs);
        threads = numprocs;
    }

    /* Create thread pool */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    printf("Starting %d mining threads\n", threads);

    for (uint8_t i = 0; i < threads; i++)
    {
        thread_contexts[i].state = &miner_state;
        thread_contexts[i].thread_id = i;
        thread_contexts[i].workspace = &workplace[i * mem_per_thread];
        thread_contexts[i].use_affinity = use_affinity;
        thread_contexts[i].cpu_id = 0;

        if (use_affinity)
        {
            CPU_ZERO(&cpuset[i]);
            uint16_t cpu_id = (i * 2) < numprocs ? i * 2 : (i * 2) - (numprocs - 1);
            CPU_SET(cpu_id, &cpuset[i]);
            thread_contexts[i].cpu_id = cpu_id;
            pthread_create(&miner_threads[i], &attr, mine_block_worker, &thread_contexts[i]);
            pthread_setaffinity_np(miner_threads[i], sizeof(cpu_set_t), &cpuset[i]);
        }
        else
        {
            pthread_create(&miner_threads[i], &attr, mine_block_worker, &thread_contexts[i]);
        }
    }

    if (use_affinity)
    {
        printf("CPU affinity: ");
        for (uint8_t i = 0; i < threads; i++)
            printf("%d ", thread_contexts[i].cpu_id);
        printf("\n");
    }

    pthread_attr_destroy(&attr);
    time(&miner_state.start_time);

    /* Main connection loop */
    do
    {
        pthread_mutex_lock(&miner_state.net_lock);
        miner_state.bio = BIO_new_ssl_connect(miner_state.ssl_ctx);
        if (!miner_state.bio)
        {
            fprintf(stderr, "Failed to create SSL connection\n");
            ERR_print_errors_fp(stderr);
            pthread_mutex_unlock(&miner_state.net_lock);
            sleep(10);
            continue;
        }

        BIO_set_conn_hostname(miner_state.bio, node);

        if (BIO_do_connect(miner_state.bio) <= 0)
        {
            fprintf(stderr, "SSL connection failed. Retrying in 10 seconds...\n");
            ERR_print_errors_fp(stderr);
            BIO_free(miner_state.bio);
            miner_state.bio = NULL;
            pthread_mutex_unlock(&miner_state.net_lock);
            sleep(10);
            continue;
        }

        pthread_mutex_unlock(&miner_state.net_lock);

        /* Send WebSocket handshake */
        char *websocket_key = generate_websocket_key();
        if (!websocket_key)
        {
            fprintf(stderr, "Failed to generate WebSocket key\n");
            continue;
        }

        char request[512];
        snprintf(request, sizeof(request),
                 "GET /ws/%s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: upgrade\r\n"
                 "Sec-WebSocket-Key: %s\r\n"
                 "Sec-WebSocket-Version: 13\r\n\r\n",
                 wallet, node, websocket_key);

        pthread_mutex_lock(&miner_state.net_lock);
        if (BIO_write(miner_state.bio, request, strlen(request)) <= 0)
        {
            fprintf(stderr, "Failed to send handshake\n");
            BIO_free(miner_state.bio);
            miner_state.bio = NULL;
            pthread_mutex_unlock(&miner_state.net_lock);
            free(websocket_key);
            sleep(10);
            continue;
        }
        pthread_mutex_unlock(&miner_state.net_lock);

        printf("Connected to server\n");
        atomic_store(&miner_state.connected, true);
        miner_state.fail_counter = 0;
        free(websocket_key);

        BIO_set_nbio(miner_state.bio, 1);

        /* Receive job messages */
        uint8_t buffer[MAX_BUFFER_SIZE];
        uint8_t in_buf[MAX_BUFFER_SIZE];
        int bytes_read;

        while (!atomic_load(&miner_state.exit_flag) && miner_state.fail_counter < 20)
        {
            pthread_mutex_lock(&miner_state.net_lock);
            bytes_read = BIO_read(miner_state.bio, buffer, sizeof(buffer));
            pthread_mutex_unlock(&miner_state.net_lock);

            if (bytes_read <= 0)
            {
                usleep(100000); /* 100ms */
                continue;
            }

            if (buffer[0] != 0x81 || bytes_read < 4)
            {
                continue;
            }

            uint16_t length = (buffer[2] << 8) | buffer[3];
            if (length < 1 || length > MAX_BUFFER_SIZE - 4)
            {
                continue;
            }

            memcpy(in_buf, &buffer[4], length);
            in_buf[length] = '\0';

            /* Send any queued solutions from mining threads */
            send_queued_solutions(&miner_state);

            /* Parse JSON and extract fields BEFORE acquiring job_lock */
            cJSON *template = cJSON_Parse((const char *)in_buf);
            if (!template)
            {
                continue;
            }

            cJSON *diff = cJSON_GetObjectItemCaseSensitive(template, "difficultyuint64");
            cJSON *blob_hash = cJSON_GetObjectItemCaseSensitive(template, "blockhashing_blob");
            cJSON *job_id = cJSON_GetObjectItemCaseSensitive(template, "jobid");
            cJSON *blocks = cJSON_GetObjectItemCaseSensitive(template, "blocks");
            cJSON *miniblocks = cJSON_GetObjectItemCaseSensitive(template, "miniblocks");
            cJSON *rejects = cJSON_GetObjectItemCaseSensitive(template, "rejected");
            cJSON *height_obj = cJSON_GetObjectItemCaseSensitive(template, "height");

            if (diff && blob_hash && job_id && blocks && miniblocks && rejects && height_obj)
            {
                /* Duplicate strings BEFORE acquiring job_lock */
                char *new_blob = strdup(blob_hash->valuestring);
                char *new_job_id = strdup(job_id->valuestring);

                if (new_blob && new_job_id)
                {
                    /* IMPORTANT: Acquire locks in SAME order as send_template: job_lock THEN net_lock (if needed) */
                    /* But we don't need net_lock here, only job_lock */
                    pthread_mutex_lock(&miner_state.job_lock);

                    if (miner_state.blob_hash)
                        free(miner_state.blob_hash);
                    if (miner_state.job_id)
                        free(miner_state.job_id);

                    miner_state.blob_hash = new_blob;
                    miner_state.job_id = new_job_id;
                    miner_state.difficulty = diff->valuedouble;
                    miner_state.height = height_obj->valueint;
                    miner_state.blocks_count = blocks->valueint;
                    miner_state.miniblocks_count = miniblocks->valueint;
                    miner_state.rejects_count = rejects->valueint;
                    atomic_fetch_add(&miner_state.template_version, 1);

                    pthread_mutex_unlock(&miner_state.job_lock);
                }
                else
                {
                    if (new_blob)
                        free(new_blob);
                    if (new_job_id)
                        free(new_job_id);
                }
            }

            cJSON_Delete(template);
        }

        pthread_mutex_lock(&miner_state.net_lock);
        if (miner_state.bio)
        {
            BIO_ssl_shutdown(miner_state.bio);
            BIO_free(miner_state.bio);
            miner_state.bio = NULL;
        }
        pthread_mutex_unlock(&miner_state.net_lock);

        atomic_store(&miner_state.connected, false);
        miner_state.fail_counter = 0;

        if (!atomic_load(&miner_state.exit_flag))
        {
            sleep(5);
        }

    } while (!atomic_load(&miner_state.exit_flag));

    /* Wait for threads to complete */
    for (uint8_t i = 0; i < threads; i++)
    {
        pthread_join(miner_threads[i], NULL);
    }

    /* Cleanup */
    if (miner_state.ssl_ctx)
        SSL_CTX_free(miner_state.ssl_ctx);
    if (miner_state.blob_hash)
        free(miner_state.blob_hash);
    if (miner_state.job_id)
        free(miner_state.job_id);
    free_workspace(workplace, total_mem);

    pthread_mutex_destroy(&miner_state.job_lock);
    pthread_mutex_destroy(&miner_state.net_lock);
    pthread_mutex_destroy(&miner_state.queue_lock);

    /* Cleanup any remaining queued solutions */
    pthread_mutex_lock(&miner_state.queue_lock);
    for (uint32_t i = miner_state.queue_head; i != miner_state.queue_tail;
         i = (i + 1) % MAX_SOLUTION_QUEUE)
    {
        if (miner_state.solution_queue[i].json)
            free(miner_state.solution_queue[i].json);
    }
    pthread_mutex_unlock(&miner_state.queue_lock);

    free(node);
    free(wallet);

    printf("Miner shutdown complete\n");
    return 0;

error_cleanup:
    if (miner_state.ssl_ctx)
        SSL_CTX_free(miner_state.ssl_ctx);
    if (miner_state.blob_hash)
        free(miner_state.blob_hash);
    if (miner_state.job_id)
        free(miner_state.job_id);
    pthread_mutex_destroy(&miner_state.job_lock);
    pthread_mutex_destroy(&miner_state.net_lock);
    pthread_mutex_destroy(&miner_state.queue_lock);

error_exit:
    if (node)
        free(node);
    if (wallet)
        free(wallet);
    return 1;
}

char *generate_websocket_key(void)
{
    unsigned char buffer[KEY_SIZE];

    if (RAND_bytes(buffer, sizeof(buffer)) != 1)
    {
        fprintf(stderr, "Failed to generate random bytes\n");
        return NULL;
    }

    BIO *mem_bio = BIO_new(BIO_s_mem());
    BIO *base64_bio = BIO_new(BIO_f_base64());
    if (!mem_bio || !base64_bio)
    {
        if (mem_bio)
            BIO_free(mem_bio);
        if (base64_bio)
            BIO_free(base64_bio);
        return NULL;
    }

    BIO_set_flags(base64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(base64_bio, mem_bio);
    BIO_write(base64_bio, buffer, sizeof(buffer));
    BIO_flush(base64_bio);

    BUF_MEM *mem_buf;
    BIO_get_mem_ptr(mem_bio, &mem_buf);

    char *result = strndup(mem_buf->data, mem_buf->length);
    BIO_free(base64_bio);

    return result;
}

/* Queue a solution for sending - non-blocking, mining threads return immediately */
void queue_solution(MinerState *state, char *json, uint8_t tid)
{
    if (!state || !json)
        return;

    pthread_mutex_lock(&state->queue_lock);

    /* Check if queue is full */
    uint32_t next_tail = (state->queue_tail + 1) % MAX_SOLUTION_QUEUE;
    if (next_tail == state->queue_head)
    {
        fprintf(stderr, "Solution queue full, dropping solution\n");
        pthread_mutex_unlock(&state->queue_lock);
        return;
    }

    /* Queue the solution */
    state->solution_queue[state->queue_tail].json = strdup(json);
    state->solution_queue[state->queue_tail].thread_id = tid;
    state->queue_tail = next_tail;

    pthread_mutex_unlock(&state->queue_lock);
}

/* Send queued solutions - called from main receive loop */
void send_queued_solutions(MinerState *state)
{
    while (1)
    {
        pthread_mutex_lock(&state->queue_lock);

        if (state->queue_head == state->queue_tail)
        {
            /* Queue is empty */
            pthread_mutex_unlock(&state->queue_lock);
            break;
        }

        /* Get next solution to send */
        SolutionQueueEntry entry = state->solution_queue[state->queue_head];
        state->queue_head = (state->queue_head + 1) % MAX_SOLUTION_QUEUE;

        pthread_mutex_unlock(&state->queue_lock);

        if (!entry.json || !state->bio)
            continue;

        size_t json_len = strlen(entry.json);
        if (json_len > 0xFFFF)
        {
            fprintf(stderr, "JSON payload too large for WebSocket frame\n");
            free(entry.json);
            continue;
        }

        /* Prepare WebSocket frame */
        int frame_size = 4 + json_len;
        char *frame = malloc(frame_size);
        if (!frame)
        {
            fprintf(stderr, "Failed to allocate frame buffer\n");
            free(entry.json);
            continue;
        }

        frame[0] = 0x81; /* Text frame, FIN bit set */
        frame[1] = 0x7E; /* 16-bit length follows */
        frame[2] = (json_len >> 8) & 0xFF;
        frame[3] = json_len & 0xFF;
        memcpy(frame + 4, entry.json, json_len);

        /* Try to send */
        pthread_mutex_lock(&state->net_lock);
        if (state->bio && BIO_write(state->bio, frame, frame_size) > 0)
        {
            BIO_flush(state->bio);

            time_t rawtime;
            time(&rawtime);
            struct tm *info = localtime(&rawtime);

            printf("\n\rThread %s%d%s found a nonce! Height %s%ld%s (diff %s%.0f%s) %s",
                   KRED, entry.thread_id, KNRM, KCYN, state->height, KNRM, KYEL, state->difficulty, KNRM,
                   asctime(info));
        }
        else
        {
            fprintf(stderr, "Failed to send WebSocket frame\n");
        }
        pthread_mutex_unlock(&state->net_lock);

        free(frame);
        free(entry.json);
    }
}

void send_template(MinerState *state, char *json, int tid)
{
    /* Just queue it - don't block on network I/O */
    queue_solution(state, json, tid);
}

void print_status(MinerState *state)
{
    if (!state)
        return;

    printf("\rHeight: %s%10ld%s | Diff: %s%12.0f%s | HR: %6s%d H/s%s | "
           "Blocks: %s%4d%s | MBLs: %s%4d%s | Rejects: %s%4d%s\t\t\r",
           KCYN, state->height, KNRM,
           KYEL, state->difficulty, KNRM,
           KGRN, state->hashrate_old, KNRM,
           KGRN, state->blocks_count, KNRM,
           KGRN, state->miniblocks_count, KNRM,
           KRED, state->rejects_count, KNRM);
    fflush(stdout);
}

/* Main mining worker thread */
static void *mine_block_worker(void *arg)
{
    ThreadContext *ctx = (ThreadContext *)arg;
    if (!ctx || !ctx->state || !ctx->workspace)
    {
        return NULL;
    }

    MinerState *state = ctx->state;
    uint8_t *work = ctx->workspace;
    uint8_t tid = ctx->thread_id;

    uint8_t in[MINIBLOCK_SIZE * 2];
    uint8_t out[32];
    uint8_t workHex[MINIBLOCK_SIZE * 2 + 1];
    uint16_t last_template_version = 0;

    printf("Thread %d started\n", tid);

    while (!atomic_load(&state->exit_flag))
    {
        /* Get current job */
        pthread_mutex_lock(&state->job_lock);
        if (!state->blob_hash || !state->job_id)
        {
            pthread_mutex_unlock(&state->job_lock);
            usleep(50000); /* 50ms */
            continue;
        }

        memcpy(in, state->blob_hash, MINIBLOCK_SIZE * 2);
        last_template_version = atomic_load(&state->template_version);
        pthread_mutex_unlock(&state->job_lock);

        /* Prepare work buffer */
        stringToHex(in, MINIBLOCK_SIZE * 2, work);
        RAND_bytes(&work[MINIBLOCK_SIZE - 8], 8);

        /* Perform AstroBWT hash */
        AstroBWTv3(work, out);

        /* Check if PoW meets difficulty target */
        if (checkPoW(out, state->difficulty) < 0)
        {
            /* Valid proof of work found */
            hexToString(work, workHex);
            workHex[MINIBLOCK_SIZE * 2] = '\0';

            /* Build result JSON */
            cJSON *result = cJSON_CreateObject();
            if (result)
            {
                pthread_mutex_lock(&state->job_lock);
                if (state->job_id)
                {
                    cJSON_AddItemToObject(result, "jobid", cJSON_CreateString(state->job_id));
                }
                pthread_mutex_unlock(&state->job_lock);

                cJSON_AddStringToObject(result, "mbl_blob", (const char *)workHex);
                char *json = cJSON_PrintUnformatted(result);

                if (json && atomic_load(&state->connected))
                {
                    send_template(state, json, tid);
                }

                cJSON_Delete(result);
                if (json)
                    free(json);
            }
        }

        /* Increment hash counter */
        atomic_fetch_add(&state->hashrate, 1);

        /* Update hash rate every second (only main thread) */
        if (tid == 0)
        {
            time_t now;
            time(&now);

            if (state->start_time + 1 <= now)
            {
                state->start_time = now;
                state->hashrate_old = atomic_load(&state->hashrate);
                atomic_store(&state->hashrate, 0);
                print_status(state);
            }
        }
    }

    printf("Thread %d shutting down\n", tid);
    return NULL;
}
