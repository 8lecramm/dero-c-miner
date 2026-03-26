/*
 * C-Miner Configuration Header
 * Contains global includes and macro definitions
 */

#ifndef C_MINER_CONFIG_H
#define C_MINER_CONFIG_H

/* Standard C library includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <cjson/cJSON.h>
#include <locale.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <stdbool.h>
#include <gmp.h>

/* Color codes for terminal output */
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"

/* Miner configuration macros */
#define MAX_BUFFER_SIZE 1024
#define KEY_SIZE 16
#define MAX_THREADS 64
#define MAX_SOLUTION_QUEUE 256

#endif /* C_MINER_CONFIG_H */
