/*
 * ============================================================================
 * C-Miner - Global Master Header
 * ============================================================================
 * Include this file first in all C source files
 *
 * This header provides:
 * - Standard library includes (OpenSSL, cJSON, POSIX, etc.)
 * - Global configuration macros
 * - Project-wide type definitions
 * - Unified access to all project modules
 */

#ifndef CMINER_H
#define CMINER_H

/* ============================================================================
 * Standard Library Includes
 * ============================================================================ */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>

#include <locale.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <linux/mman.h>

#include <pthread.h>
#include <sched.h>

#include <gmp.h>

/* ============================================================================
 * Global Configuration
 * ============================================================================ */

/* Terminal color codes */
#define KNRM "\x1B[0m"
#define KRED "\x1B[31m"
#define KGRN "\x1B[32m"
#define KYEL "\x1B[33m"
#define KBLU "\x1B[34m"
#define KMAG "\x1B[35m"
#define KCYN "\x1B[36m"
#define KWHT "\x1B[37m"

/* Miner configuration constants */
#define MAX_BUFFER_SIZE 1024
#define KEY_SIZE 16
#define MAX_THREADS 64
#define MAX_SOLUTION_QUEUE 256

/* ============================================================================
 * Module Interfaces
 * ============================================================================ */

/* Base module - hash and string utilities (unified via pow.h) */
#include "pow.h"

/* Crypto module - all cryptographic algorithms */
#include "crypto/astrobwt/astrobwt.h"
#include "crypto/salsa/salsa.h"

#endif /* CMINER_H */
