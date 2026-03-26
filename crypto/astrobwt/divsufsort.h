#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>

static const int32_t lg_table[256]= {
 -1,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
  5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
};

#define ALPHABET_SIZE 256
#define BUCKET_A_SIZE ALPHABET_SIZE
#define BUCKET_B_SIZE ALPHABET_SIZE * ALPHABET_SIZE
#define BUCKET_A(_c0) bucket_A[(_c0)]
#define BUCKET_B(_c0, _c1) (bucket_B[((_c1) << 8) | (_c0)])
#define BUCKET_BSTAR(_c0, _c1) (bucket_B[((_c0) << 8) | (_c1)])

#define SS_MISORT_STACKSIZE 64
#define SS_INSERTIONSORT_THRESHOLD 8

#define TR_STACKSIZE 64
#define TR_INSERTIONSORT_THRESHOLD 8

typedef struct _trbudget_t trbudget_t;
struct _trbudget_t {
  int32_t chance;
  int32_t remain;
  int32_t incval;
  int32_t count;
};

typedef int32_t saint_t;
typedef int32_t saidx_t;
typedef uint8_t sauchar_t;

#define STACK_PUSH(_a, _b, _c, _d)\
  do {\
    stack[ssize].a = (_a), stack[ssize].b = (_b),\
    stack[ssize].c = (_c), stack[ssize++].d = (_d);\
  } while(0)

#define STACK_PUSH5(_a, _b, _c, _d, _e)\
  do {\
    stack[ssize].a = (_a), stack[ssize].b = (_b),\
    stack[ssize].c = (_c), stack[ssize].d = (_d), stack[ssize++].e = (_e);\
  } while(0)

#define STACK_POP(_a, _b, _c, _d)\
  do {\
    if(ssize == 0) { return; }\
    (_a) = stack[--ssize].a, (_b) = stack[ssize].b,\
    (_c) = stack[ssize].c, (_d) = stack[ssize].d;\
  } while(0)

#define STACK_POP5(_a, _b, _c, _d, _e)\
  do {\
    if(ssize == 0) { return; }\
    (_a) = stack[--ssize].a, (_b) = stack[ssize].b,\
    (_c) = stack[ssize].c, (_d) = stack[ssize].d, (_e) = stack[ssize].e;\
  } while(0)

#define SWAP(_a, _b) do { t = (_a); (_a) = (_b); (_b) = t; } while(0)

void sais(uint8_t *input, uint32_t length, int32_t *indices);
static int32_t sort_typeBstar(const uint8_t *input, int32_t *indices, int32_t *bucket_A, int32_t *bucket_B, int32_t length);
static void construct_SA(const uint8_t *T, int32_t *SA, int32_t *bucket_A, int32_t *bucket_B, int32_t n, int32_t m);

static void sssort(const uint8_t *T, const int32_t *PA, int32_t *first, int32_t *last, int32_t *buf, int32_t bufsize, int32_t depth, int32_t n, int32_t lastsuffix);
static int32_t ss_compare(const uint8_t *T, const int32_t *p1, const int32_t *p2, int32_t depth);
static void ss_mintrosort(const uint8_t *T, const int32_t *PA, int32_t *first, int32_t *last, int32_t depth);
static inline int32_t ss_ilg(int32_t n);
static void ss_insertionsort(const uint8_t *T, const int32_t *PA, int32_t *first, int32_t *last, int32_t depth);
static int32_t ss_compare(const uint8_t *T, const int32_t *p1, const int32_t *p2, int32_t depth);
static void ss_heapsort(const uint8_t *Td, const int32_t *PA, int32_t *SA, int32_t size);
static void ss_fixdown(const uint8_t *Td, const int32_t *PA, int32_t *SA, int32_t i, int32_t size);
static int32_t *ss_partition(const int32_t *PA, int32_t *first, int32_t *last, int32_t depth);
static int32_t *ss_pivot(const uint8_t *Td, const int32_t *PA, int32_t *first, int32_t *last);
static inline int32_t *ss_median3(const uint8_t *Td, const int32_t *PA, int32_t *v1, int32_t *v2, int32_t *v3);
static int32_t *ss_median5(const uint8_t *Td, const int32_t *PA, int32_t *v1, int32_t *v2, int32_t *v3, int32_t *v4, int32_t *v5);

static void trsort(int32_t *ISA, int32_t *SA, int32_t n, int32_t depth);
static inline int32_t tr_ilg(int32_t n);
static void trbudget_init(trbudget_t *budget, int32_t chance, int32_t incval);
static void tr_introsort(int32_t *ISA, const int32_t *ISAd, int32_t *SA, int32_t *first, int32_t *last, trbudget_t *budget);
static void tr_partition(const int32_t *ISAd, int32_t *first, int32_t *middle, int32_t *last, int32_t **pa, int32_t **pb, int32_t v);
static void tr_copy(int32_t *ISA, const int32_t *SA, int32_t *first, int32_t *a, int32_t *b, int32_t *last, int32_t depth);
static void tr_partialcopy(int32_t *ISA, const int32_t *SA, int32_t *first, int32_t *a, int32_t *b, int32_t *last, int32_t depth);
static inline int32_t trbudget_check(trbudget_t *budget, int32_t size);
static void tr_insertionsort(const int32_t *ISAd, int32_t *first, int32_t *last);
static void tr_heapsort(const int32_t *ISAd, int32_t *SA, int32_t size);
static void tr_fixdown(const int32_t *ISAd, int32_t *SA, int32_t i, int32_t size);
static int32_t * tr_pivot(const int32_t *ISAd, int32_t *first, int32_t *last);
static inline int32_t * tr_median3(const int32_t *ISAd, int32_t *v1, int32_t *v2, int32_t *v3);
static int32_t * tr_median5(const int32_t *ISAd, int32_t *v1, int32_t *v2, int32_t *v3, int32_t *v4, int32_t *v5);

static int sort_typeBstar_compute_lcp(const sauchar_t *T, saidx_t *SA, saidx_t *LCP,
               saidx_t *bucket_A, saidx_t *bucket_B,
               saidx_t n);

static void construct_SA_LCP(const sauchar_t *T, saidx_t *SA, saidx_t *LCP,
             saidx_t *bucket_A, saidx_t *bucket_B, saidx_t *min_stack,
             saidx_t *last_induced_from, saidx_t n, saidx_t m);