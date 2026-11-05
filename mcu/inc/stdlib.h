#ifndef FW_STDLIB_H
#define FW_STDLIB_H
#include <stddef.h>
void* malloc(size_t n); void free(void* p); void* realloc(void* p, size_t n); void* calloc(size_t a, size_t b);
void abort(void);
#endif
