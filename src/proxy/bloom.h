//
// Created by jackson on 6/7/20.
//

#ifndef TLSCACHE_BLOOM_H
#define TLSCACHE_BLOOM_H
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
typedef unsigned int (*hash_func)(const void *data);
typedef struct bloom_filter *bloom_t;

bloom_t bloom_create(size_t size);

void bloom_free(bloom_t filter);

void bloom_add_hash(bloom_t filter, hash_func func);

void bloom_add(bloom_t filter, const void *item);

bool bloom_test(bloom_t filter, const void *item);

#endif //TLSCACHE_BLOOM_H
