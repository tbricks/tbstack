/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL TBRICKS
 * AB BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THISS OFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef __8a2a3b50_986f_11e3_aa30_efef7030cdbc
#define __8a2a3b50_986f_11e3_aa30_efef7030cdbc

#include <stdint.h>
#include <string.h>

#define MEM_REGION_TYPE_EMPTY    0
#define MEM_REGION_TYPE_MALLOC   1
#define MEM_REGION_TYPE_MMAP     2
#define MEM_REGION_TYPE_VDSO     3
#define MEM_REGION_TYPE_VSYSCALL 4
#define MEM_REGION_TYPE_DELETED  5

struct mem_data_chunk
{
    /* start in process' address space */
    void *start;
    /* allocated memory */
    char *data;
    /* data size */
    size_t length;
    /* next list element */
    struct mem_data_chunk *next;
};

struct mem_region
{
    /* start in process' address space */
    void *start;
    /* memory length */
    size_t length;
    /* file offset */
    size_t offset;

    /* list of copied data chunks */
    struct mem_data_chunk *data_head;
    /* sorted index for binary search */
    struct mem_data_chunk **data_index;
    /* number of data chunks in index */
    size_t num_data_chunks;
    /* cached result of previous lookup */
    struct mem_data_chunk *prev_accessed_chunk;

    /* points to build label cover and copy needed memory contents */
    void **labels;
    /* number of points (normally 1) */
    size_t num_labels;

    /* path of mmapped file */
    char *path;
    /* file descriptor */
    int fd;
    /* type of region */
    int type;

    /* next list element */
    struct mem_region *next;
};

struct mem_map
{
    /* list of regions */
    struct mem_region *list_head;
    /* sorted index for binary search */
    struct mem_region **list_index;
    /* number of regions in index */
    size_t num_regions;
    /* cached result of previous lookup */
    struct mem_region *prev_accessed_region;
};

/*
 * mem region
 */

const char *str_mem_region_type(int type);

void mem_region_init(struct mem_region *region);

/*
 * mem map
 */
void mem_map_init(struct mem_map *map);

int mem_map_add_region(struct mem_map *map, struct mem_region *region);

void mem_map_create_region_index(struct mem_map *map);

int mem_map_add_label(struct mem_map *map, void *label, size_t reserve);

int mem_map_build_label_cover(struct mem_map *map, size_t generic_chunk_size,
        struct mem_data_chunk **chunks, size_t align);

struct mem_region *mem_map_get_file_region(struct mem_map *map, void *addr);

struct mem_data_chunk *mem_region_find_data_chunk(
        struct mem_region *region, void *addr);

int mem_map_read_word(struct mem_map *map, void *addr, uintptr_t *value);

void mem_map_destroy(struct mem_map *map);

void mem_map_print(const struct mem_map *map);

#endif

