/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
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
    void *start;
    char *data;
    size_t length;
    struct mem_data_chunk *next;
};

struct mem_region
{
    void *start;
    size_t length;
    size_t offset;

    struct mem_data_chunk *data_head;
    struct mem_data_chunk **data_index;
    size_t num_data_chunks;
    struct mem_data_chunk *prev_accessed_chunk;

    void **labels;
    size_t num_labels;

    char *path;
    int fd;
    int type;

    struct mem_region *next;
};

struct mem_map
{
    struct mem_region *list_head;
    struct mem_region **list_index;
    size_t num_regions;
    struct mem_region *prev_accessed_region;
};

/*
 * mem region
 */
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

int mem_map_read_word(struct mem_map *map, void *addr, uint64_t *value);

void mem_map_destroy(struct mem_map *map);

void mem_map_print(const struct mem_map *map);

#endif

