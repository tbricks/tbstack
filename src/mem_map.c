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

#include "mem_map.h"
#include "proc.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef VSYSCALL_START
#define VSYSCALL_START (-10UL << 20)
#endif

extern int opt_verbose;
extern int opt_ignore_deleted;

static int in(const void *point, const void *start, size_t size)
{
    return ((point >= start) &&
            ((const char *)point < ((const char *)start + size)));
}

static void mem_data_chunk_init(struct mem_data_chunk *chunk)
{
    chunk->start = NULL;
    chunk->data = NULL;
    chunk->length = 0;
    chunk->next = NULL;
}

static int mem_data_chunk_read_word(struct mem_data_chunk *chunk,
        void *addr, uintptr_t *value)
{
    size_t offset = (size_t)addr - (size_t)chunk->start;
    assert(offset < chunk->length);
    *value = *(uintptr_t *)(chunk->data + offset);
    return 0;
}

static void mem_data_chunk_destroy(struct mem_data_chunk *chunk, int type)
{
    switch (type)
    {
    case MEM_REGION_TYPE_MALLOC:
        free(chunk->data);
        break;

    case MEM_REGION_TYPE_MMAP:
        munmap(chunk->data, chunk->length);
        break;

    default:
        break;
    }
    free(chunk);
}

static void mem_data_chunk_list_destroy(struct mem_data_chunk *chunk, int type)
{
    struct mem_data_chunk *next;
    while (chunk != NULL) {
        next = chunk->next;
        mem_data_chunk_destroy(chunk, type);
        chunk = next;
    }
}

void mem_region_init(struct mem_region *region)
{
    region->start = NULL;
    region->length = 0;
    region->offset = 0;

    region->data_head = NULL;
    region->data_index = NULL;
    region->num_data_chunks = 0;
    region->prev_accessed_chunk = NULL;

    region->labels = NULL;
    region->num_labels = 0;

    region->path = NULL;
    region->fd = -1;
    region->type = MEM_REGION_TYPE_EMPTY;

    region->next = NULL;
}

static void mem_region_add_label(struct mem_region *region,
        void *label, size_t reserve)
{
    size_t i;

    if (region->labels == NULL)
        region->labels = malloc(sizeof(void *)*reserve);

    for (i = 0; i < region->num_labels; ++i) {
        if (region->labels[i] > label) {
            memmove(&region->labels[i+1], &region->labels[i],
                    sizeof(void*) * (region->num_labels - i));
            break;
        }
    }

    region->labels[i] = label;
    ++region->num_labels;
}

static int mem_region_add_data_chunk(struct mem_region *region,
        struct mem_data_chunk *chunk)
{
    size_t i;
    struct mem_data_chunk **cur = &region->data_head;
    void *chunk_ceil;

    chunk_ceil = (char *)chunk->start + chunk->length;
    region->type = MEM_REGION_TYPE_MALLOC;

    for (i = 0; i < region->num_data_chunks; ++i) {
        if (in(chunk->start, (*cur)->start, (*cur)->length) ||
            in(chunk_ceil, (*cur)->start, (*cur)->length))
        {
            fprintf(stderr, "error: overlapping chunks: existing: %p-%p "
                            "new: %p-%p\n",
                            (*cur)->start,
                            (*cur)->start + (*cur)->length,
                            chunk->start,
                            chunk_ceil);
            return -1;
        }
        if ((*cur)->start > chunk->start)
            break;
        cur = &(*cur)->next;
    }

    chunk->next = *cur;
    *cur = chunk;
    ++region->num_data_chunks;
    return 0;
}

static struct mem_data_chunk *mem_region_alloc_chunk(struct mem_region *region,
        void *start, void *end, size_t align)
{
    struct mem_data_chunk *chunk;
    int rc;

    chunk = malloc(sizeof(struct mem_data_chunk));
    mem_data_chunk_init(chunk);

    chunk->start = start;
    chunk->length = (size_t)end - (size_t)start;
    rc = posix_memalign((void **)&chunk->data, align, chunk->length);
    if (rc < 0) {
        perror("posix_memalign");
        return NULL;
    }

    mem_region_add_data_chunk(region, chunk);
    return chunk;
}

const char *str_mem_region_type(int type)
{
    switch (type)
    {
    case MEM_REGION_TYPE_EMPTY:
        return "empty";
    case MEM_REGION_TYPE_MALLOC:
        return "malloc";
    case MEM_REGION_TYPE_MMAP:
        return "mmap";
    case MEM_REGION_TYPE_VDSO:
        return "vdso";
    case MEM_REGION_TYPE_VSYSCALL:
        return "vsyscall";
    case MEM_REGION_TYPE_DELETED:
        return "deleted";
    default:
        break;
    }
    return "unknown";
}

static void mem_region_print(const struct mem_region *region)
{
    fprintf(stderr,
            "region addr: %zx-%zx len: %zx off: %zx num_chunks: %zd "
            "path='%s' fd=%d type=%s\n",
            (size_t)region->start,
            (size_t)region->start+region->length,
            region->length,
            region->offset,
            region->num_data_chunks,
            region->path,
            region->fd,
            str_mem_region_type(region->type));
}

static void mem_region_create_data_chunk_index(struct mem_region *region)
{
    int i;
    struct mem_data_chunk *cur;

    if (!region->num_data_chunks)
        return;

    region->data_index = malloc(sizeof(
                struct mem_data_chunk*) * region->num_data_chunks);

    cur = region->data_head;
    for (i = 0; cur != NULL; cur = cur->next) {
        region->data_index[i++] = cur;

        if (i > (int)region->num_data_chunks) {
            fprintf(stderr, "region %p: num_data_chunks=%zd but cur != NULL\n",
                    region, region->num_data_chunks);
            mem_region_print(region);
            break;
        }
    }
}

static char *addr_increment_clamped(char *start, char *end, size_t increment)
{
    assert(end >= start);
    return ((size_t)(end - start) <= increment) ?
            end : start + increment;
}

static int mem_region_build_label_cover(struct mem_region *region,
        size_t generic_chunk_size, struct mem_data_chunk **chunks, size_t align)
{
    size_t i, n = 0;

    if (region->num_labels == 0)
        return 0;

    for (i = 0; i < region->num_labels; ++i) {
        char *cur_start, *cur_end, *region_end;
        struct mem_data_chunk *new_chunk;

        region_end = (char *)region->start + region->length;
        cur_start = region->labels[i];
        cur_end = addr_increment_clamped(cur_start, region_end, generic_chunk_size);

        for (++i; i < region->num_labels; ++i) {
            if ((size_t)region->labels[i] <= (size_t)cur_end) {
                cur_end = addr_increment_clamped((char *)region->labels[i],
                                                 region_end, generic_chunk_size);
                if (cur_end == region_end)
                    break;
            }
        }

        new_chunk = mem_region_alloc_chunk(region, cur_start, cur_end, align);
        chunks[n] = new_chunk;
        ++n;
    }

    mem_region_create_data_chunk_index(region);

    return n;
}

static int mem_region_map_file(struct mem_region *region)
{
    void *data;
    struct stat stat_buf;
    size_t length = region->length;

    if (region->path == NULL || *region->path == '\0') {
        fprintf(stderr, "trying to map file for region %p-%p "
                "with empty path\n",
                region->start, region->start + region->length);
        return -1;
    }

    region->fd = open(region->path, O_RDONLY);
    if (region->fd < 0) {
        perror(region->path);
        return -1;
    }

    if (fstat(region->fd, &stat_buf) < 0) {
        int err = errno;
        fprintf(stderr, "failed to stat file %s: %s\n", region->path, strerror(err));
        return -1;
    }

    if (region->offset > (size_t)stat_buf.st_size) {
        return -1;
    }

    // Accessing beyond the length of the file, even though we can map a
    // region larger than the size of the file, will cause a SIGBUS, so
    // truncate the length of the map to fit within the file.
    if (region->length > stat_buf.st_size - region->offset) {
        length = stat_buf.st_size - region->offset;
    }

    data = mmap(NULL, length, PROT_READ, MAP_SHARED, region->fd,
                region->offset);

    if (data == MAP_FAILED) {
        int err = errno;
        fprintf(stderr, "failed to mmap file %s (length 0x%zx, read, offset "
                "0x%zx): %s\n", region->path, region->length, region->offset,
                strerror(err));
        return -1;
    }

    region->data_head = malloc(sizeof(struct mem_data_chunk));
    mem_data_chunk_init(region->data_head);
    region->data_head->start = region->start;
    region->data_head->data = data;
    region->data_head->length = length;

    region->data_index = malloc(sizeof(struct mem_data_chunk**));
    *region->data_index = region->data_head;
    ++region->num_data_chunks;

    region->prev_accessed_chunk = region->data_head;

    return 0;
}

static int mem_region_init_vdso(struct mem_region *region)
{
    region->data_head = malloc(sizeof(struct mem_data_chunk));
    mem_data_chunk_init(region->data_head);
    region->data_head->start = region->start;
    region->data_head->length = region->length;

    if ((region->data_head->data = (char *)get_vdso()) == NULL)
        return -1;

    region->data_index = malloc(sizeof(struct mem_data_chunk**));
    *region->data_index = region->data_head;
    ++region->num_data_chunks;

    region->prev_accessed_chunk = region->data_head;

    return 0;
}

static int mem_region_init_vsyscall(struct mem_region *region)
{
    region->data_head = malloc(sizeof(struct mem_data_chunk));
    mem_data_chunk_init(region->data_head);
    region->data_head->start = region->start;
    region->data_head->data = (char *)VSYSCALL_START;
    region->data_head->length = region->length;

    region->data_index = malloc(sizeof(struct mem_data_chunk**));
    *region->data_index = region->data_head;
    ++region->num_data_chunks;

    region->prev_accessed_chunk = region->data_head;

    return 0;
}

static int addr_data_chunk_compar(const void *key, const void *member)
{
    const struct mem_data_chunk* const *chunk = member;
    if (key < (*chunk)->start)
        return -1;
    if (in(key, (*chunk)->start, (*chunk)->length))
        return 0;
    return 1;
}

struct mem_data_chunk *mem_region_find_data_chunk(
        struct mem_region *region, void *addr)
{
    struct mem_data_chunk **chunk_ptr, *chunk;

    chunk = region->prev_accessed_chunk;
    if (chunk != NULL && !addr_data_chunk_compar(addr, &chunk))
        return chunk;

    if (region->data_index == NULL) {
        if (region->num_data_chunks) {
            fprintf(stderr,
                    "error: region %p-%p is not indexed but "
                    "attempting to read word\n",
                    region->start,
                    region->start + region->length);
        }
        return NULL;
    }

    chunk_ptr = (struct mem_data_chunk **)bsearch(addr,
            region->data_index,
            region->num_data_chunks,
            sizeof(struct mem_data_chunk*),
            addr_data_chunk_compar);

    if (chunk_ptr == NULL)
        return NULL;

    chunk = *chunk_ptr;
    region->prev_accessed_chunk = chunk;
    return chunk;
}

static int mem_region_read_word(struct mem_region *region,
        void *addr, uintptr_t *value)
{
    struct mem_data_chunk *chunk;

    switch (region->type) {
    case MEM_REGION_TYPE_EMPTY:
        fprintf(stderr,
                "error: trying to read word from empty region %p-%p\n",
                region->start,
                region->start + region->length);
        return -1;

    case MEM_REGION_TYPE_DELETED:
        if (!opt_ignore_deleted)
            return -2;

    case MEM_REGION_TYPE_MMAP:
        if (region->fd < 0 && mem_region_map_file(region) < 0)
            return -1;
        break;

    case MEM_REGION_TYPE_VDSO:
        if (region->data_head == NULL && mem_region_init_vdso(region) < 0)
            return -1;
        break;

    case MEM_REGION_TYPE_VSYSCALL:
        if (region->data_head == NULL && mem_region_init_vsyscall(region) < 0)
            return -1;
        break;

    default:
        break;
    }

    if (value == NULL)
        return 0;

    chunk = mem_region_find_data_chunk(region, addr);

    if (chunk == NULL) {
        size_t i;

        if (!opt_verbose)
            return -1;

        fprintf(stderr,
                "no chunk of memory containing %p at region %p-%p\n",
                addr, region->start, region->start + region->length);
        mem_region_print(region);

        for (i = 0; i < region->num_data_chunks; ++i) {
            struct mem_data_chunk *chunk = region->data_index[i];
            fprintf(stderr, "chunk %zd: start %p length 0x%zx data %p\n",
                    i, chunk->start, chunk->length, chunk->data);
        }
        return -1;
    }

    return mem_data_chunk_read_word(chunk,
            addr,
            value);
}

static void mem_region_destroy(struct mem_region *region)
{
    if (region->data_head != NULL)
        mem_data_chunk_list_destroy(region->data_head, region->type);
    free(region->data_index);
    if (region->fd >= 0)
        close(region->fd);
    free(region->labels);
    free(region->path);
    free(region);
}

static void mem_region_list_destroy(struct mem_region *region)
{
    struct mem_region *next;
    while (region != NULL) {
        next = region->next;
        mem_region_destroy(region);
        region = next;
    }
}

void mem_map_init(struct mem_map *map)
{
    map->list_head = NULL;
    map->list_index = NULL;
    map->num_regions = 0;
    map->prev_accessed_region = NULL;
}

int mem_map_add_region(struct mem_map *map, struct mem_region *region)
{
    size_t i;
    struct mem_region **cur = &map->list_head;
    struct mem_region *prev = map->prev_accessed_region;
    void *region_ceil;

    region_ceil = (char *)region->start + region->length;

    if (prev != NULL && prev->next == NULL) {
        if ((char *)region->start >= ((char *)prev->start + prev->length)) {
            prev->next = region;
            ++map->num_regions;
            map->prev_accessed_region = region;
            return 0;
        }
    }

    for (i = 0; i < map->num_regions; ++i) {
        if (in(region->start, (*cur)->start, (*cur)->length) ||
            in(region_ceil, (*cur)->start, (*cur)->length))
        {
            fprintf(stderr, "error: overlapping regions: existing: %p-%p "
                            "new: %p-%p\n",
                            (*cur)->start,
                            (*cur)->start+(*cur)->length,
                            region->start,
                            region_ceil);
            return -1;
        }
        if ((*cur)->start > region->start)
            break;
        cur = &(*cur)->next;
    }

    region->next = *cur;
    *cur = region;
    ++map->num_regions;
    map->prev_accessed_region = region;
    return 0;
}

void mem_map_create_region_index(struct mem_map *map)
{
    int i;
    struct mem_region *cur;

    if (!map->num_regions)
        return;

    map->list_index = malloc(sizeof(struct mem_region*) * map->num_regions);
    cur = map->list_head;
    for (i = 0; cur != NULL; cur = cur->next) {
        map->list_index[i++] = cur;
    }
}

static int addr_region_compar(const void *key, const void *member)
{
    const struct mem_region* const *region = member;

    if (key < (*region)->start)
        return -1;
    if (in(key, (*region)->start, (*region)->length))
        return 0;
    return 1;
}

static struct mem_region *mem_map_find_region(struct mem_map *map, void *addr)
{
    struct mem_region **region_ptr, *region;

    region = map->prev_accessed_region;
    if (region != NULL && !addr_region_compar(addr, &region))
        return region;

    if (map->list_index == NULL) {
        if (map->num_regions) {
            fprintf(stderr,
                    "error: map is not indexed but attempting to find region\n");
        }
        return NULL;
    }

    region_ptr = (struct mem_region **)bsearch(addr,
            map->list_index,
            map->num_regions,
            sizeof(struct mem_region*),
            addr_region_compar);

    if (region_ptr == NULL) {
        fprintf(stderr,
                "cannot find region of memory containing %p\n",
                addr);
        region = NULL;
    } else {
        region = *region_ptr;
        map->prev_accessed_region = region;
    }

    return region;
}

struct mem_region *mem_map_get_file_region(struct mem_map *map, void *addr)
{
    struct mem_region *region;

    if ((region = mem_map_find_region(map, addr)) == NULL) {
        fprintf(stderr, "cannot get file region\n");
        return NULL;
    }

    if (region->type != MEM_REGION_TYPE_MMAP &&
            region->type != MEM_REGION_TYPE_DELETED &&
            region->type != MEM_REGION_TYPE_VDSO &&
            region->type != MEM_REGION_TYPE_VSYSCALL) {
        fprintf(stderr, "get file region: unexpected region type %s\n",
                str_mem_region_type(region->type));
        mem_region_print(region);
        return NULL;
    }

    if (region->fd < 0 && mem_region_read_word(region, addr, NULL) == -1)
        return NULL;

    return region;
}

int mem_map_add_label(struct mem_map *map, void *label, size_t reserve)
{
    struct mem_region *region;

    region = mem_map_find_region(map, label);
    if (region == NULL)
        return -1;

    mem_region_add_label(region, label, reserve);
    return 0;
}

int mem_map_build_label_cover(struct mem_map *map, size_t generic_chunk_size,
        struct mem_data_chunk **chunks, size_t align)
{
    struct mem_region *cur;
    int n = 0;

    cur = map->list_head;
    while (cur != NULL) {
        n += mem_region_build_label_cover(
                cur, generic_chunk_size, chunks + n, align);
        cur = cur->next;
    }

    return n;
}

int mem_map_read_word(struct mem_map *map, void *addr, uintptr_t *value)
{
    struct mem_region *region;

    region = mem_map_find_region(map, addr);
    if (region == NULL)
        return -1;

    return mem_region_read_word(region,
            addr,
            value);
}

void mem_map_destroy(struct mem_map *map)
{
    if (map->list_head != NULL)
        mem_region_list_destroy(map->list_head);
    free(map->list_index);
    free(map);
}

void mem_map_print(const struct mem_map *map)
{
    struct mem_region *region;

    fprintf(stderr, "mem map with %zd regions\n", map->num_regions);
    region = map->list_head;
    for (; region != NULL; region = region->next)
        mem_region_print(region);
}
