/*
 * tbstack -- fast stack trace utility
 *
 * Copyright (c) 2014, Tbricks AB
 * All rights reserved.
 */

#include "mem_map.h"
#include "snapshot.h"
#include "unwind.h"

#include <dwarf.h>
#include <gelf.h>
#include <libelf.h>
#include <libgen.h>
#include <libunwind.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>

/*
 * search unwind table for a procedure (used by find_proc_info)
 */
#define search_unwind_table UNW_OBJ(dwarf_search_unwind_table)

extern int search_unwind_table(unw_addr_space_t as, unw_word_t ip,
        unw_dyn_info_t *di, unw_proc_info_t *pip,
        int need_unwind_info, void *arg);


#ifdef HAVE_DWARF
#define dwarf_find_debug_frame UNW_OBJ(dwarf_find_debug_frame)

extern int
UNW_OBJ(dwarf_find_debug_frame)(int found, unw_dyn_info_t *di_debug,
                                unw_word_t ip,
                                unw_word_t segbase,
                                const char *obj_name, unw_word_t start,
                                unw_word_t end);
#endif


/*
 * get dwarf encoded value
 */
static ssize_t dw_get_value(char *data, unsigned char enc,
        uint64_t cur, uint64_t *value)
{
    int64_t number = 0;
    size_t size;

    if (enc == DW_EH_PE_omit) {
        *value = 0;
        return 0;
    }

    if (enc == DW_EH_PE_absptr) {
        *value = *(uint64_t *)data;
        return 8;
    }

    switch (enc & 0xf)
    {
    case DW_EH_PE_udata2:
        number = *(uint16_t *)data;
        size = 2;
        break;

    case DW_EH_PE_sdata2:
        number = *(int16_t *)data;
        size = 2;
        break;

    case DW_EH_PE_udata4:
        number = *(uint32_t *)data;
        size = 4;
        break;

    case DW_EH_PE_sdata4:
        number = *(int32_t *)data;
        size = 4;
        break;

    case DW_EH_PE_udata8:
        number = *(uint64_t *)data;
        size = 8;
        break;

    case DW_EH_PE_sdata8:
        number = *(int64_t *)data;
        size = 8;
        break;

    default:
        fprintf(stderr, "unsupported encoding in "
                ".eh_frame_hdr: %d\n", (int)enc);
        return -1;
    }

    switch (enc & 0xf0) {
    case DW_EH_PE_absptr:
        *value = number;
        break;

    case DW_EH_PE_pcrel:
        *value = cur + number;
        break;

    default:
        return -1;
    }

    return size;
}

/*
 * parse contents of .eh_frame_hdr
 */
static int parse_eh_frame_hdr(char *data, size_t pos,
        uint64_t *table_data, uint64_t *fde_count)
{
    char version, eh_frame_ptr_enc, fde_count_enc;
    ssize_t size;
    uint64_t eh_frame_ptr;

    version = data[0];
    eh_frame_ptr_enc = data[1];
    fde_count_enc = data[2];
    data += 4;
    pos += 4;

    if (version != 1) {
        fprintf(stderr, "unknown .ehf_frame_hdr version %d\n", version);
        return -1;
    }

    size = dw_get_value(data, eh_frame_ptr_enc, pos, &eh_frame_ptr);
    if (size < 0)
        return -1;
    pos += size;
    data += size;

    size = dw_get_value(data, fde_count_enc, pos, fde_count);
    if (size < 0)
        return -1;
    pos += size;
    *table_data = pos;

    return 0;
}

static Elf *elf_start(int fd, char *image, uint64_t size)
{
    Elf *elf;

    if (fd > 0) {
        if ((elf = elf_begin(fd, ELF_C_READ_MMAP, NULL)) == NULL)
            fprintf(stderr, "elf_begin: %s\n", elf_errmsg(elf_errno()));
    } else {
        if ((elf = elf_memory(image, size)) == NULL)
            fprintf(stderr, "elf_memory: %s\n", elf_errmsg(elf_errno()));
    }

    return elf;
}

/*
 * find section .eh_frame_hdr in ELF binary
 */
static int find_eh_frame_hdr(int fd, char *image, uint64_t size,
        uint64_t *table_data, uint64_t *segbase, uint64_t *fde_count)
{
    Elf *elf;
    GElf_Ehdr ehdr;
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    uint64_t offset = 0;

    if ((elf = elf_start(fd, image, size)) == NULL)
        return -1;

    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "elf_getehdr: %s\n", elf_errmsg(elf_errno()));
        goto elf_section_offset_end;
    }

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        char *str;

        if (gelf_getshdr(scn, &shdr) == NULL) {
            fprintf(stderr, "elf_getshdr: %s\n", elf_errmsg(elf_errno()));
            break;
        }

        str = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (str != NULL && !strcmp(str, ".eh_frame_hdr")) {
            Elf_Data *data = NULL;

            if ((data = elf_getdata(scn, data)) == NULL) {
                fprintf(stderr, "elf_getdata: %s\n", elf_errmsg(elf_errno()));
                break;
            }

            offset = *segbase = shdr.sh_offset;
            parse_eh_frame_hdr(data->d_buf, offset, table_data, fde_count);
            break;
        }
    }

    if (!offset)
        goto elf_section_offset_end;

elf_section_offset_end:
    elf_end(elf);
    return (offset ? 0 : -1);
}

/*
 * dynamic array of symbols
 */
struct symbols
{
    GElf_Sym *s_data;
    size_t s_size;
    size_t s_cap;
};

/*
 * add a symbol to array
 */
static void push_symbol(struct symbols *array, const GElf_Sym *s)
{
    ++array->s_size;
    if (array->s_size > array->s_cap) {
        GElf_Sym *new_data;
        array->s_cap <<= 1;
        new_data = malloc(sizeof(GElf_Sym) * array->s_cap);
        memcpy(new_data, array->s_data, sizeof(GElf_Sym) * (array->s_size-1));
        free(array->s_data);
        array->s_data = new_data;
    }
    memcpy(array->s_data + (array->s_size-1), s, sizeof(GElf_Sym));
}

/*
 * symbol comparison function for qsort
 */
static int sym_compar(const void *v1, const void *v2)
{
    const GElf_Sym *s1 = v1;
    const GElf_Sym *s2 = v2;

    if (s1->st_value < s2->st_value)
        return -1;
    if (s1->st_value > s2->st_value)
        return 1;
    return 0;
}

/*
 * get function name
 *
 * fd: open binary
 * load: mmap address
 * offset: file offset
 * addr: ip value
 * off: offset within the function
 */
static char *proc_name(int fd, char *image, size_t size, uint64_t load,
        uint64_t offset, uint64_t addr, unw_word_t *off)
{
    Elf *elf;
    Elf_Scn *scn = NULL;
    char *str = NULL;
    int rc = 0;
    struct symbols all;
    size_t pnum, i;
    uint64_t vaddr = 0;

    /*
     * open ELF handle
     */
    if ((elf = elf_start(fd, image, size)) == NULL)
        return NULL;

    /*
     * initialize dynamic array
     */
    all.s_cap = 64;
    all.s_size = 0;
    all.s_data = malloc(all.s_cap * sizeof(GElf_Sym));

    if (elf_getphdrnum (elf, &pnum))
        goto proc_name_end;

    for (i = 0; i < pnum; ++i) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) == NULL)
            goto proc_name_end;
        if (phdr.p_type != PT_LOAD)
            continue;
        if (phdr.p_flags != (PF_X | PF_R))
            continue;
        if ((phdr.p_offset & ~(phdr.p_align - 1)) != offset)
            continue;
        vaddr = phdr.p_vaddr;
        break;
    }

    /*
     * adjust address
     */
    addr -= load;
    addr += offset;

    /*
     * search symtab or dynsym section
     */
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;

        if (gelf_getshdr(scn, &shdr) == NULL) {
            fprintf(stderr, "elf_nextscn: %s\n", elf_errmsg(elf_errno()));
            goto proc_name_end;
        }

        if (shdr.sh_type == SHT_DYNSYM || shdr.sh_type == SHT_SYMTAB) {
            Elf_Data *data = NULL;
            int symbol_count;

            if ((data = elf_getdata(scn, data)) == NULL) {
                fprintf(stderr, "elf_getdata: %s\n", elf_errmsg(elf_errno()));
                goto proc_name_end;
            }

            symbol_count = shdr.sh_size / shdr.sh_entsize;
            for (i = 0; i < (size_t)symbol_count; ++i) {
                GElf_Sym s;

                if (gelf_getsym(data, i, &s) == NULL) {
                    fprintf(stderr, "elf_getsym: %s\n",
                            elf_errmsg(elf_errno()));
                    rc = -1;
                    goto proc_name_end;
                }

                if (ELF64_ST_TYPE(s.st_info) != STT_FUNC)
                    continue;

                /*
                 * adjust symbol value
                 */
                s.st_value -= vaddr;

                /*
                 * exact match
                 */
                if (addr >= s.st_value && addr < (s.st_value + s.st_size)) {
                    str = elf_strptr(elf, shdr.sh_link, s.st_name);
                    if (str == NULL) {
                        fprintf(stderr, "elf_strptr #1: %s\n",
                                elf_errmsg(elf_errno()));
                        rc = -1;
                        goto proc_name_end;
                    }
                    str = strdup(str);
                    *off = addr - s.st_value;
                    goto proc_name_end;
                }

                /* store section link */
                s.st_shndx = shdr.sh_link;
                /*
                 * save symbol in array
                 */
                push_symbol(&all, &s);
            }
        }
    }

    /*
     * sometimes function symbols have zero size but contain the code.
     * common example is _start on most systems.
     * in this case we try to find two adjacent symbols with first
     * one of zero size
     */
    if (!rc && str == NULL) {
        qsort(all.s_data, all.s_size, sizeof(GElf_Sym), sym_compar);
        for (i = 0; i < (all.s_size-1); ++i) {
            const GElf_Sym *cur = all.s_data + i;
            const GElf_Sym *next = all.s_data + i + 1;
            if (cur->st_size == 0) {
                if (cur->st_value <= addr && addr < next->st_value) {
                    str = elf_strptr(elf, cur->st_shndx, cur->st_name);
                    if (str == NULL) {
                        fprintf(stderr, "elf_strptr #2: %s\n",
                                elf_errmsg(elf_errno()));
                        rc = -1;
                        goto proc_name_end;
                    }
                    str = strdup(str);
                    *off = addr - cur->st_value;
                    goto proc_name_end;
                }
            }
        }
    }

proc_name_end:
    free(all.s_data);
    elf_end(elf);
    return str;
}

/*
 * get mmapped ELF image info
 */
static int get_elf_image_info(struct mem_region *region,
        char **elf_image, uint64_t *elf_length, uintptr_t ip)
{
    struct mem_data_chunk *chunk;

    if ((chunk = mem_region_find_data_chunk(region, (void *)ip)) == NULL)
        return -1;

    if (chunk->data == NULL)
        return -1;

    *elf_image = chunk->data;
    *elf_length = chunk->length;

    return 0;
}

#ifdef HAVE_DWARF
static int elf_is_exec(int fd, char *image, uint64_t size)
{
    Elf *elf;
    GElf_Ehdr ehdr;
    int ret = 0;

    if ((elf = elf_start(fd, image, size)) == NULL)
        return 0;

    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "elf_getehdr: %s\n", elf_errmsg(elf_errno()));
        goto elf_is_exec_end;
    }

    ret = ehdr.e_type == ET_EXEC;

elf_is_exec_end:
    elf_end(elf);

    return ret;
}

static int elf_get_link_base(int fd, char *image, uint64_t size,
        uint64_t *link_base)
{
    Elf *elf;
    GElf_Ehdr ehdr;
    GElf_Phdr phdr;
    int idx=0;
    uint64_t offset = UINT64_MAX;

    if ((elf = elf_start(fd, image, size)) == NULL)
        return -1;

    if (gelf_getehdr(elf, &ehdr) == NULL) {
        fprintf(stderr, "elf_getehdr: %s\n", elf_errmsg(elf_errno()));
        goto elf_section_offset_end;
    }

    /* Get the vaddr of the segment with 0 offset.  This is the link base of
     * the shared object. */
    while (gelf_getphdr(elf, idx, &phdr) && phdr.p_type != PT_NULL) {
	if (phdr.p_type != PT_LOAD)
	    goto next;

	if (phdr.p_offset)
	    goto next;

	offset = phdr.p_vaddr;
	break;

next:
	idx++;
    }

    *link_base = offset;
    elf_end(elf);
    return 0;

elf_section_offset_end:
    elf_end(elf);
    return -1;
}

#endif

/*
 * find unwind info for function
 */
static int find_proc_info(unw_addr_space_t as, unw_word_t ip,
        unw_proc_info_t *pip, int need_unwind_info, void *arg)
{
    struct snapshot *snap = arg;
    struct mem_region *region;
    char *elf_image = NULL;
    uint64_t elf_length = 0;
    unw_dyn_info_t di;
    uint64_t table_data = 0;
    uint64_t segbase, fde_count;
    int rc = -UNW_EINVAL;

    if (ip == 0)
        return -UNW_ENOINFO;

    if ((region = mem_map_get_file_region(snap->map, (void *)ip)) == NULL)
        return rc;

    if (region->fd < 0 && region->type != MEM_REGION_TYPE_VDSO
            && region->type != MEM_REGION_TYPE_VSYSCALL)
        return rc;

    if (region->fd < 0 &&
            get_elf_image_info(region, &elf_image, &elf_length, ip) < 0)
        return rc;

    memset(&di, 0, sizeof(di));

    if (!find_eh_frame_hdr(region->fd, elf_image, elf_length,
                &table_data, &segbase, &fde_count)) {

        di.format = UNW_INFO_FORMAT_REMOTE_TABLE;
        di.start_ip = (unw_word_t)region->start;
        di.end_ip = (unw_word_t)region->start + region->length;
        di.u.rti.segbase = (unw_word_t)(region->start - region->offset) + segbase;
        di.u.rti.table_data = (unw_word_t)(region->start - region->offset) + table_data;
        di.u.rti.table_len =
            fde_count * sizeof(uint32_t) * 2 / sizeof(unw_word_t);

        rc = search_unwind_table(as, ip, &di, pip, need_unwind_info, arg);
    }

    if (rc == 0)
        return rc;

#ifdef HAVE_DWARF
    unw_word_t base = 0;
    if (!elf_is_exec(region->fd, elf_image, elf_length)) {
	uint64_t link_base;
	if (elf_get_link_base(region->fd, elf_image, elf_length, &link_base))
	    return -UNW_EINVAL;
        base = (uintptr_t)region->start - link_base;
    }

    if (dwarf_find_debug_frame(0, &di, ip, base, region->path,
                region->start, region->start + region->length))
            return search_unwind_table(as, ip, &di, pip, need_unwind_info, arg);
#endif

    return rc;
}

/*
 * put_unwind_info: do nothing
 */
static void put_unwind_info(unw_addr_space_t as,
        unw_proc_info_t *pip, void *arg)
{
    (void) as;
    (void) pip;
    (void) arg;
}

/*
 * not used
 */
static int get_dyn_info_list_addr(unw_addr_space_t as,
        unw_word_t *dilap, void *arg)
{
    (void) as;
    (void) dilap;
    (void) arg;
    return -UNW_ENOINFO;
}

/*
 * read a word from memory. we use mem_map for that
 */
static int access_mem(unw_addr_space_t as, unw_word_t addr,
        unw_word_t *valp, int write, void *arg)
{
    struct snapshot *snap = arg;

    (void) as;

    if (write) {
        fprintf(stderr, "access_mem: requested write, rejecting\n");
        return -UNW_EINVAL;
    }

    return mem_map_read_word(snap->map, (void *)(uintptr_t)addr, valp);
}

/*
 * get register value
 */
static int access_reg(unw_addr_space_t as, unw_regnum_t reg,
        unw_word_t *val, int write, void *arg)
{
    struct snapshot *snap = arg;

    (void) as;

    if (write) {
        fprintf(stderr, "requested to write into register\n");
        return -UNW_EINVAL;
    }

    switch (reg) {
#if defined(UNW_TARGET_AARCH64)
    case UNW_AARCH64_X0 ... UNW_AARCH64_X30:
        /*
         * Currently this enum directly maps to the index so this is a no-op.
         * Assert just in case.
         */
        reg -= UNW_AARCH64_X0;
        assert(reg>= 0 && reg <= 30);
        *val = snap->regs[snap->cur_thr].regs[reg];
        break;
    case UNW_AARCH64_SP:
        *val = snap->regs[snap->cur_thr].sp;
        break;
    case UNW_AARCH64_PC:
        *val = snap->regs[snap->cur_thr].pc;
        break;
    case UNW_AARCH64_PSTATE:
        *val = snap->regs[snap->cur_thr].pstate;
        break;
#elif defined(UNW_TARGET_ARM)
    case UNW_ARM_R0 ... UNW_ARM_R15:
        /*
         * Currently this enum directly maps to the index so this is a no-op.
         * Assert just in case.
         */
        reg -= UNW_ARM_R0;
        assert(reg >= 0 && reg <= 15);
        *val = snap->regs[snap->cur_thr].uregs[reg];
        break;
#elif defined(UNW_TARGET_X86)
    case UNW_X86_EAX:
        *val = snap->regs[snap->cur_thr].eax;
        break;
    case UNW_X86_EDX:
        *val = snap->regs[snap->cur_thr].edx;
        break;
    case UNW_X86_ECX:
        *val = snap->regs[snap->cur_thr].ecx;
        break;
    case UNW_X86_EBX:
        *val = snap->regs[snap->cur_thr].ebx;
        break;
    case UNW_X86_ESI:
        *val = snap->regs[snap->cur_thr].esi;
        break;
    case UNW_X86_EDI:
        *val = snap->regs[snap->cur_thr].edi;
        break;
    case UNW_X86_EBP:
        *val = snap->regs[snap->cur_thr].ebp;
        break;
    case UNW_X86_ESP:
        *val = snap->regs[snap->cur_thr].esp;
        break;
    case UNW_X86_EIP:
        *val = snap->regs[snap->cur_thr].eip;
        break;
#elif defined(UNW_TARGET_X86_64)
    case UNW_X86_64_RAX:
        *val = snap->regs[snap->cur_thr].rax;
        break;
    case UNW_X86_64_RDX:
        *val = snap->regs[snap->cur_thr].rdx;
        break;
    case UNW_X86_64_RCX:
        *val = snap->regs[snap->cur_thr].rcx;
        break;
    case UNW_X86_64_RBX:
        *val = snap->regs[snap->cur_thr].rbx;
        break;
    case UNW_X86_64_RSI:
        *val = snap->regs[snap->cur_thr].rsi;
        break;
    case UNW_X86_64_RDI:
        *val = snap->regs[snap->cur_thr].rdi;
        break;
    case UNW_X86_64_RBP:
        *val = snap->regs[snap->cur_thr].rbp;
        break;
    case UNW_X86_64_RSP:
        *val = snap->regs[snap->cur_thr].rsp;
        break;
    case UNW_X86_64_R8:
        *val = snap->regs[snap->cur_thr].r8;
        break;
    case UNW_X86_64_R9:
        *val = snap->regs[snap->cur_thr].r9;
        break;
    case UNW_X86_64_R10:
        *val = snap->regs[snap->cur_thr].r10;
        break;
    case UNW_X86_64_R11:
        *val = snap->regs[snap->cur_thr].r11;
        break;
    case UNW_X86_64_R12:
        *val = snap->regs[snap->cur_thr].r12;
        break;
    case UNW_X86_64_R13:
        *val = snap->regs[snap->cur_thr].r13;
        break;
    case UNW_X86_64_R14:
        *val = snap->regs[snap->cur_thr].r14;
        break;
    case UNW_X86_64_R15:
        *val = snap->regs[snap->cur_thr].r15;
        break;
    case UNW_X86_64_RIP:
        *val = snap->regs[snap->cur_thr].rip;
        break;
#else
#error Need porting to this arch
#endif
    default:
        return -UNW_EBADREG;
    }

    return 0;
}

/*
 * floating point registers are not used
 */
static int access_fpreg(unw_addr_space_t as, unw_regnum_t regnum,
        unw_fpreg_t *fpvalp, int write, void *arg)
{
    (void) as;
    (void) regnum;
    (void) fpvalp;
    (void) write;
    (void) arg;

    fprintf(stderr, "access_fpreg is not supported\n");
    return -UNW_ENOINFO;
}

/*
 * not used
 */
static int resume(unw_addr_space_t as, unw_cursor_t *cp, void *arg)
{
    (void) as;
    (void) cp;
    (void) arg;

    fprintf(stderr, "resume is not supported\n");
    return -UNW_ENOINFO;
}

/*
 * get function name callback
 */
static int get_proc_name(unw_addr_space_t as, unw_word_t addr, char *bufp,
        size_t buf_len, unw_word_t *offp, void *arg)
{
    struct snapshot *snap = arg;
    struct mem_region *region;
    char *name = NULL;

    (void) as;

    if (addr == 0)
        return -UNW_ENOINFO;

    if ((region = mem_map_get_file_region(snap->map, (void *)addr)) == NULL)
        return -UNW_ENOINFO;

    if (region->fd < 0 && region->type == MEM_REGION_TYPE_DELETED) {
        const char *base = basename(region->path);
        snprintf(bufp, buf_len, "?? (%s is deleted)", base);
        *offp = 0;
        return 0;
    } else if (region->type == MEM_REGION_TYPE_MMAP ||
            region->type == MEM_REGION_TYPE_VDSO ||
            region->type == MEM_REGION_TYPE_VSYSCALL) {
        char *elf_image = NULL;
        uint64_t elf_length = 0;

        if (region->fd < 0 &&
                get_elf_image_info(region, &elf_image, &elf_length, addr) < 0)
            return -UNW_ENOINFO;

        name = proc_name(region->fd, elf_image, elf_length,
                (uint64_t)(uintptr_t)region->start, region->offset, addr, offp);
    }

    if (name == NULL) {
        /*
         * if name cannot be resolved, print binary file name
         */
        const char *base = basename(region->path);
        snprintf(bufp, buf_len, "?? (%s)", base);
        *offp = 0;
        return 0;
    }

    strncpy(bufp, name, buf_len);
    free(name);

    return 0;
}

/*
 * libunwind remote callbacks
 */
unw_accessors_t snapshot_addr_space_accessors = {
    .find_proc_info = find_proc_info,
    .put_unwind_info = put_unwind_info,
    .get_dyn_info_list_addr = get_dyn_info_list_addr,
    .access_mem = access_mem,
    .access_reg = access_reg,
    .access_fpreg = access_fpreg,
    .resume = resume,
    .get_proc_name = get_proc_name,
};
