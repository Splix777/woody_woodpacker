#include "woody.h"

/*
 * Code cave scanner + injector path.
 *
 * A "code cave" commonly means unused bytes inside a mapped segment (PT_LOAD).
 * We use that in two ways:
 *  - scan_code_caves(): analysis-only reporting of padding gaps
 *  - find_code_cave(): choose an executable padding gap and inject the loader
 *    stub there (without inserting a new section header)
 *
 * Reporting policy:
 *  - Always prints cave sizes and segment indices.
 *  - Prints precise file offsets / virtual addresses only when -v is enabled.
 */

typedef struct s_range {
    uint64_t start; /* file offset */
    uint64_t end;   /* file offset (exclusive) */
    int      shndx; /* section index */
} t_range;

static const char* phdr_flags_to_string(uint32_t flags) {
    static char buf[8];
    size_t      n = 0;
    buf[0]        = '\0';
    if (flags & PF_R)
        buf[n++] = 'R';
    if (flags & PF_W)
        buf[n++] = 'W';
    if (flags & PF_X)
        buf[n++] = 'X';
    buf[n] = '\0';
    return buf;
}

static void sort_ranges_by_start(t_range* ranges, size_t n) {
    /* n is small; insertion sort is fine and keeps dependencies minimal. */
    for (size_t i = 1; i < n; i++) {
        t_range key = ranges[i];
        size_t  j   = i;
        while (j > 0 && ranges[j - 1].start > key.start) {
            ranges[j] = ranges[j - 1];
            j--;
        }
        ranges[j] = key;
    }
}

static uint64_t max_u64(uint64_t a, uint64_t b) {
    return (a > b) ? a : b;
}

static void report_gap(t_woody_context* context, size_t seg_idx,
    const Elf64_Phdr* seg, uint64_t gap_start, uint64_t gap_end,
    const char* label) {
    uint64_t gap_sz = (gap_end > gap_start) ? (gap_end - gap_start) : 0;
    if (gap_sz == 0)
        return;

    printf("  seg[%zu] cave: %s size=%lu bytes", seg_idx, label,
        (unsigned long)gap_sz);
    if (context && context->verbose) {
        uint64_t vaddr = seg->p_vaddr + (gap_start - seg->p_offset);
        printf(" file_off=0x%lx vaddr=0x%lx", (unsigned long)gap_start,
            (unsigned long)vaddr);
    }
    printf("\n");
}

void scan_code_caves(t_woody_context* context) {
    if (!context || !context->elf.is_64bit || !context->elf.elf64.ehdr
        || !context->elf.elf64.phdr || !context->elf.elf64.shdr) {
        fprintf(stderr, "scan_code_caves: invalid context\n");
        return;
    }

    printf("Code cave scan (analysis-only)\n");
    printf("Input: %s\n", context->file.input_file_path);
    printf("PT_LOAD segments: %u\n", context->elf.elf64.ehdr->e_phnum);
    printf("Note: offsets/vaddrs are shown only with -v\n");

    const size_t shnum = context->elf.elf64.ehdr->e_shnum;
    t_range*     ranges = malloc(sizeof(t_range) * shnum);
    if (!ranges) {
        fprintf(stderr, "scan_code_caves: out of memory\n");
        return;
    }

    for (size_t p = 0; p < context->elf.elf64.ehdr->e_phnum; p++) {
        const Elf64_Phdr* seg = &context->elf.elf64.phdr[p];
        if (seg->p_type != PT_LOAD)
            continue;

        uint64_t seg_start = seg->p_offset;
        uint64_t seg_end   = seg->p_offset + seg->p_filesz;

        size_t n = 0;
        for (size_t i = 0; i < shnum; i++) {
            const Elf64_Shdr* sh = &context->elf.elf64.shdr[i];

            if (sh->sh_type == SHT_NOBITS || sh->sh_size == 0)
                continue;

            uint64_t s = sh->sh_offset;
            uint64_t e = sh->sh_offset + sh->sh_size;

            /* Only consider section data that lies fully inside this segment's file range. */
            if (s < seg_start || e > seg_end)
                continue;

            ranges[n].start = s;
            ranges[n].end   = e;
            ranges[n].shndx = (int)i;
            n++;
        }

        sort_ranges_by_start(ranges, n);

        printf("\nseg[%zu] PT_LOAD flags=%s file=[0x%lx..0x%lx] size=%lu\n", p,
            phdr_flags_to_string(seg->p_flags), (unsigned long)seg_start,
            (unsigned long)seg_end, (unsigned long)seg->p_filesz);

        if (n == 0) {
            report_gap(context, p, seg, seg_start, seg_end, "empty-segment");
            continue;
        }

        uint64_t cursor = seg_start;
        for (size_t k = 0; k < n; k++) {
            if (ranges[k].start > cursor)
                report_gap(context, p, seg, cursor, ranges[k].start,
                    "between-sections");
            cursor = max_u64(cursor, ranges[k].end);
        }

        if (cursor < seg_end)
            report_gap(context, p, seg, cursor, seg_end, "end-padding");
    }

    free(ranges);
    printf("\nDone.\n");
}

int find_code_cave(t_woody_context* context) {
    if (!context || !context->elf.is_64bit || !context->elf.elf64.ehdr
        || !context->elf.elf64.phdr || !context->elf.elf64.shdr
        || !context->elf.elf64.section_data) {
        return ERR_INVALID_CONTEXT;
    }

    const size_t required = INJECTION_PAYLOAD_64_SIZE;
    const size_t shnum    = context->elf.elf64.ehdr->e_shnum;

    t_range* ranges = malloc(sizeof(t_range) * shnum);
    if (!ranges)
        return ERR_MEMORY_ALLOC;

    int      best_section   = -1;
    int      best_segment   = -1;
    uint64_t best_gap       = 0;
    bool     best_sh_exec   = false;
    bool     best_seg_exec  = false;

    for (size_t p = 0; p < context->elf.elf64.ehdr->e_phnum; p++) {
        const Elf64_Phdr* seg = &context->elf.elf64.phdr[p];
        if (seg->p_type != PT_LOAD)
            continue;
        const bool seg_is_exec = (seg->p_flags & PF_X) != 0;

        const uint64_t seg_start = seg->p_offset;
        const uint64_t seg_end   = seg->p_offset + seg->p_filesz;

        size_t n = 0;
        for (size_t i = 0; i < shnum; i++) {
            const Elf64_Shdr* sh = &context->elf.elf64.shdr[i];
            if (sh->sh_type == SHT_NOBITS || sh->sh_size == 0)
                continue;

            const uint64_t s = sh->sh_offset;
            const uint64_t e = sh->sh_offset + sh->sh_size;
            if (s < seg_start || e > seg_end)
                continue;

            ranges[n].start = s;
            ranges[n].end   = e;
            ranges[n].shndx = (int)i;
            n++;
        }

        if (n == 0)
            continue;

        sort_ranges_by_start(ranges, n);

        int      prev_shndx = -1;
        uint64_t cursor     = seg_start;
        for (size_t k = 0; k < n; k++) {
            if (prev_shndx != -1 && ranges[k].start > cursor) {
                const uint64_t gap_sz = ranges[k].start - cursor;
                if (gap_sz >= required) {
                    const Elf64_Shdr* prev_sh
                        = &context->elf.elf64.shdr[prev_shndx];
                    const bool is_exec
                        = (prev_sh->sh_flags & SHF_EXECINSTR) != 0;

                    /* Prefer executable segments, then executable sections, then larger gaps. */
                    if ((seg_is_exec && !best_seg_exec)
                        || (seg_is_exec == best_seg_exec && is_exec && !best_sh_exec)
                        || (seg_is_exec == best_seg_exec && is_exec == best_sh_exec
                            && gap_sz > best_gap)) {
                        best_seg_exec = seg_is_exec;
                        best_sh_exec  = is_exec;
                        best_gap      = gap_sz;
                        best_section  = prev_shndx;
                        best_segment  = (int)p;
                    }
                }
            }

            cursor     = max_u64(cursor, ranges[k].end);
            prev_shndx = ranges[k].shndx;
        }

        if (prev_shndx != -1 && cursor < seg_end) {
            const uint64_t gap_sz = seg_end - cursor;
            if (gap_sz >= required) {
                const Elf64_Shdr* prev_sh
                    = &context->elf.elf64.shdr[prev_shndx];
                const bool is_exec = (prev_sh->sh_flags & SHF_EXECINSTR) != 0;

                if ((seg_is_exec && !best_seg_exec)
                    || (seg_is_exec == best_seg_exec && is_exec && !best_sh_exec)
                    || (seg_is_exec == best_seg_exec && is_exec == best_sh_exec
                        && gap_sz > best_gap)) {
                    best_seg_exec = seg_is_exec;
                    best_sh_exec  = is_exec;
                    best_gap      = gap_sz;
                    best_section  = prev_shndx;
                    best_segment  = (int)p;
                }
            }
        }
    }

    free(ranges);

    if (best_section < 0 || best_segment < 0)
        return NO_CODE_CAVE;
    if (context->elf.elf64.shdr[best_section].sh_type == SHT_NOBITS)
        return NO_CODE_CAVE;
    if (context->elf.elf64.section_data[best_section] == NULL)
        return NO_CODE_CAVE;

    context->elf.elf64.payload_section_index = best_section;
    context->elf.elf64.cave                  = true;
    context->elf.elf64.text_offset
        = context->elf.elf64.shdr[best_section].sh_addr
        + context->elf.elf64.shdr[best_section].sh_size;

    set_elf_segment_permission(context, best_segment, PF_W | PF_X | PF_R);
    const int text_sec = find_elf_section_index(context, ".text");
    if (text_sec >= 0) {
        const int text_seg = find_elf_segment_index_by_section(context, text_sec);
        if (text_seg >= 0)
            set_elf_segment_permission(context, text_seg, PF_W | PF_X | PF_R);
    }

    char* payload = prepare_payload(context);
    if (!payload)
        return ERR_INJECTION;

    const size_t old_sz = (size_t)context->elf.elf64.shdr[best_section].sh_size;
    char*        grown
        = realloc(context->elf.elf64.section_data[best_section],
            old_sz + INJECTION_PAYLOAD_64_SIZE);
    if (!grown) {
        free(payload);
        return ERR_MEMORY_ALLOC;
    }
    context->elf.elf64.section_data[best_section] = grown;

    memcpy(context->elf.elf64.section_data[best_section] + old_sz, payload,
        INJECTION_PAYLOAD_64_SIZE);
    free(payload);

    print_verbose(context,
        "Code cave injection: seg[%d] section[%d]=%s gap=%lu payload=%zu\n",
        best_segment, best_section, find_elf_section_name(context, best_section),
        (unsigned long)best_gap, (size_t)INJECTION_PAYLOAD_64_SIZE);

    return SUCCESS;
}
