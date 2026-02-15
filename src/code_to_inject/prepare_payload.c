#include "woody.h"

/*
 * Payload preparation: patch the loader stub template (INJECTION_PAYLOAD_64)
 * with runtime values derived from the input ELF:
 *  - info_key:   XOR stream key used to decrypt
 *  - info_addr:  virtual address of the encrypted region (.text)
 *  - info_size:  size of the encrypted region
 *  - info_offset: PIE slide (computed by the stub at runtime)
 *
 * The assembler stub embeds placeholder constants (0xaaaa..., 0xbbbb..., ...)
 * so we can locate them via byte-pattern search and overwrite them safely.
 *
 * patch_entry_point() also updates the ELF entry point to the injected stub
 * and patches the stub's final jump to land back at the original entry point.
 */
static unsigned char jmp_placeholder_64[4]           = { 0x96, 0xff, 0xff, 0xff };
static uint64_t      key_placeholder_64              = 0xaaaaaaaaaaaaaaaa;
static uint64_t      text_data_entry_placeholder_64  = 0xbbbbbbbbbbbbbbbb;
static uint64_t      text_data_size_placeholder_64   = 0xcccccccccccccccc;
static uint64_t      text_data_offset_placeholder_64 = 0xdddddddddddddddd;

static uint64_t find_pattern(const char* bin, size_t size,
    const unsigned char* pattern, size_t pattern_size) {
    if (!bin || !pattern || size < pattern_size)
        return (uint64_t)-1;

    for (uint64_t i = 0; i <= size - pattern_size; i++) {
        if (memcmp(bin + i, pattern, pattern_size) == 0)
            return i;
    }

    return (uint64_t)-1;
}

static int validate_offset(t_woody_context* context, uint64_t offset,
    size_t required_space, const char* what) {
    if (offset == (uint64_t)-1) {
        print_verbose(context, "Failed to find %s placeholder\n", what);
        return -1;
    }

    if (offset + required_space > INJECTION_PAYLOAD_64_SIZE) {
        print_verbose(context, "Not enough space for %s (needs %zu bytes)\n",
            what, required_space);
        return -1;
    }

    return 0;
}

static int patch_key_info(t_woody_context* context, char* patched_bin) {
    uint64_t key_offset = find_pattern(patched_bin, INJECTION_PAYLOAD_64_SIZE,
        (unsigned char*)&key_placeholder_64, sizeof(uint64_t));

    if (validate_offset(context, key_offset, sizeof(uint64_t), "key") != 0)
        return -1;

    memcpy(patched_bin + key_offset, &context->encryption.key64,
        sizeof(uint64_t));

    return SUCCESS;
}

static int patch_text_data_info(t_woody_context* context, char* patched_bin) {
    const size_t entry_size = sizeof(uint64_t);
    uint64_t     text_data_entry_offset
        = find_pattern(patched_bin, INJECTION_PAYLOAD_64_SIZE,
            (unsigned char*)&text_data_entry_placeholder_64, entry_size);
    uint64_t text_data_size_offset
        = find_pattern(patched_bin, INJECTION_PAYLOAD_64_SIZE,
            (unsigned char*)&text_data_size_placeholder_64, entry_size);
    uint64_t text_data_offset
        = find_pattern(patched_bin, INJECTION_PAYLOAD_64_SIZE,
            (unsigned char*)&text_data_offset_placeholder_64, entry_size);

    if (validate_offset(
            context, text_data_entry_offset, entry_size, "text data entry")
            != 0
        || validate_offset(
               context, text_data_size_offset, entry_size, "text data size")
            != 0
        || validate_offset(
               context, text_data_offset, entry_size, "text data offset")
            != 0)
        return -1;

    memcpy(patched_bin + text_data_entry_offset, &context->elf.elf64.text_entry,
        entry_size);
    memcpy(patched_bin + text_data_size_offset, &context->elf.elf64.text_size,
        entry_size);
    memcpy(patched_bin + text_data_offset, &context->elf.elf64.text_offset,
        entry_size);

    return SUCCESS;
}

static int patch_entry_point(t_woody_context* context, char* patched_bin) {
    uint64_t jump_offset = find_pattern(patched_bin, INJECTION_PAYLOAD_64_SIZE,
        jmp_placeholder_64, sizeof(jmp_placeholder_64));

    if (validate_offset(context, jump_offset, sizeof(int32_t), "jump") != 0)
        return -1;

    Elf64_Addr new_entry_point;
    Elf64_Addr old_entry_point = context->elf.elf64.ehdr->e_entry;
    Elf64_Shdr relevant_section
        = context->elf.elf64.shdr[context->elf.elf64.payload_section_index];

    if (context->elf.elf64.cave)
        new_entry_point = relevant_section.sh_addr + relevant_section.sh_size;
    else
        new_entry_point = relevant_section.sh_addr;

    context->elf.elf64.ehdr->e_entry = new_entry_point;

    int32_t jump
        = (old_entry_point - (new_entry_point + jump_offset + sizeof(int32_t)));
    memcpy(patched_bin + jump_offset, &jump, sizeof(int32_t));

    return SUCCESS;
}

char* prepare_payload(t_woody_context* context) {
    if (!context->elf.is_64bit)
        return NULL;

    char* patched_bin = malloc(INJECTION_PAYLOAD_64_SIZE);
    if (!patched_bin) {
        print_verbose(context, "Failed to allocate memory for payload\n");
        return NULL;
    }

    memcpy(patched_bin, INJECTION_PAYLOAD_64, INJECTION_PAYLOAD_64_SIZE);

    if (patch_key_info(context, patched_bin) != SUCCESS
        || patch_text_data_info(context, patched_bin) != SUCCESS
        || patch_entry_point(context, patched_bin) != SUCCESS) {
        free(patched_bin);
        return NULL;
    }

    return patched_bin;
}
