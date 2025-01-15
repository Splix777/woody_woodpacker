#include "woody.h"

// Placeholder definitions
static const unsigned char key_placeholder[XOR_KEY_SIZE] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

uint64_t text_data_entry_placeholder = 0xbbbbbbbbbbbbbbbb;
uint64_t text_data_size_placeholder = 0xcccccccccccccccc;
uint64_t text_data_offset_placeholder = 0xdddddddddddddddd;
uint64_t old_entry_placeholder = 0xeeeeeeeeeeeeeeee;

static uint64_t
find_pattern(
    const unsigned char *bin,
    size_t size,
    const unsigned char *pattern,
    size_t pattern_size)
{
    if (size < pattern_size || !bin || !pattern)
        return (uint64_t)-1;

    for (uint64_t i = 0; i <= size - pattern_size; i++)
    {
        if (memcmp(bin + i, pattern, pattern_size) == 0)
            return i;
    }
    return (uint64_t)-1;
}

static int validate_offsets(
    t_woody_context *context,
    uint64_t offset,
    size_t required_space,
    const char *what)
{
    if (offset == (uint64_t)-1)
    {
        print_verbose(context, "Failed to find %s placeholder\n", what);
        return -1;
    }

    if (offset + required_space > INJECTION_PAYLOAD_SIZE)
    {
        print_verbose(context, "Not enough space for %s (needs %zu bytes)\n",
                      what, required_space);
        return -1;
    }

    return 0;
}

static int patch_key_info(
    t_woody_context *context,
    unsigned char *patched_bin)
{
    uint64_t key_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        key_placeholder,
        XOR_KEY_SIZE);

    if (validate_offsets(context, key_offset, XOR_KEY_SIZE, "key") != 0)
        return -1;

    memcpy(patched_bin + key_offset, context->encryption.key, XOR_KEY_SIZE);

    print_verbose(context, "Key: ");
    for (size_t i = 0; i < XOR_KEY_SIZE; i++)
        print_verbose(context, "%02x", context->encryption.key[i]);
    print_verbose(context, "\n");

    return 0;
}

static int patch_text_data_entry_info(
    t_woody_context *context,
    unsigned char *patched_bin)
{
    const size_t entry_size = sizeof(uint64_t);
    uint64_t text_data_entry_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&text_data_entry_placeholder,
        entry_size);
    uint64_t text_data_size_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&text_data_size_placeholder,
        entry_size);
    uint64_t text_data_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&text_data_offset_placeholder,
        entry_size);
    uint64_t old_entry_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&old_entry_placeholder,
        entry_size);

    // Validate all offsets
    if (validate_offsets(
            context, text_data_entry_offset, entry_size, "text data entry") != 0 ||
        validate_offsets(
            context, text_data_size_offset, entry_size, "text data size") != 0 ||
        validate_offsets(
            context, text_data_offset, entry_size, "old entry") != 0 ||
        validate_offsets(
            context, old_entry_offset, entry_size, "text data offset") != 0)
        return -1;

    memcpy(patched_bin + text_data_entry_offset, &context->elf.elf64.text_entry, entry_size);
    memcpy(patched_bin + text_data_size_offset, &context->elf.elf64.text_size, entry_size);
    memcpy(patched_bin + text_data_offset, &context->injection.cave64.offset, entry_size);
    memcpy(patched_bin + old_entry_offset, &context->elf.elf64.ehdr->e_entry, entry_size);

    print_verbose(
        context,
        "Text Data Entry: %lx, Size: %lx, Offset: %lx, Old Entry: %lx\n",
        context->elf.elf64.text_entry,
        context->elf.elf64.text_size,
        context->injection.cave64.offset,
        context->elf.elf64.ehdr->e_entry);

    return 0;
}

unsigned char *prepare_payload(t_woody_context *context)
{
    if (!context || !context->encryption.key)
    {
        return NULL;
    }

    unsigned char *patched_bin = calloc(1, INJECTION_PAYLOAD_SIZE);
    if (!patched_bin)
    {
        print_verbose(context, "Failed to allocate memory for patched binary\n");
        return NULL;
    }

    memcpy(patched_bin, INJECTION_PAYLOAD, INJECTION_PAYLOAD_SIZE);

    if (patch_key_info(context, patched_bin) != 0 ||
        patch_text_data_entry_info(context, patched_bin) != 0)
    {
        free(patched_bin);
        return NULL;
    }

    if (context->verbose)
    {
        print_verbose(context, "Patched payload:\n");
        for (size_t i = 0; i < INJECTION_PAYLOAD_SIZE; i++)
            print_verbose(context, "%02x", patched_bin[i]);
        print_verbose(context, "\n");
    }

    return patched_bin;
}