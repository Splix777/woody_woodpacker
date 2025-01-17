#include "woody.h"

// Placeholder definitions
// static const unsigned char key_placeholder[XOR_KEY_SIZE] = {
//     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
//     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
//     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
//     0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

uint64_t key_placeholder = 0xaaaaaaaaaaaaaaaa;
uint64_t text_data_entry_placeholder = 0xbbbbbbbbbbbbbbbb;
uint64_t text_data_size_placeholder = 0xcccccccccccccccc;
uint64_t text_data_offset_placeholder = 0xdddddddddddddddd;

unsigned char amd64_xor_linux_elf_loader_stub[] = {
    0x9c, 0x50, 0x57, 0x56, 0x54, 0x52, 0x51, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc7, 0x48,
    0x8d, 0x35, 0x17, 0x00, 0x00, 0x00, 0xba, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x4c, 0x8d, 0x25,
    0xdc, 0xff, 0xff, 0xff, 0x4c, 0x2b, 0x25, 0x5f, 0x00, 0x00, 0x00, 0xeb, 0x10, 0x5b, 0x55, 0x6e,
    0x70, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x2e, 0x2e, 0x2e, 0x5d, 0x0a, 0x00, 0x48, 0x8b, 0x05,
    0x36, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x0d, 0x37, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x15, 0x20, 0x00,
    0x00, 0x00, 0x4c, 0x01, 0xe0, 0x48, 0x01, 0xc1, 0x30, 0x10, 0x48, 0xc1, 0xca, 0x08, 0x48, 0xff,
    0xc0, 0x48, 0x39, 0xc8, 0x75, 0xf2, 0x59, 0x5a, 0x5c, 0x5e, 0x5f, 0x58, 0x9d, 0xe9, 0xfb, 0xff,
    0xff, 0xff, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd};

static uint64_t
find_pattern(
    const char *bin,
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
    char *patched_bin)
{
    uint64_t key_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&key_placeholder,
        sizeof(uint64_t));

    if (validate_offsets(context, key_offset, sizeof(uint64_t), "key") != 0)
        return -1;

    memcpy(patched_bin + key_offset, &context->encryption.key64, sizeof(uint64_t));

    print_verbose(context, "Key: ");
    for (size_t i = 0; i < sizeof(uint64_t); i++)
        print_verbose(context, "%02x", (unsigned char)patched_bin[key_offset + i]);
    print_verbose(context, "\n");

    return 0;
}

static int patch_text_data_entry_info(
    t_woody_context *context,
    char *patched_bin)
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

    // Validate all offsets
    if (validate_offsets(
            context, text_data_entry_offset, entry_size, "text data entry") != 0 ||
        validate_offsets(
            context, text_data_size_offset, entry_size, "text data size") != 0 ||
        validate_offsets(
            context, text_data_offset, entry_size, "entry offset") != 0)
        return -1;

    memcpy(patched_bin + text_data_entry_offset, &context->elf.elf64.text_entry, entry_size);
    memcpy(patched_bin + text_data_size_offset, &context->elf.elf64.text_size, entry_size);
    memcpy(patched_bin + text_data_offset, &context->elf.elf64.text_offset, entry_size);

    print_verbose(
        context,
        "Text Data Entry: %lx, Size: %lx, Offset: %lx\n",
        context->elf.elf64.text_entry,
        context->elf.elf64.text_size,
        context->elf.elf64.text_offset);

    return 0;
}

char *prepare_payload(t_woody_context *context)
{
    char *patched_bin = malloc(INJECTION_PAYLOAD_SIZE);
    if (!patched_bin)
    {
        print_verbose(context, "Failed to allocate memory for patched binary\n");
        return NULL;
    }

    memset(patched_bin, 0x0, INJECTION_PAYLOAD_SIZE);
    memcpy(patched_bin, INJECTION_PAYLOAD, INJECTION_PAYLOAD_SIZE);

    print_verbose(context, "Payload:\n");
    for (size_t i = 0; i < INJECTION_PAYLOAD_SIZE; i++)
        print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
    print_verbose(context, "\n");

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
            print_verbose(context, "%02x", (unsigned char)patched_bin[i]);
        print_verbose(context, "\n");
    }

    return patched_bin;
}