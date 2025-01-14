#include "woody.h"

// Message placeholder - 14 bytes
unsigned char message_placeholder[14] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
// Message length placeholder - 8 bytes (64-bit quadword)
uint64_t message_len_placeholder = 0x4343434343434343;
// Key placeholder - 32 bytes
unsigned char key_placeholder[32] = {
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44};
// Encrypted start address placeholder - 8 bytes (64-bit quadword)
uint64_t text_data_entry_placeholder = 0x4545454545454545;
// Encrypted size placeholder - 8 bytes (64-bit quadword)
uint64_t text_data_size_placeholder = 0x4646464646464646;
// Old entry point placeholder - 8 bytes (64-bit quadword)
uint64_t old_entry_placeholder = 0x4747474747474747;

static uint64_t find_pattern(
    unsigned char *bin,
    size_t size,
    unsigned char *pattern,
    size_t pattern_size)
{
    for (uint64_t i = 0; i <= size - pattern_size; i++)
    {
        if (memcmp(bin + i, pattern, pattern_size) == 0)
            return i;
    }
    return -1;
}

static int patch_message_info(
    t_woody_context *context,
    unsigned char *patched_bin)
{
    const char *message = "....Woody....\n";
    uint64_t message_len = 14;

    uint64_t message_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        message_placeholder,
        sizeof(message_placeholder));
    uint64_t message_len_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&message_len_placeholder,
        sizeof(message_len_placeholder));

    if (message_offset == (uint64_t)-1 ||
        message_len_offset == (uint64_t)-1)
    {
        print_verbose(context, "Failed to find message placeholders\n");
        return -1;
    }

    memcpy(patched_bin + message_offset, message, strlen(message));
    memcpy(patched_bin + message_len_offset, &message_len, sizeof(uint64_t));

    print_verbose(
        context,
        "Message: %sMessage Length: %ld\n",
        message, message_len);

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
        sizeof(key_placeholder));

    if (key_offset == (uint64_t)-1)
    {
        print_verbose(context, "Failed to find key placeholder\n");
        return -1;
    }

    memcpy(patched_bin + key_offset, context->encryption.key, 32);

    print_verbose(
        context,
        "Key: ");
    for (size_t i = 0; i < 32; i++)
        print_verbose(context, "%02x", context->encryption.key[i]);
    print_verbose(context, "\n");

    return 0;
}

static int patch_text_data_entry_info(
    t_woody_context *context,
    unsigned char *patched_bin)
{
    uint64_t text_data_entry_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&text_data_entry_placeholder,
        sizeof(text_data_entry_placeholder));
    uint64_t text_data_size_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&text_data_size_placeholder,
        sizeof(text_data_size_placeholder));
    uint64_t old_entry_offset = find_pattern(
        patched_bin,
        INJECTION_PAYLOAD_SIZE,
        (unsigned char *)&old_entry_placeholder,
        sizeof(old_entry_placeholder));

    if (text_data_entry_offset == (uint64_t)-1 ||
        text_data_size_offset == (uint64_t)-1 ||
        old_entry_offset == (uint64_t)-1)
    {
        print_verbose(
            context,
            "Failed to find text data entry placeholders\n");
        return -1;
    }

    memcpy(patched_bin + text_data_entry_offset, &context->elf.elf64.text_data_entry, sizeof(uint64_t));
    memcpy(patched_bin + text_data_size_offset, &context->elf.elf64.text_data_size, sizeof(uint64_t));
    memcpy(patched_bin + old_entry_offset, &context->elf.elf64.old_entry, sizeof(uint64_t));

    print_verbose(
        context,
        "Text Data Entry: %lx, Size: %lx, Old Entry: %lx\n",
        context->elf.elf64.text_data_entry,
        context->elf.elf64.text_data_size,
        context->elf.elf64.old_entry);

    return 0;
}

unsigned char *prepare_payload(t_woody_context *context)
{
    unsigned char *patched_bin = malloc(INJECTION_PAYLOAD_SIZE);
    if (patched_bin == NULL)
    {
        print_verbose(
            context,
            "Failed to allocate memory for patched binary\n");
        return NULL;
    }

    memcpy(patched_bin, INJECTION_PAYLOAD, INJECTION_PAYLOAD_SIZE);

    if (patch_message_info(context, patched_bin) != 0)
    {
        free(patched_bin);
        print_verbose(context, "Failed to patch message info\n");
        return NULL;
    }
    if (patch_key_info(context, patched_bin) != 0)
    {
        free(patched_bin);
        print_verbose(context, "Failed to patch key info\n");
        return NULL;
    }
    if (patch_text_data_entry_info(context, patched_bin) != 0)
    {
        free(patched_bin);
        print_verbose(context, "Failed to patch text data entry info\n");
        return NULL;
    }

    print_verbose(context, "Patched payload:\n");
    for (size_t i = 0; i < INJECTION_PAYLOAD_SIZE; i++)
        print_verbose(context, "%02x", patched_bin[i]);
    print_verbose(context, "\n");

    return patched_bin;
}
