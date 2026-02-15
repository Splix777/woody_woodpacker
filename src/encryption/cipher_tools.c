#include "woody.h"

/*
 * Encryption stage:
 *  - Generate a random 64-bit key (from /dev/urandom)
 *  - Print it to stdout (project requirement)
 *  - XOR-encrypt the original ".text" section in-place (in our owned buffers)
 *
 * The injected loader stub performs the exact inverse operation at runtime
 * using the same XOR stream (see src/code_to_inject/amd64_xor.s).
 */
static void print_generated_key(const t_woody_context* context) {
    printf("key_value: %016lX\n", (unsigned long)context->encryption.key64);
}

static uint64_t generate_64_bit_key(void) {
    uint64_t key = 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open /dev/urandom: %s\n", strerror(errno));
        return 0;
    }

    ssize_t bytes_read = read(fd, &key, sizeof(key));
    if (bytes_read != sizeof(key)) {
        fprintf(stderr, "Failed to read from /dev/urandom: %s\n",
            bytes_read < 0 ? strerror(errno) : "short read");
        close(fd);
        return 0;
    }

    close(fd);
    return key;
}

static int generate_key(t_woody_context* context) {
    if (!context->encryption.key64)
        context->encryption.key64 = generate_64_bit_key();
    if (context->encryption.key64 == 0)
        return ERR_ENCRYPTION;

    print_generated_key(context);

    print_verbose(context, "Key: ");
    for (size_t i = 0; i < sizeof(uint64_t); i++)
        print_verbose(context, "%02x",
            (unsigned char)(context->encryption.key64 >> (i * 8)));
    print_verbose(context, "\n");

    return SUCCESS;
}

int encrypt_text_section(t_woody_context* context) {
    int text_index = find_elf_section_index(context, ".text");
    if (text_index < 0) {
        print_verbose(context, "Failed to find .text section to encrypt\n");
        return ERR_ENCRYPTION;
    }
    print_verbose(context, "Encrypting .text - Section %d\n", text_index);

    char* text_data = (char*)context->elf.elf64.section_data[text_index];

    context->elf.elf64.text_size = context->elf.elf64.shdr[text_index].sh_size;
    context->elf.elf64.text_entry = context->elf.elf64.shdr[text_index].sh_addr;

    if (generate_key(context) != SUCCESS)
        return ERR_ENCRYPTION;

    if (encrypt_64(
            text_data, context->elf.elf64.text_size, context->encryption.key64)
        != 0)
        return ERR_ENCRYPTION;

    print_verbose(context, "Encrypted .text section\n");
    return SUCCESS;
}
