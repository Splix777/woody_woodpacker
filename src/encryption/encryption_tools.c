#include "woody.h"

// Helper function to generate cryptographically secure random bytes using /dev/urandom
static uint64_t generate64_key(void)
{
    uint64_t key = 0;

    // Generate a random key
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        print_verbose(NULL, "Cannot open /dev/urandom\n");
        return 0;
    }

    // Read exactly 8 bytes (sizeof uint64_t)
    ssize_t bytes_read = read(fd, &key, sizeof(key));
    if (bytes_read != sizeof(key))
    {
        print_verbose(NULL, "Failed to read from /dev/urandom\n");
        close(fd);
        return 0;
    }

    close(fd);
    return key;
}

// Generate the XOR key
static int generate_key(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        // Assuming context->encryption.key64 is uint64_t (not uint64_t*)
        context->encryption.key64 = generate64_key();
        if (!context->encryption.key64)
            return ERR_ENCRYPTION;

        print_verbose(context, "Generated XOR key: ");
        for (size_t i = 0; i < sizeof(uint64_t); i++)
            print_verbose(context, "%02x", (unsigned char)(context->encryption.key64 >> (i * 8)));
        print_verbose(context, "\n");
    }

    return SUCCESS;
}

static uint64_t rotate_right(uint64_t value)
{
    uint64_t n_rotations = 1; // Changed to rotate by 1 bit at a time
    uint64_t int_bits = sizeof(uint64_t) * 8;
    return (value >> n_rotations) | (value << (int_bits - n_rotations));
}

static int xor_encrypt64(char *data, size_t size, uint64_t key)
{
    uint64_t current_key = key;
    for (size_t i = 0; i < size; i++)
    {
        data[i] ^= (char)current_key;
        current_key = rotate_right(current_key);
    }
    return 0;
}

int encrypt_text_section(t_woody_context *context)
{
    int text_index = find_elf_section_index(context, ".text");
    if (text_index < 0)
    {
        print_verbose(context, "Failed to find .text section to encrypt\n");
        return ERR_ENCRYPTION;
    }
    print_verbose(context, "Encrypting .text section %d\n", text_index);

    if (context->elf.is_64bit)
    {
        char *text_data = (char *)context->elf.elf64.section_data[text_index];

        print_verbose(context, ".text before encryption: ");
        for (size_t i = 0; i < context->elf.elf64.shdr[text_index].sh_size; i++)
            print_verbose(context, "%02x", (unsigned char)text_data[i]);
        print_verbose(context, "\n");

        context->elf.elf64.text_size = context->elf.elf64.shdr[text_index].sh_size;
        context->elf.elf64.text_entry = context->elf.elf64.shdr[text_index].sh_addr;

        if (generate_key(context) != SUCCESS)
            return ERR_ENCRYPTION;

        if (xor_encrypt64(text_data,
                          context->elf.elf64.text_size,
                          context->encryption.key64) != 0)
            return ERR_ENCRYPTION;

        print_verbose(context, ".text after encryption: ");
        for (size_t i = 0; i < context->elf.elf64.shdr[text_index].sh_size; i++)
            print_verbose(context, "%02x", (unsigned char)text_data[i]);
        print_verbose(context, "\n");
    }

    print_verbose(context, "Encrypted .text section\n");
    return SUCCESS;
}