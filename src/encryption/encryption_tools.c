#include "woody.h"

// Helper function to generate cryptographically secure random bytes using /dev/urandom
static bool generate_crypto_random_bytes(unsigned char *buffer, size_t length)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("Cannot open /dev/urandom");
        return false;
    }

    // Read exactly 'length' bytes
    ssize_t bytes_read = 0;
    while (bytes_read < (ssize_t)length)
    {
        ssize_t result = read(fd, buffer + bytes_read, length - bytes_read);
        if (result < 0)
        {
            perror("Error reading from /dev/urandom");
            close(fd);
            return false;
        }
        bytes_read += result;
    }

    close(fd);
    return true;
}

// Generate the XOR key
int generate_key(t_woody_context *context)
{
    unsigned char key[XOR_KEY_SIZE];

    if (context->encryption.key)
    {
        size_t key_len = strlen((char *)context->encryption.key);
        if (key_len != XOR_KEY_SIZE)
            return ERR_ENCRYPTION;
        memcpy(key, context->encryption.key, XOR_KEY_SIZE);
    }
    else if (!generate_crypto_random_bytes(key, XOR_KEY_SIZE))
    {
        print_verbose(context, "Failed to generate random key\n");
        return ERR_ENCRYPTION;
    }

    context->encryption.key = malloc(XOR_KEY_SIZE);
    if (!context->encryption.key)
        return ERR_MEMORY_ALLOC;

    memcpy(context->encryption.key, key, XOR_KEY_SIZE);
    print_verbose(context, "Generated XOR key: ");
    for (size_t i = 0; i < XOR_KEY_SIZE; i++)
        print_verbose(context, "%02x", context->encryption.key[i]);
    print_verbose(context, "\n");

    return SUCCESS;
}

// Encrypt the text section using the XOR key
int encrypt_text_section(t_woody_context *context)
{
    int text_index = find_elf_section_index(context, ".text");
    if (text_index < 0)
    {
        print_verbose(context, "Failed to find .text section to encrypt\n");
        return ERR_ENCRYPTION;
    }
    print_verbose(context, "Encrypting .text section %d\n", text_index);

    char *text_data;
    if (context->elf.is_64bit)
    {
        text_data = (char *)context->elf.elf64.section_data[text_index];

        context->elf.elf64.text_entry = context->elf.elf64.shdr[text_index].sh_addr;
        context->elf.elf64.text_size = context->elf.elf64.shdr[text_index].sh_size;

        if (generate_key(context) != SUCCESS)
            return ERR_ENCRYPTION;

        if (encrypt(
                (char *)context->elf.elf64.section_data[text_index],
                context->elf.elf64.text_size,
                context->encryption.key) != 0)
            return ERR_ENCRYPTION;
    }
    else
    {
        text_data = (char *)context->elf.elf32.section_data[text_index];

        context->elf.elf32.text_entry = context->elf.elf32.shdr[text_index].sh_addr;
        context->elf.elf32.text_size = context->elf.elf32.shdr[text_index].sh_size;

        if (generate_key(context) != SUCCESS)
            return ERR_ENCRYPTION;

        if (encrypt(
                text_data,
                context->elf.elf32.text_size,
                context->encryption.key) != 0)
            return ERR_ENCRYPTION;
    }
    print_verbose(context, "Encrypted .text section\n");

    return SUCCESS;
}
