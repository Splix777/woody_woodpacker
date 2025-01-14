#include "woody.h"

static int validate_magic(t_woody_context *context)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)context->file.file_buff;
    unsigned char *e_ident = ehdr->e_ident;

    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0 ||
        e_ident[EI_MAG0] != ELFMAG0 ||
        e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 ||
        e_ident[EI_MAG3] != ELFMAG3)
    {
        print_verbose(context,
                      "Invalid Magic: %c%c%c%c\n",
                      e_ident[EI_MAG0],
                      e_ident[EI_MAG1],
                      e_ident[EI_MAG2],
                      e_ident[EI_MAG3]);
        return ERR_INVALID_ELF;
    }
    return SUCCESS;
}

static int validate_class_and_machine(t_woody_context *context)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)context->file.file_buff;
    unsigned char e_class = ehdr->e_ident[EI_CLASS];
    uint16_t machine = ehdr->e_machine;

    if ((e_class != ELFCLASS64 && e_class != ELFCLASS32) ||
        (machine != EM_X86_64 && machine != EM_386))
    {
        print_verbose(context,
                      "Invalid Class: %d or Machine: %d\n",
                      e_class, machine);
        return ERR_INVALID_ELF;
    }
    context->elf.is_64bit = (e_class == ELFCLASS64);
    print_verbose(
        context,
        "ELF 64-bit: %s", context->elf.is_64bit ? "true\n" : "false\n");

    return SUCCESS;
}

static int validate_type(t_woody_context *context)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)context->file.file_buff;
    uint16_t type = ehdr->e_type;

    if (type != ET_EXEC && type != ET_DYN)
    {
        print_verbose(context, "Invalid Type: %d\n", type);
        return ERR_INVALID_ELF;
    }
    print_verbose(
        context,
        "Executable Type: %s\n",
        type == ET_EXEC ? "Executable" : "Dynamic");

    return SUCCESS;
}

static int validate_header_fields(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)context->file.file_buff;
        if (ehdr->e_phnum == 0 || ehdr->e_shnum == 0)
        {
            print_verbose(
                context,
                "Program Header Count: %ld, Section Header Count: %ld\n",
                ehdr->e_phnum, ehdr->e_shnum);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_phoff == 0 || ehdr->e_shoff == 0)
        {
            print_verbose(
                context,
                "Program Header Offset: %ld, Section Header Offset: %ld\n",
                ehdr->e_phoff, ehdr->e_shoff);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_phoff >= context->file.file_size ||
            ehdr->e_shoff >= context->file.file_size)
        {
            print_verbose(
                context,
                "Program Header Offset: %ld, Section Header Offset: %ld\n",
                ehdr->e_phoff, ehdr->e_shoff);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_shstrndx == SHN_UNDEF)
        {
            print_verbose(
                context,
                "Section Header String Table Index: %d\n",
                ehdr->e_shstrndx);
            return ERR_INVALID_ELF;
        }
    }
    else
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)context->file.file_buff;
        if (ehdr->e_phnum == 0 || ehdr->e_shnum == 0)
        {
            print_verbose(
                context,
                "Program Header Count: %d, Section Header Count: %d\n",
                ehdr->e_phnum, ehdr->e_shnum);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_phoff == 0 || ehdr->e_shoff == 0)
        {
            print_verbose(
                context,
                "Program Header Offset: %d, Section Header Offset: %d\n",
                ehdr->e_phoff, ehdr->e_shoff);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_phoff >= context->file.file_size ||
            ehdr->e_shoff >= context->file.file_size)
        {
            print_verbose(
                context,
                "Program Header Offset: %d, Section Header Offset: %d\n",
                ehdr->e_phoff, ehdr->e_shoff);
            return ERR_INVALID_ELF;
        }
        if (ehdr->e_shstrndx == SHN_UNDEF)
        {
            print_verbose(
                context,
                "Section Header String Table Index: %d\n",
                ehdr->e_shstrndx);
            return ERR_INVALID_ELF;
        }
    }

    return SUCCESS;
}

static int validate_entry_point(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)context->file.file_buff;
        if (ehdr->e_entry == 0)
        {
            print_verbose(context, "Invalid Entry Point: %ld\n", ehdr->e_entry);
            return ERR_INVALID_ELF;
        }
        context->elf.elf64.old_entry = ehdr->e_entry;
    }
    else
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)context->file.file_buff;
        if (ehdr->e_entry == 0)
        {
            print_verbose(context, "Invalid Entry Point: %d\n", ehdr->e_entry);
            return ERR_INVALID_ELF;
        }
        context->elf.elf32.old_entry = ehdr->e_entry;
    }

    return SUCCESS;
}

int validate_headers(t_woody_context *context)
{
    t_error_code ret;
    if ((ret = validate_magic(context)) != SUCCESS)
        return ret;
    if ((ret = validate_class_and_machine(context)) != SUCCESS)
        return ret;
    if ((ret = validate_type(context)) != SUCCESS)
        return ret;
    if ((ret = validate_header_fields(context)) != SUCCESS)
        return ret;
    if ((ret = validate_entry_point(context)) != SUCCESS)
        return ret;

    return SUCCESS;
}
