#include "woody.h"

// Fine ELF Segment Index by Section
int find_elf_segment_index_by_section(t_woody_context *context, int section_index)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_phnum; i++)
        {
            if (context->elf.elf64.phdr[i].p_offset <=
                    context->elf.elf64.shdr[section_index].sh_offset &&
                (context->elf.elf64.phdr[i].p_offset +
                 context->elf.elf64.phdr[i].p_filesz) >=
                    context->elf.elf64.shdr[section_index].sh_offset)
                return i;
        }
    }
    else
    {
        for (size_t i = 0; i < context->elf.elf32.ehdr->e_phnum; i++)
        {
            if (context->elf.elf32.phdr[i].p_offset <=
                    context->elf.elf32.shdr[section_index].sh_offset &&
                (context->elf.elf32.phdr[i].p_offset +
                 context->elf.elf32.phdr[i].p_filesz) >=
                    context->elf.elf32.shdr[section_index].sh_offset)
                return i;
        }
    }

    return -1;
}

// Find Elf Section Name
char *find_elf_section_name(t_woody_context *context, int index)
{
    if (context->elf.is_64bit)
    {
        int shstrndx = context->elf.elf64.ehdr->e_shstrndx;
        char *section_name = (char *)context->elf.elf64.section_data[shstrndx] +
                             context->elf.elf64.shdr[index].sh_name;
        return section_name;
    }
    else
    {
        int shstrndx = context->elf.elf32.ehdr->e_shstrndx;
        char *section_name = (char *)context->elf.elf32.section_data[shstrndx] +
                             context->elf.elf32.shdr[index].sh_name;
        return section_name;
    }
}

// Find Elf Section
int find_elf_section_index(t_woody_context *context, char *name)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
        {
            char *section_name = find_elf_section_name(context, i);
            if (strcmp(section_name, name) == 0)
                return i;
        }
    }
    else
    {
        for (size_t i = 0; i < context->elf.elf32.ehdr->e_shnum; i++)
        {
            char *section_name = find_elf_section_name(context, i);
            if (strcmp(section_name, name) == 0)
                return i;
        }
    }

    return -1;
}

// Find Text Section Index
int find_text_section_index(t_woody_context *context)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = 0; i < context->elf.elf64.ehdr->e_phnum; i++)
        {
            // First we check if the type is PT_LOAD
            // Then we check if the entry point is within the segment by checking if the entry point is greater than the segment virtual address and less than the segment virtual address + segment file size
            // If all conditions are met it means the entry point is within the segment and we return the segment index (The .text section is always within the text segment)
            if (context->elf.elf64.phdr[i].p_type == PT_LOAD &&
                context->elf.elf64.ehdr->e_entry < context->elf.elf64.phdr[i].p_vaddr + context->elf.elf64.phdr[i].p_filesz &&
                context->elf.elf64.ehdr->e_entry >= context->elf.elf64.phdr[i].p_vaddr)
                return i;
        }
    }
    else
    {
        for (size_t i = 0; i < context->elf.elf32.ehdr->e_phnum; i++)
        {
            if (context->elf.elf32.phdr[i].p_type == PT_LOAD &&
                context->elf.elf32.ehdr->e_entry < context->elf.elf32.phdr[i].p_vaddr + context->elf.elf32.phdr[i].p_filesz &&
                context->elf.elf32.ehdr->e_entry >= context->elf.elf32.phdr[i].p_vaddr)
                return i;
        }
    }

    return -1;
}
