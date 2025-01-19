#include "woody.h"

// Find ELF Segment Index by Section
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

// Set Elf Segment Permissions
void set_elf_segment_permission(t_woody_context *context, int index, int flags)
{
    if (context->elf.is_64bit)
        context->elf.elf64.phdr[index].p_flags |= flags;
    else
        context->elf.elf32.phdr[index].p_flags |= flags;
}

// Find Last Segment by Type
int find_last_segment_by_type(t_woody_context *context, unsigned int type)
{
    if (context->elf.is_64bit)
    {
        for (size_t i = context->elf.elf64.ehdr->e_phnum - 1; i > 0; i--)
        {
            // We are trying to find the last segment of a specific type
            // iterating reverse through the program headers allows us
            // to find the last segment of a specific type
            if (context->elf.elf64.phdr[i].p_type == type)
                return i;
        }
    }
    else
    {
        for (size_t i = context->elf.elf32.ehdr->e_phnum - 1; i > 0; i--)
        {
            if (context->elf.elf32.phdr[i].p_type == type)
                return i;
        }
    }

    return -1;
}

// Find Last Section in Segment
int find_last_section_in_segment(t_woody_context *context, int segment_index)
{
    if (context->elf.is_64bit)
    {
        Elf64_Phdr *segment = &context->elf.elf64.phdr[segment_index];
        for (size_t i = context->elf.elf64.ehdr->e_shnum - 1; i > 0; i--)
        {
            Elf64_Shdr *section = &context->elf.elf64.shdr[i];
            // We are trying to find the last section in the segment
            // If the section address is within the segment virtual address
            // and the section address is less than the segment
            // virtual address + segment memory size it means the section is within the segment
            if (section->sh_addr >= segment->p_vaddr &&
                section->sh_addr < (segment->p_vaddr + segment->p_memsz))
                return i;
        }
    }
    else
    {
        Elf32_Phdr *segment = &context->elf.elf32.phdr[segment_index];
        for (size_t i = context->elf.elf32.ehdr->e_shnum - 1; i > 0; i--)
        {
            Elf32_Shdr *section = &context->elf.elf32.shdr[i];
            if (section->sh_addr >= segment->p_vaddr &&
                section->sh_addr < (segment->p_vaddr + segment->p_memsz))
                return i;
        }
    }

    return -1;
}