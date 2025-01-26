#include "woody.h"

void cleanup_context(t_woody_context* context) {
    if (context->file.input_fd > 0)
        close(context->file.input_fd);
    if (context->file.output_fd > 0)
        close(context->file.output_fd);

    if (context->file.file_buff)
        munmap(context->file.file_buff, context->file.file_size);

    if (context->elf.is_64bit) {
        if (context->elf.elf64.section_data) {
            for (size_t i = 0; i < context->elf.elf64.ehdr->e_shnum; i++)
                if (context->elf.elf64.section_data[i])
                    free(context->elf.elf64.section_data[i]);
            free(context->elf.elf64.section_data);
        }
        if (context->elf.elf64.shdr)
            free(context->elf.elf64.shdr);
        if (context->elf.elf64.phdr)
            free(context->elf.elf64.phdr);
        if (context->elf.elf64.ehdr)
            free(context->elf.elf64.ehdr);
    } else {
        if (context->elf.elf32.section_data) {
            for (size_t i = 0; i < context->elf.elf32.ehdr->e_shnum; i++)
                if (context->elf.elf32.section_data[i])
                    free(context->elf.elf32.section_data[i]);
            free(context->elf.elf32.section_data);
        }
        if (context->elf.elf32.shdr)
            free(context->elf.elf32.shdr);
        if (context->elf.elf32.phdr)
            free(context->elf.elf32.phdr);
        if (context->elf.elf32.ehdr)
            free(context->elf.elf32.ehdr);
    }

    if (context->file.output_file_path && context->error_code != SUCCESS)
        remove(context->file.output_file_path);

    memset(context, 0, sizeof(t_woody_context));
}
