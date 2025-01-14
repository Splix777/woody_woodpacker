// #include "woody.h"

// struct replaceable_section
// {
//     const char *name;
//     bool can_replace;
// } replaceable_sections_table[] = {
//     {".comment", true},
//     {".shstrtab", true}};

// static int analyze_program_headers(t_woody_context *context)
// {
//     t_elf_info *info = &context->header.info;

//     for (size_t i = 0; i < info->phnum; i++)
//     {
//         if (info->is_64bit)
//         {
//             Elf64_Phdr *ph = info->phdr.ph64 + i;
//             if (ph->p_type == PT_LOAD && ph->p_flags & PF_X)
//             {
//                 info->text.p_addr = ph->p_vaddr;
//                 info->text.p_size = ph->p_filesz;
//                 info->text.p_offset = ph->p_offset;
//                 return SUCCESS;
//             }
//         }
//         else
//         {
//             Elf32_Phdr *ph = info->phdr.ph32 + i;
//             if (ph->p_type == PT_LOAD && ph->p_flags & PF_X)
//             {
//                 info->text.p_addr = ph->p_vaddr;
//                 info->text.p_size = ph->p_filesz;
//                 info->text.p_offset = ph->p_offset;
//                 return SUCCESS;
//             }
//         }
//     }

//     return ERR_INVALID_ELF;
// }

// static bool get_section_string_table(t_woody_context *context, char **shstrtab)
// {
//     t_elf_info *info = &context->header.info;
//     if (info->is_64bit)
//     {
//         Elf64_Shdr *sh_strtab = &info->shdr.sh64[info->shstrndx];
//         *shstrtab = (char *)context->file.file_buff + sh_strtab->sh_offset;
//     }
//     else
//     {
//         Elf32_Shdr *sh_strtab = &info->shdr.sh32[info->shstrndx];
//         *shstrtab = (char *)context->file.file_buff + sh_strtab->sh_offset;
//     }
//     return *shstrtab != NULL;
// }

// static bool analyze_section_headers(t_woody_context *context)
// {
//     t_elf_info *info = &context->header.info;
//     char *shstrtab = NULL;

//     if (!get_section_string_table(context, &shstrtab))
//         return ERR_INVALID_ELF;

//     for (size_t i = 0; i < info->shnum; i++)
//     {
//         if (info->is_64bit)
//         {
//             Elf64_Shdr *sh = info->shdr.sh64 + i;
//             if (sh->sh_flags & SHF_EXECINSTR && sh->sh_type == SHT_PROGBITS)
//             {
//                 if (strcmp(shstrtab + sh->sh_name, ".text") == 0)
//                 {
//                     info->text.text_section_index = i;
//                     return SUCCESS;
//                 }
//             }
//         }
//         else
//         {
//             Elf32_Shdr *sh = info->shdr.sh32 + i;
//             if (sh->sh_flags & SHF_EXECINSTR && sh->sh_type == SHT_PROGBITS)
//             {
//                 if (strcmp(shstrtab + sh->sh_name, ".text") == 0)
//                 {
//                     info->text.text_section_index = i;
//                     return SUCCESS;
//                 }
//             }
//         }
//     }

//     return ERR_INVALID_ELF;
// }

// // Cave creation strategies
// static bool expand_file(t_woody_context *context, size_t min_size)
// {
//     size_t new_size = context->file.file_size + min_size;
//     // Since we are using mmap, we unmap the file and remap it with the new size
//     if (munmap(context->file.file_buff, context->file.file_size) == -1)
//         return false;

//     int fd = open(context->file.input_file_path, O_RDWR);
//     if (fd == -1)
//         return false;

//     if (ftruncate(fd, new_size) == -1)
//     {
//         close(fd);
//         return false;
//     }

//     context->file.file_buff = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
//     if (context->file.file_buff == MAP_FAILED)
//     {
//         close(fd);
//         return false;
//     }

//     context->file.file_size = new_size;

//     return true;
// }

// static bool create_new_segment(t_woody_context *context, size_t min_size)
// {
//     if (!expand_file(context, min_size))
//         return false;

//     t_elf_info *info = &context->header.info;
//     if (info->is_64bit)
//     {
//         Elf64_Phdr *last_ph = info->phdr.ph64 + info->phnum - 1;
//         Elf64_Phdr new_ph = *last_ph;

//         new_ph.p_offset += last_ph->p_filesz;
//         new_ph.p_vaddr += last_ph->p_filesz;
//         new_ph.p_filesz = min_size;
//         new_ph.p_memsz = min_size;
//         new_ph.p_flags = PF_R | PF_W | PF_X;
//         new_ph.p_type = PT_LOAD;

//         info->phdr.ph64[info->phnum] = new_ph;
//         info->phnum++;
//     }
//     else
//     {
//         Elf32_Phdr *last_ph = info->phdr.ph32 + info->phnum - 1;
//         Elf32_Phdr new_ph = *last_ph;

//         new_ph.p_offset += last_ph->p_filesz;
//         new_ph.p_vaddr += last_ph->p_filesz;
//         new_ph.p_filesz = min_size;
//         new_ph.p_memsz = min_size;
//         new_ph.p_flags = PF_R | PF_W | PF_X;
//         new_ph.p_type = PT_LOAD;

//         info->phdr.ph32[info->phnum] = new_ph;
//         info->phnum++;
//     }

//     // Save info to cave
//     info->cave.offset = info->phdr.ph64[info->phnum - 1].p_offset;
//     info->cave.vaddr = info->phdr.ph64[info->phnum - 1].p_vaddr;
//     info->cave.size = min_size;
//     info->cave.found = true;

//     return true;
// }

// static int create_code_cave(t_woody_context *context, size_t min_size)
// {
//     if (create_new_segment(context, min_size))
//         return SUCCESS;
//     // Other strategies

//     return NO_CODE_CAVE;
// }

// static int find_code_cave(t_woody_context *context, size_t min_size)
// {
//     t_elf_info *info = &context->header.info;
//     info->cave.found = false;
//     size_t largest_gap_size = 0;
//     uint64_t largest_gap_offset = 0;
//     uint64_t largest_gap_vaddr = 0;

//     for (int i = 0; i < info->phnum - 1; i++)
//     {
//         if (info->is_64bit)
//         {
//             Elf64_Phdr *curr = info->phdr.ph64 + i;
//             Elf64_Phdr *next = info->phdr.ph64 + i + 1;

//             uint64_t curr_end = curr->p_offset + curr->p_filesz;
//             uint64_t gap_size = next->p_offset - curr_end;

//             if (curr_end == 0 || curr_end > next->p_offset)
//                 continue;

//             uint64_t alignment = CODE_CAVE_ALIGNMENT;
//             uint64_t aligned_gap_size = (gap_size / alignment) * alignment;

//             if (aligned_gap_size >= min_size)
//             {
//                 if (aligned_gap_size > largest_gap_size && curr->p_flags & PF_X)
//                 {
//                     largest_gap_size = aligned_gap_size;
//                     largest_gap_offset = curr_end;
//                     largest_gap_vaddr = curr->p_vaddr + curr->p_filesz;
//                     memset(context->file.file_buff + largest_gap_offset, 0, gap_size);
//                 }
//             }
//         }
//         else
//         {
//             Elf32_Phdr *curr = info->phdr.ph32 + i;
//             Elf32_Phdr *next = info->phdr.ph32 + i + 1;

//             uint64_t curr_end = curr->p_offset + curr->p_filesz;
//             uint64_t gap_size = next->p_offset - curr_end;

//             if (curr_end == 0 || curr_end > next->p_offset)
//                 continue;

//             uint64_t alignment = CODE_CAVE_ALIGNMENT;
//             uint64_t aligned_gap_size = (gap_size / alignment) * alignment;

//             if (aligned_gap_size >= min_size)
//             {
//                 if (aligned_gap_size > largest_gap_size && curr->p_flags & PF_X)
//                 {
//                     largest_gap_size = aligned_gap_size;
//                     largest_gap_offset = curr_end;
//                     largest_gap_vaddr = curr->p_vaddr + curr->p_filesz;
//                     memset(context->file.file_buff + largest_gap_offset, 0, gap_size);
//                 }
//             }
//         }
//     }

//     if (largest_gap_size > 0)
//     {
//         info->cave.offset = largest_gap_offset;
//         info->cave.vaddr = largest_gap_vaddr;
//         info->cave.size = largest_gap_size;
//         info->cave.found = true;
//         printf("Found code cave at 0x%lx\n", (unsigned long)largest_gap_vaddr);
//         return SUCCESS;
//     }

//     return create_code_cave(context, PAYLOAD_SIZE);
// }

// int analyze_elf_file(t_woody_context *context)
// {
//     t_error_code ret;

//     if ((ret = analyze_program_headers(context)) != SUCCESS)
//         return ret;
//     if ((ret = analyze_section_headers(context)) != SUCCESS)
//         return ret;
//     if ((ret = find_code_cave(context, PAYLOAD_SIZE)) != SUCCESS)
//         return ret;



//     return SUCCESS;
// }