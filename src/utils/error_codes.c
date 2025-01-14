#include "woody.h"

static const t_error error_table[] = {
    {SUCCESS, "No error"},
    {ERR_INVALID_ARGS, "Invalid arguments"},
    {ERR_REGEX_ERROR, "Regex error"},
    {ERR_INVALID_KEY, "Invalid key error"},
    {ERR_FILE_OPEN, "File open error"},
    {ERR_INVALID_BINARY, "Invalid binary error"},
    {ERR_FILE_PARSE, "File parse error"},
    {ERR_KEY_GEN, "Key generation error"},
    {ERR_ENCRYPTION, "Encryption error"},
    {ERR_INJECTION, "Code injection error"},
    {ERR_OUTPUT, "Output creation error"},
    {ERR_OVERFLOW, "Overflow error"},
    {ERR_INVALID_CONTEXT, "Invalid context error"},
    {ERR_INVALID_ELF, "Invalid ELF error"},
    {ERR_MEMORY_ALLOC, "Memory allocation error"},
    {ERR_MEMORY, "Memory error"},
    {ERR_FILE_READ, "File read error"},
    {ERR_FILE_WRITE, "File write error"},
    {ERR_INVALID_MAGIC, "Invalid magic error"},
    {NO_CODE_CAVE, "No code cave found"},
    {ERR_FILE_TRUNCATE, "File truncate error"},
    {ERR_UNKNOWN, "Unknown error"},
};

#define ERROR_COUNT (sizeof(error_table) / sizeof(t_error))

const char *get_error_message(t_error_code code)
{
    for (size_t i = 0; i < ERROR_COUNT; i++)
    {
        if (error_table[i].code == code)
        {
            // Use perror to check if the error code is a system error
            return error_table[i].message;
        }
    }
    return "Unknown error code";
}

void print_error(t_error_code code)
{
    const char *message = get_error_message(code);
    fprintf(stderr, "Error: %s\n", message);

    if (errno != 0)
        perror("System error");
}

t_error_code handle_error(t_woody_context *context, t_error_code err_code)
{
    if (context)
    {
        context->error_code = err_code;
        cleanup_context(context);
    }
    print_error(err_code);
    return err_code;
}
