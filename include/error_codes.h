#ifndef ERROR_CODES_H
#define ERROR_CODES_H

typedef enum e_error_code
{
    SUCCESS = 0,
    ERR_INVALID_ARGS,
    ERR_REGEX_ERROR,
    ERR_INVALID_KEY,
    ERR_FILE_OPEN,
    ERR_INVALID_BINARY,
    ERR_FILE_PARSE,
    ERR_KEY_GEN,
    ERR_ENCRYPTION,
    ERR_INJECTION,
    ERR_OUTPUT,
    ERR_OVERFLOW,
    ERR_INVALID_CONTEXT,
    ERR_INVALID_ELF,
    ERR_MEMORY_ALLOC,
    ERR_MEMORY,
    ERR_FILE_READ,
    ERR_FILE_WRITE,
    ERR_INVALID_MAGIC,
    NO_CODE_CAVE,
    ERR_FILE_TRUNCATE,
    ERR_ALREADY_SIGNED,
    ERR_UNKNOWN
} t_error_code;

typedef struct s_error
{
    t_error_code code;
    const char *message;
} t_error;

#endif
