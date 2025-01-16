#include "woody.h"

static int is_valid_file_name(const char *name)
{
    if (strlen(name) > 255 || strlen(name) < 1)
    {
        fprintf(stderr, "Invalid file name length: %s\n", name);
        return ERR_INVALID_ARGS;
    }

    for (size_t i = 0; i < strlen(name); i++)
    {
        if (
            (!isalnum(name[i]) && name[i] != '/') &&
            name[i] != '.' &&
            name[i] != '_')
        {
            fprintf(stderr, "Invalid character in file name: %s\n", name);
            return ERR_INVALID_ARGS;
        }
    }

    return SUCCESS;
}

static int valid_key(const char *key, int key_size)
{
    if (strlen(key) != (size_t)key_size)
    {
        fprintf(
            stderr,
            "Invalid key length: %s, must be %d characters\n",
            key, key_size);
        return ERR_INVALID_KEY;
    }

    for (size_t i = 0; i < strlen(key); i++)
    {
        if (!isxdigit(key[i]))
        {
            fprintf(stderr, "Invalid character in key: %s\n", key);
            return ERR_INVALID_KEY;
        }
    }

    return SUCCESS;
}

static void print_help(const char *name)
{
    fprintf(
        stderr,
        "Usage: %s <input_file> -o [output_file] -k [key] -c [compress]\n",
        name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o <output_file>  Output file name\n");
    fprintf(stderr, "  -k <key>          Encryption key (32 characters)\n");
    fprintf(stderr, "  -c                Enable compression\n");
    fprintf(stderr, "  -v                Enable verbose output\n");
}

int argument_parse(int argc, char **argv, t_woody_context *context)
{
    t_error_code ret;

    if (argc < 2 || argc > 7)
    {
        print_help(argv[0]);
        return ERR_INVALID_ARGS;
    }

    context->file.input_file_path = argv[1];

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 >= argc)
            {
                print_help(argv[0]);
                return ERR_INVALID_ARGS;
            }
            if ((ret = is_valid_file_name(argv[i + 1]) != SUCCESS))
                return ERR_INVALID_ARGS;
            context->file.output_file_path = argv[i + 1];
            print_verbose(context, "Output file: %s\n", context->file.output_file_path);
            i++;
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            if (i + 1 >= argc)
            {
                print_help(argv[0]);
                handle_error(context, ERR_INVALID_ARGS);
            }
            if ((ret = valid_key(argv[i + 1], XOR_KEY_SIZE) != SUCCESS))
                return ERR_INVALID_ARGS;
            // context->encryption.key64 = argv[i + 1];
            // print_verbose(context, "Encryption key: %s\n", context->encryption.key64);
            i++;
        }
        else if (strcmp(argv[i], "-c") == 0)
        {
            context->compression = true;
            print_verbose(context, "Compression enabled\n");
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            context->verbose = true;
            print_verbose(context, "Verbose output enabled\n");
        }
        else
        {
            print_help(argv[0]);
            return ERR_INVALID_ARGS;
        }
    }
    if (!context->file.output_file_path)
    {
        context->file.output_file_path = OUTPUT_FILE_NAME;
        print_verbose(context, "Output file: %s\n", context->file.output_file_path);
    }

    return SUCCESS;
}