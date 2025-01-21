#include "woody.h"

// Check if the file name is valid
static int is_valid_file_name(const char *name)
{
    if (!name || strlen(name) > 255 || strlen(name) < 1)
    {
        fprintf(stderr,
                "%s Invalid file name length: %s\n",
                BOXED_CROSS, name ? name : "NULL");
        return ERR_INVALID_ARGS;
    }

    for (size_t i = 0; i < strlen(name); i++)
    {
        if (!isalnum(name[i]) &&
            name[i] != '/' &&
            name[i] != '.' &&
            name[i] != '_')
        {
            fprintf(stderr,
                    "%sInvalid character in file name: %s\n",
                    BOXED_CROSS, name);
            return ERR_INVALID_ARGS;
        }
    }

    return SUCCESS;
}

// Print help/usage information
static void print_help(const char *name)
{
    fprintf(stderr, "Usage: %s -f <input_file> [-o <output_file>] [-v] [-h]\n", name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -f <input_file>    Input file name\n");
    fprintf(stderr, "  -o <output_file>   Output file name\n");
    fprintf(stderr, "  -v                 Enable verbose output\n");
    fprintf(stderr, "  -h                 Display this help message\n");
}

// Parse command-line arguments
int argument_parse(int argc, char **argv, t_woody_context *context)
{
    if (argc < 3 || argc > 7)
    {
        print_help(argv[0]);
        return ERR_INVALID_ARGS;
    }

    // Default values
    context->compression = false;
    context->verbose = false;
    context->file.output_file_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-f") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "%s Missing argument for -f\n", BOXED_CROSS);
                print_help(argv[0]);
                return ERR_INVALID_ARGS;
            }
            if (is_valid_file_name(argv[i + 1]) != SUCCESS)
                return ERR_INVALID_ARGS;
            context->file.input_file_path = argv[++i];
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "%s Missing argument for -o\n", BOXED_CROSS);
                print_help(argv[0]);
                return ERR_INVALID_ARGS;
            }
            if (is_valid_file_name(argv[i + 1]) != SUCCESS)
                return ERR_INVALID_ARGS;
            context->file.output_file_path = argv[++i];
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            context->verbose = true;
            fprintf(stderr, "%s Verbose mode enabled\n", BOXED_CHECKMARK);
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            print_help(argv[0]);
            return SUCCESS;
        }
        else
        {
            fprintf(stderr,
                    "%s Unknown argument: %s\n",
                    BOXED_CHECKMARK, argv[i]);
            print_help(argv[0]);
            return ERR_INVALID_ARGS;
        }
    }

    if (!context->file.input_file_path)
    {
        fprintf(stderr,
                "%s Input file is required (-f <input_file>)\n",
                BOXED_CROSS);
        print_help(argv[0]);
        return ERR_INVALID_ARGS;
    }

    if (!context->file.output_file_path)
        context->file.output_file_path = OUTPUT_FILE_NAME;

    return SUCCESS;
}
