# Compiler and Assembler
CC = gcc
AS = nasm
CFLAGS = -Wall -Wextra -Werror -g -O2
LDFLAGS = -no-pie
ASFLAGS = -f elf64

# Directories
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include

# Source files
C_SRCS = $(shell find $(SRC_DIR) -type f -name '*.c')
ASM_SRCS = $(shell find $(SRC_DIR) -type f -name '*.s')

# Object files
C_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(C_SRCS))
ASM_OBJS = $(patsubst $(SRC_DIR)/%.s, $(OBJ_DIR)/%.o, $(ASM_SRCS))
OBJS = $(C_OBJS) $(ASM_OBJS)

# Binary output
NAME = woody_woodpacker

# Include dependency files
DEP_FILES = $(C_OBJS:.o=.d)
-include $(DEP_FILES)

# Default target
all: $(NAME)

# Build binary
$(NAME): $(OBJS)
	@echo "Linking $(NAME)..."
	@$(CC) $(LDFLAGS) $(OBJS) -o $@

# Compile C source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -MMD -o $@ -c $<

# Assemble assembly source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s
	@mkdir -p $(@D)
	@echo "Assembling $<..."
	@$(AS) $(ASFLAGS) -o $@ $<

# Clean object files and dependencies
clean:
	@echo "Cleaning object files..."
	@rm -rf $(OBJ_DIR)

# Clean everything including the binary
fclean: clean
	@echo "Removing binary..."
	@rm -f $(NAME)

# Rebuild everything
re: fclean all

# Debug mode
debug: CFLAGS += -g
debug: re

# Phony targets
.PHONY: all clean fclean re debug
