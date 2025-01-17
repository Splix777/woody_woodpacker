# Binary outputs
NAME = woody_woodpacker

# Compiler and flags
CC = gcc
AS = nasm
CFLAGS = -Wall -Wextra -Werror -g3 -O2 -pie
ASFLAGS = -f elf64

# Directories
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include
INJECT_DIR = $(SRC_DIR)/code_to_inject

# Source files
C_SRCS = $(filter-out $(INJECT_DIR)/payload.c, $(shell find $(SRC_DIR) -type f -name '*.c'))
ASM_SRCS = $(SRC_DIR)/encryption/encrypt.s
INJECT_ASM = $(INJECT_DIR)/amd64_xor.s
INJECT_PAYLOAD = $(INJECT_DIR)/payload.c

# Headers
HEADERS = $(shell find $(INCLUDE_DIR) -type f -name '*.h')
INC = $(addprefix -I , $(INCLUDE_DIR))

# Object files
C_OBJS = $(C_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
ASM_OBJS = $(ASM_SRCS:$(SRC_DIR)/%.s=$(OBJ_DIR)/%.o)
INJECT_OBJ = $(OBJ_DIR)/code_to_inject/woody_injection.o
PAYLOAD_OBJ = $(OBJ_DIR)/code_to_inject/payload.o

# All objects combined
ALL_OBJS = $(PAYLOAD_OBJ) $(C_OBJS) $(ASM_OBJS)

# Default target
all: $(NAME)

# Main binary build
$(NAME): $(OBJ_DIR) $(ALL_OBJS)
	@printf "Linking %-40s" "$(NAME)"
	@$(CC) $(CFLAGS) -o $@ $(ALL_OBJS)
	@echo "[\033[32m OK \033[0m]"
	@echo "Binary size: $$(wc -c < $@) bytes"

# Create object directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/code_to_inject
	@mkdir -p $(OBJ_DIR)/encryption
	@mkdir -p $(OBJ_DIR)/injector
	@mkdir -p $(OBJ_DIR)/parser
	@mkdir -p $(OBJ_DIR)/utils
	@mkdir -p $(OBJ_DIR)/utils/printing_utils

# Build injection object file
$(INJECT_OBJ): $(INJECT_ASM)
	@printf "Assembling %-40s" "$(notdir $<)"
	@$(AS) -w[+-]error=x -g -f bin -o $@ $<
	@echo "[\033[32m OK \033[0m]"
	@echo "Injection size: $$(wc -c < $@) bytes"

# Generate and compile payload
$(PAYLOAD_OBJ): $(INJECT_OBJ)
	@printf "Generating %-40s" "payload.c"
	@./generate_payload.sh $< $(INJECT_PAYLOAD)
	@echo "[\033[32m OK \033[0m]"
	@printf "Compiling %-40s" "payload.c"
	@$(CC) $(CFLAGS) $(INC) -c $(INJECT_PAYLOAD) -o $@
	@echo "[\033[32m OK \033[0m]"

# Compile C source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@printf "Compiling %-40s" "$(notdir $<)"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@
	@echo "[\033[32m OK \033[0m]"

# Compile Assembly source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s
	@printf "Assembling %-40s" "$(notdir $<)"
	@mkdir -p $(dir $@)
	@$(AS) $(ASFLAGS) $< -o $@
	@echo "[\033[32m OK \033[0m]"

# Compile Injected code as standalone
standalone: $(INJECT_OBJ) $(PAYLOAD_OBJ)
	@printf "Linking %-40s" "woody"
	@$(CC) $(CFLAGS) -o woody $(INJECT_OBJ) $(PAYLOAD_OBJ)
	@echo "[\033[32m OK \033[0m]"
	@echo "Binary size: $$(wc -c < woody) bytes"

# Clean object files
clean:
	@printf "Cleaning objects... "
	@rm -rf $(OBJ_DIR)
	@rm -f $(INJECT_PAYLOAD)
	@echo "[\033[32m OK \033[0m]"

# Clean everything
fclean: clean
	@printf "Cleaning binaries... "
	@rm -f $(NAME)
	@rm -f woody
	@echo "[\033[32m OK \033[0m]"

# Rebuild everything
re: fclean all

# Debug build
debug: CFLAGS += -g3 -DDEBUG
debug: re

# Utility targets
dump: $(INJECT_OBJ)
	@echo "Hexdump of injection code:"
	@hexdump -C $(INJECT_OBJ)

.PHONY: all clean fclean re debug dump