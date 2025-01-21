# Binary outputs
NAME = woody_woodpacker

# Compiler and flags
CC = gcc
AS = nasm
CFLAGS = -Wall -Wextra -Werror -O2
ASFLAGS = -f elf64 -g

# Docker
DOCKER_COMPOSE = docker compose
SERVICE_NAME = woody_woodpacker

# Directories
SRC_DIR = src
OBJ_DIR = obj
INCLUDE_DIR = include
INJECT_DIR = $(SRC_DIR)/code_to_inject

# Source files
INJECT_ASM_64 = $(INJECT_DIR)/amd64_xor.s
INJECT_ASM_32 = $(INJECT_DIR)/i386_xor.s
INJECT_PAYLOAD_64 = $(INJECT_DIR)/payload_64.c
INJECT_PAYLOAD_32 = $(INJECT_DIR)/payload_32.c
ASM_SRCS = $(filter-out $(INJECT_ASM_64) $(INJECT_ASM_32), $(shell find $(SRC_DIR) -type f -name '*.s'))
C_SRCS = $(filter-out $(INJECT_PAYLOAD_64) $(INJECT_PAYLOAD_32), $(shell find $(SRC_DIR) -type f -name '*.c'))

# Headers
HEADERS = $(shell find $(INCLUDE_DIR) -type f -name '*.h')
INC = $(addprefix -I , $(INCLUDE_DIR))

# Object files
C_OBJS = $(C_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
ASM_OBJS = $(ASM_SRCS:$(SRC_DIR)/%.s=$(OBJ_DIR)/%.o)
INJECT_OBJ_64 = $(OBJ_DIR)/code_to_inject/amd64_xor.o
INJECT_OBJ_32 = $(OBJ_DIR)/code_to_inject/i386_xor.o
PAYLOAD_OBJ_64 = $(OBJ_DIR)/code_to_inject/payload_64.o
PAYLOAD_OBJ_32 = $(OBJ_DIR)/code_to_inject/payload_32.o

# All objects combined
ALL_OBJS = $(PAYLOAD_OBJ_64) $(PAYLOAD_OBJ_32) $(C_OBJS) $(ASM_OBJS)

# Colors
GREEN = \033[32m
RESET = \033[0m

# Default target
all: $(NAME)

# Main binary build
$(NAME): $(OBJ_DIR) $(ALL_OBJS)
	@printf "Linking %-42s" "$(NAME)"
	@$(CC) $(CFLAGS) -o $@ $(ALL_OBJS)
	@echo "$(GREEN)[ OK ]$(RESET)"
	@echo "$(GREEN)Binary size: $$(wc -c < $@) bytes$(RESET)"

# Create object directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/code_to_inject
	@mkdir -p $(OBJ_DIR)/encryption
	@mkdir -p $(OBJ_DIR)/injector
	@mkdir -p $(OBJ_DIR)/parser
	@mkdir -p $(OBJ_DIR)/utils
	@mkdir -p $(OBJ_DIR)/utils/printing_utils

# Build injection object files
$(INJECT_OBJ_64): $(INJECT_ASM_64)
	@printf "Assembling %-39s" "$(notdir $<)"
	@$(AS) -f bin -o $@ $<
	@echo "$(GREEN)[ OK ]$(RESET)"
	@echo "$(GREEN)Injection size: $$(wc -c < $@) bytes$(RESET)"

$(INJECT_OBJ_32): $(INJECT_ASM_32)
	@printf "Assembling %-39s" "$(notdir $<)"
	@$(AS) -f bin -o $@ $<
	@echo "$(GREEN)[ OK ]$(RESET)"
	@echo "$(GREEN)Injection size: $$(wc -c < $@) bytes$(RESET)"

# Generate and compile payloads
$(PAYLOAD_OBJ_64): $(INJECT_OBJ_64)
	@printf "Generating %-39s" "payload_64.c"
	@./generate_payload.sh $< $(INJECT_PAYLOAD_64) INJECTION_PAYLOAD_64
	@echo "$(GREEN)[ OK ]$(RESET)"
	@printf "Compiling %-40s" "payload_64.c"
	@$(CC) $(CFLAGS) $(INC) -c $(INJECT_PAYLOAD_64) -o $@
	@echo "$(GREEN)[ OK ]$(RESET)"

$(PAYLOAD_OBJ_32): $(INJECT_OBJ_32)
	@printf "Generating %-39s" "payload_32.c"
	@./generate_payload.sh $< $(INJECT_PAYLOAD_32) INJECTION_PAYLOAD_32
	@echo "$(GREEN)[ OK ]$(RESET)"
	@printf "Compiling %-40s" "payload_32.c"
	@$(CC) $(CFLAGS) $(INC) -c $(INJECT_PAYLOAD_32) -o $@
	@echo "$(GREEN)[ OK ]$(RESET)"

# Compile C source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@printf "Compiling %-40s" "$(notdir $<)"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@
	@echo "$(GREEN)[ OK ]$(RESET)"

# Compile Assembly source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s
	@printf "Assembling %-39s" "$(notdir $<)"
	@mkdir -p $(dir $@)
	@$(AS) $(ASFLAGS) $< -o $@
	@echo "$(GREEN)[ OK ]$(RESET)"

# Docker
build:
	@echo "Building the Docker image..."
	@$(DOCKER_COMPOSE) build

up:
	@echo "Starting the Docker container..."
	@$(DOCKER_COMPOSE) up -d

down:
	@echo "Stopping the Docker container..."
	@$(DOCKER_COMPOSE) down

exec:
	@echo "Accessing the Docker container..."
	@$(DOCKER_COMPOSE) exec -it $(SERVICE_NAME) bash

dclean:
	@echo "Cleaning up Docker..."
	@$(DOCKER_COMPOSE) down --rmi all
	@docker system prune -f
	@docker volume prune -f

# Clean object files
clean:
	@printf "Cleaning objects... %-2s"
	@rm -rf $(OBJ_DIR)
	@rm -f $(INJECT_PAYLOAD_64) $(INJECT_PAYLOAD_32)
	@echo "$(GREEN)[ OK ]$(RESET)"

# Clean everything
fclean: clean
	@printf "Cleaning binaries... %-1s"
	@rm -f $(NAME)
	@rm -f woody
	@echo "$(GREEN)[ OK ]$(RESET)"

# Rebuild everything
re: fclean all

# Debug build
debug: CFLAGS += -g3 -DDEBUG
debug: re

# Utility targets
dump: $(INJECT_OBJ_64) $(INJECT_OBJ_32)
	@echo "Hexdump of 64-bit injection code:"
	@hexdump -C $(INJECT_OBJ_64)
	@echo
	@echo "Hexdump of 32-bit injection code:"
	@hexdump -C $(INJECT_OBJ_32)

.PHONY: all clean fclean re debug dump build up down exec dclean
