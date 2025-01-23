<h1 align="center">Woody_Woodpacker</h1>
<h2 align="center">Packing the woods, one byte at a time.</h2>

<div align="center">
<img src="docs/readme_images/woodpecker_elf.png" alt="Ouroboros" width="25%">
</div>

# Table of Contents
- [Introduction](#introduction)
- [Objectives](#objectives)
- [General Instructions](#general-instructions)
- [Mandatory Part](#mandatory-part)
- [Instructions](#instructions)
  - [Cloning the Repository](#cloning-the-repository)
  - [Using Docker](#using-docker)
- [Bonus](#bonus)

# Introduction

“Packers” are tools that compress and encrypt executable programs (e.g., `.exe`, `.dll`) to obfuscate their content until execution. This method helps bypass antivirus checks by encrypting the program in memory and decrypting it just before execution.

The `woody_woodpacker` project challenges you to implement such a packer for 64-bit ELF files. At its core, this project involves creating a program that encrypts an executable file and generates a new file (`woody`). Upon running the new file, it decrypts itself in memory and executes exactly like the original.

# Objectives

The goal of `woody_woodpacker` is to:
1. Encrypt a 64-bit ELF file given as a parameter.
2. Generate a new program (`woody`) that, when executed:
   - Displays the string `....WOODY....` followed by a newline to indicate encryption.
   - Decrypts itself in memory and executes identically to the original program.
3. Explore advanced encryption algorithms for securing the program.
4. Optionally, use assembly for optimized performance.

# General Instructions

- This project is written in **C** with an optional assembly component for optimization.
- The following system calls and functions are authorized:
  - `open`, `close`, `exit`
  - `fputs`, `fflush`, `lseek`
  - `mmap`, `munmap`, `mprotect`
  - `perror`, `strerror`
  - `syscall`
  - The `printf` family of functions
  - Functions from your `libft` (e.g., `read`, `write`, `malloc`, `free`)
- The executable must be named `woody_woodpacker`.
- Ensure the encryption algorithm is robust and justified during evaluation. Basic algorithms like ROT are not sufficient.

# Mandatory Part

### Program Requirements:
1. **Executable Name:** `woody_woodpacker`
2. **Input:** A single binary file parameter (64-bit ELF only).
3. **Output:**
   - A second file named `woody` that:
     - Displays `....WOODY....` followed by a newline when executed.
     - Decrypts itself and executes identically to the original input file.
   - Encryption must not modify the original execution behavior.
4. **Encryption:**
   - The encryption algorithm must be advanced and well-justified.
   - If the algorithm uses a key, it must be generated randomly and displayed in the terminal during execution.

### Constraints:
- The encrypted program must not crash or alter the functionality of the original binary.
- Files not adhering to the 64-bit ELF format should result in an error message.

### Example Use Case:

```bash
# Create a sample executable
$ cat sample.c
#include <stdio.h>
int main(void) {
    printf("Hello, World!\n");
    return (0);
}
$ clang -m64 -o sample sample.c

# Run woody_woodpacker
$ ./woody_woodpacker sample
key_value: 07A51FF040D45D5CD

# Resulting files
$ ls
sample sample.c woody woody_woodpacker

# Run the generated woody program
$ ./woody
....WOODY....
Hello, World!

# Instructions

## Cloning the Repository

To get started with `woody_woodpacker`, clone the repository:

```bash
git clone https://github.com/Splix777/woody_woodpacker
cd woody_woodpacker
```

## Conclusion
The "woody_woodpacker" project is more than just an exercise in encryption—it’s a deep dive into the internals of ELF files, system calls, and low-level programming. By designing a robust packer, you’ll gain insights into binary manipulation, algorithm design, and the delicate balance between obfuscation and performance.

Through this project, you’ll experience the challenges and rewards of working at the intersection of security, systems programming, and cryptography. Whether you stick to the mandatory requirements or take on the bonus challenges, "woody_woodpacker" promises a rich learning experience and a deeper appreciation of executable internals

## Using Docker
This project includes a Docker setup to ensure consistent development environments. Here's how to use it:

- **Docker Commands**
    - Build the Docker Image:
    ```bash
    make build
    ```
    - Start the Docker Container
    ```bash
    make up
    ```
    - Stop the Container
    ```bash
    make down
    ```
    - Clean Up (remove containers, volumes and prune Docker)
    ```bash
    make clean
    ```
    - Build and enter the container all done with a simple make
    ```bash
    make
    ```