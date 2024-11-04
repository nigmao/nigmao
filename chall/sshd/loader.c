// gcc loader.c -o loader
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>  // Để sử dụng uintptr_t

void *global_encrypted_data = NULL;
size_t encrypted_data_size = 0;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// Sử dụng mmap để cấp phát bộ nhớ cho shellcode với quyền thực thi
void *load_shellcode(const char *filename, size_t *shellcode_size) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    fseek(fdopen(fd, "r"), 0, SEEK_END);
    *shellcode_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Cấp phát bộ nhớ với mmap có quyền thực thi (PROT_READ | PROT_WRITE | PROT_EXEC)
    void *shellcode = mmap(NULL, *shellcode_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (shellcode == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Đọc dữ liệu shellcode vào vùng nhớ được cấp phát bởi mmap
    if (read(fd, shellcode, *shellcode_size) != *shellcode_size) {
        perror("read");
        munmap(shellcode, *shellcode_size);
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    return shellcode;
}

// Hàm load encrypted data từ file
void load_encrypted_data(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open encrypted file");
        exit(EXIT_FAILURE);
    }

    fseek(fdopen(fd, "r"), 0, SEEK_END);
    encrypted_data_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    global_encrypted_data = malloc(encrypted_data_size);
    if (!global_encrypted_data) {
        perror("malloc for encrypted data");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (read(fd, global_encrypted_data, encrypted_data_size) != encrypted_data_size) {
        perror("read encrypted file");
        free(global_encrypted_data);
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
    return;
}

int main() {
    const char *shellcode_filename = "decrypted_shellcode.bin";
    const char *encrypted_filename = "encrypted_shellcode.bin";
    size_t shellcode_size = 0;

    // Load encrypted data từ file vào biến toàn cục
    load_encrypted_data(encrypted_filename);

    // Load shellcode từ file sử dụng mmap
    void *shellcode = load_shellcode(shellcode_filename, &shellcode_size);

    // In kích thước và địa chỉ shellcode
    printf("Loaded shellcode size: %zu bytes, address: %p\n", shellcode_size, shellcode);
    printf("Loaded encrypted data size: %zu bytes, address: %p\n", encrypted_data_size, global_encrypted_data);

    // Thiết lập các thanh ghi và gọi shellcode
    asm volatile (
        "mov $0x1, %%rbx\n"            // Thiết lập rbx = 0x1
        "mov %0, %%rsi\n"              // Thiết lập rsi bằng địa chỉ encrypted data
        "mov $0x200, %%rdi\n"          // Thiết lập rdi = 0x200
        "mov $0x200, %%r12\n"          // Thiết lập r12 = 0x200
        "call *%1\n"                   // Gọi shellcode
        :
        : "r"(global_encrypted_data), "r"(shellcode) // Tham số cho rsi và địa chỉ shellcode
        : "rbx", "rsi", "rdi", "r12"    // Các thanh ghi bị thay đổi
    );

    // Giải phóng bộ nhớ mmap
    munmap(shellcode, shellcode_size);
    free(global_encrypted_data);

    return 0;
}
