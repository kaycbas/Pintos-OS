#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/synch.h"

void syscall_init (void);


int write(int fd, const void* buffer, unsigned size);
void exit (int status);
void halt(void);
int exec(const char* cmd_line); //should be pid_t type
int wait(int pid); //should be pid_t type
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* bufffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int ptr_to_kernel_mode(const void* vaddr);
int buffer_check(const void* buffer_vaddr, unsigned size);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct lock syscall_lock;

#endif /* userprog/syscall.h */
