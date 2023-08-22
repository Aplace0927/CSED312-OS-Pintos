#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/vaddr.h"

void syscall_init (void);

/* Syscall handler functions. */
void syscall_handle_halt(void* esp UNUSED);        // NORETRN void ()
void syscall_handle_exit(void* esp);        // NORETRN void (int)
void syscall_handle_exec(void* esp);        // pid_t (const char*)
void syscall_handle_wait(void* esp);        // int (pid_t)
void syscall_handle_create(void* esp);      // bool (const char*, unsigned)
void syscall_handle_remove(void* esp);      // bool (const char*)
void syscall_handle_open(void* esp);        // int (const char*)
void syscall_handle_filesize(void* esp);    // int (int)
void syscall_handle_read(void* esp);        // int (int, void*, unsigned)
void syscall_handle_write(void* esp);       // int (int, const void*, unsigned)
void syscall_handle_seek(void* esp);        // void (int, unsigned)
void syscall_handle_tell(void* esp);        // unsigned (int)
void syscall_handle_close(void* esp);       // void (int)

void syscall_handle_mmap(void* esp);        // mapid_t (int, void* esp)
void syscall_handle_munmap(void* esp);      // void (mapid_t)

void syscall_handle_chdir(void* esp);       // bool (const char*)
void syscall_handle_mkdir(void* esp);       // bool (const char*)
void syscall_handle_readdir(void* esp);     // bool (int, char[])
void syscall_handle_isdir(void* esp);       // bool (int)
void syscall_handle_inumber(void* esp);     // int (int)

#endif /* userprog/syscall.h */
