#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/vaddr.h"

void syscall_init (void);

/* Arguments validating. */
void validate_user_address (void *addr);                // Validates `type**`
void validate_argument_address (void *esp, int argc);   // Validates `type*`

/* File and stream related lock. */
struct lock lock_files;

/* Syscall handler functions. */
void syscall_handle_halt (void* esp UNUSED, struct intr_frame* UNUSED); // NORETRN void ()
void syscall_handle_exit (void* esp, struct intr_frame* UNUSED);        // NORETRN void (int)
void syscall_handle_exec (void* esp, struct intr_frame*);        // pid_t (const char*)
void syscall_handle_wait (void* esp, struct intr_frame*);        // int (pid_t)
void syscall_handle_create (void* esp, struct intr_frame*);      // bool (const char*, unsigned)
void syscall_handle_remove (void* esp, struct intr_frame*);      // bool (const char*)
void syscall_handle_open (void* esp, struct intr_frame*);        // int (const char*)
void syscall_handle_filesize (void* esp, struct intr_frame*);    // int (int)                                        // Prevent race condition during file IO
void syscall_handle_read (void* esp, struct intr_frame*);        // int (int, void*, unsigned)
void syscall_handle_write (void* esp, struct intr_frame*);       // int (int, const void*, unsigned)
void syscall_handle_seek (void* esp, struct intr_frame* UNUSED);        // void (int, unsigned)
void syscall_handle_tell (void* esp, struct intr_frame*);        // unsigned (int)
void syscall_handle_close (void* esp, struct intr_frame* UNUSED);       // void (int)


void syscall_handle_mmap (void* esp, struct intr_frame*);        // mapid_t (int, void* esp)
void syscall_handle_munmap (void* esp, struct intr_frame* UNUSED);      // void (mapid_t)


void syscall_handle_chdir (void* esp, struct intr_frame*);       // bool (const char*)
void syscall_handle_mkdir (void* esp, struct intr_frame*);       // bool (const char*)
void syscall_handle_readdir (void* esp, struct intr_frame*);     // bool (int, char[])
void syscall_handle_isdir (void* esp, struct intr_frame*);       // bool (int)
void syscall_handle_inumber (void* esp, struct intr_frame*);     // int (int)


struct file* file_find_descriptor_table (struct thread*, int);
int file_add_descriptor_table (struct thread*, struct file*);
void file_delete_descriptor_table (struct thread*, int);
#endif /* userprog/syscall.h */
