#include "devices/shutdown.h"

#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_id = (int) (*(addr_t*) (f->esp));
  
  // Syscall function pointers
  void (*syscall_function[SYSCALL_COUNT]) (void*) =
  {
    syscall_handle_halt,      // void halt () NO_RETURN
    syscall_handle_exit,      // void exit (int status) NO_RETURN
    syscall_handle_exec,      // pid_t exec (const char* file)
    syscall_handle_wait,      // int wait (pid_t pid)
    syscall_handle_create,    // bool create (const char* file, unsigned initial_size)
    syscall_handle_remove,    // bool remove (const char* file)
    syscall_handle_open,      // int open (const char* file)
    syscall_handle_filesize,  // int filesize (int fd)
    syscall_handle_read,      // int read (int fd, void* buffer, unsigned size)
    syscall_handle_write,     // int write (int fd, const void* buffer, unsigned size)
    syscall_handle_seek,      // void seek (int fd, unsigned position)
    syscall_handle_tell,      // unsigned tell (int fd)
    syscall_handle_close,     // void close (int fd)

    syscall_handle_mmap,      // mapid_t mmap (int fd, void *addr)
    syscall_handle_munmap,    // void munmap (mapid_t mapid)

    syscall_handle_chdir,     // bool chdir (const char* dir)
    syscall_handle_mkdir,     // bool mkdir (const char* dir)
    syscall_handle_readdir,   // bool readdir (int fd, char name[])
    syscall_handle_isdir,     // bool isdir (int fd)
    syscall_handle_inumber,   // int inumber (int fd)
  };

  if (0 <= syscall_id && syscall_id < SYSCALL_COUNT)
  {
    syscall_function[syscall_id](f->esp);
  }
  else
  {
    syscall_handle_exit(NULL);
  }
}

void
syscall_handle_halt (void* esp UNUSED)
{
  shutdown_power_off();
  NOT_REACHED();
}

void
syscall_handle_exit (void* esp)
{
  struct thread* current_thread = thread_current();
  int exit_code;

  if (esp)
  {
    exit_code = *(int*)(esp);
  }
  else
  {
    exit_code = -1;
  }

  printf("%s: exit(%d)\n", current_thread->name, exit_code);
  thread_exit();
  NOT_REACHED();
}

void
syscall_handle_exec (void* esp)
{
  ASSERT(esp != NULL);
  char* file_name = (char*) (esp);

}