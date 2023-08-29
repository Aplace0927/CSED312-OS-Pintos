#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>

#include "devices/shutdown.h"
#include "devices/kbd.h"
#include "devices/input.h"

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"

#include "userprog/syscall.h"
#include "userprog/process.h"

#include "filesys/file.h"
#include "filesys/filesys.h"

//#define USERPROG_SYSCALL_DEBUG

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock_files);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_id = (int) (*(addr_t*) (f->esp));
/**
 * Syscall handler functions.
 * 
 * Those functions are called by function pointer, with argument (void*, struct intr_frame*)
 *  - (void*) passes the stack pointer address, to get syscall argument.
 * 
 *  - (struct intr_frame*) passes the entire inturrupt frame pointer,
 *    to return result if necessary. (UNUSED suffix added if certain syscall is `void`)
 *    Might be leave as NULL for calling those syscall indirectly (e.g. exit(NULL, NULL))
*/
  void (*syscall_function[SYSCALL_COUNT]) (void*, struct intr_frame*) =
  {
    syscall_handle_halt,      // #00 void halt () NO_RETURN
    syscall_handle_exit,      // #01 void exit (int status) NO_RETURN
    syscall_handle_exec,      // #02 pid_t exec (const char* file)
    syscall_handle_wait,      // #03 int wait (pid_t pid)
    syscall_handle_create,    // #04 bool create (const char* file, unsigned initial_size)
    syscall_handle_remove,    // #05 bool remove (const char* file)
    syscall_handle_open,      // #06 int open (const char* file)
    syscall_handle_filesize,  // #07 int filesize (int fd)
    syscall_handle_read,      // #08 int read (int fd, void* buffer, unsigned size)
    syscall_handle_write,     // #09 int write (int fd, const void* buffer, unsigned size)
    syscall_handle_seek,      // #10 void seek (int fd, unsigned position)
    syscall_handle_tell,      // #11 unsigned tell (int fd)
    syscall_handle_close,     // #12 void close (int fd)

    syscall_handle_mmap,      // #13 mapid_t mmap (int fd, void *addr)
    syscall_handle_munmap,    // #14 void munmap (mapid_t mapid)

    syscall_handle_chdir,     // #15 bool chdir (const char* dir)
    syscall_handle_mkdir,     // #16 bool mkdir (const char* dir)
    syscall_handle_readdir,   // #17 bool readdir (int fd, char name[])
    syscall_handle_isdir,     // #18 bool isdir (int fd)
    syscall_handle_inumber,   // #19 int inumber (int fd)
  };

#ifdef USERPROG_SYSCALL_DEBUG
  char* syscall_function_names[SYSCALL_COUNT] = {
    "HALT",
    "EXIT",
    "EXEC",
    "WAIT",
    "CREATE",
    "REMOVE",
    "OPEN",
    "FILESIZE",
    "READ",
    "WRITE",
    "SEEK",
    "TELL",
    "CLOSE",

    "MMAP",
    "MUNMAP",

    "CHDIR",
    "MKDIR",
    "READDIR",
    "ISDIR",
    "INUMBER"
  };
#endif

  if (0 <= syscall_id && syscall_id < SYSCALL_COUNT)
  {
#ifdef USERPROG_SYSCALL_DEBUG
    printf("[ O ] Syscall ID %#04x (%s)\n", syscall_id, syscall_function_names[syscall_id]);
#endif
    syscall_function[syscall_id](f->esp, f);
  }
  else
  {
#ifdef USERPROG_SYSCALL_DEBUG
    printf("[ X ] Syscall ID %#04x (UNKNOWN)\n", syscall_id);
#endif
    syscall_handle_exit(NULL, NULL);
  }
}

void
validate_user_address (void* addr)
{
  if (addr == NULL || !is_user_vaddr(addr))
  {
#ifdef USERPROG_SYSCALL_DEBUG
    //printf("\t\t[ X ] Address validation FAILED with address %#p\n", addr);
#endif
    syscall_handle_exit(NULL, NULL);
  }
#ifdef USERPROG_SYSCALL_DEBUG
  //printf("\t\t[ V ] Address validation succeed with address %#p\n", addr);
#endif
}

void
validate_argument_address (void* esp, int argc)
{
  /* 0 for syscall ID addr, 1 ~ argc for syscall args. */
  for (int arg = 0; arg <= argc; arg++)
  {
    validate_user_address(((addr_t*) esp + argc));
  }
}

/* Syscall handler functions */

void
syscall_handle_halt (void* esp UNUSED, struct intr_frame* f UNUSED)
{
#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] HALT -------------\n");
  printf("\t[-->] - \n");
#endif

  shutdown_power_off();
  NOT_REACHED();
}

void
syscall_handle_exit (void* esp, struct intr_frame* f)
{
  /* Base case of exit: internally calls `syscall_handle_exit(NULL, NULL)`*/
  struct thread* current_thread = thread_current();
  if (esp == NULL && f == NULL)
  {
    current_thread->exit_code = -1;

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] EXIT -------------\n");
  printf("\t[-->] Exit Code   : %d\n", current_thread->exit_code);
#endif

    printf("%s: exit(%d)\n", current_thread->name, current_thread->exit_code);
    thread_exit();
  }

  /* Normal case */
  validate_argument_address(esp, 1);          // Validating

  int exit_code = (int) *((addr_t*) esp + 1); // Fetching

  current_thread->exit_code = exit_code;

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] EXIT -------------\n");
  printf("\t[-->] Exit Code   : %d\n", f->eax);
#endif

  printf("%s: exit(%d)\n", current_thread->name, current_thread->exit_code);

  thread_exit();
}

void
syscall_handle_exec (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);              // Validating

  char* exec_name = (char*) *((addr_t*) esp + 1); // Fetching

  validate_user_address(exec_name);               // Validating ref-args

  char* exec_copy = palloc_get_page(PAL_ZERO);
  
  if (exec_copy == NULL)
  {
    syscall_handle_exit(NULL, NULL);
  }

  strlcpy(exec_copy, exec_name, strlen(exec_name) + 1);
 
  f->eax = process_execute(exec_copy);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] EXEC ------------\n");
  printf("\t[<-0] Exec Name   : %p (%s)\n", exec_copy, exec_copy);
  printf("\t[-->] Exec Result : %d\n", f->eax);
#endif

  palloc_free_page(exec_copy);
}

void
syscall_handle_wait (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);          // Validating

  int wait_pid = (int) *((addr_t*) esp + 1);  // Fetching
  
  f->eax = process_wait(wait_pid);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] WAIT ------------\n");
  printf("\t[<-0] Wait PID    : %d\n", wait_pid);
  printf("\t[-->] Wait Result : %d\n", f->eax);
#endif
}

void
syscall_handle_create (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 2);                                  // Validating

  const char* create_file_name = (const char*) *((addr_t*) esp + 1);  // Fetching
  unsigned create_init_size = (unsigned*) *((addr_t*) esp + 2);
  
  validate_user_address(create_file_name);                            // Validating ref-args

  f->eax = (uint32_t) filesys_create(create_file_name, create_init_size);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] CREATE ----------\n");
  printf("\t[<-0] File Name   : %p (%s)\n", create_file_name, create_file_name);
  printf("\t[<-1] Init Size   : %u\n", create_init_size);
  printf("\t[-->] Result      : %d\n", f->eax);
#endif
}

void
syscall_handle_remove (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);                                  // Validating

  const char* remove_file_name = (const char*) *((addr_t*) esp + 1);  // Fetching

  validate_user_address(remove_file_name);                            // Validating ref-args

  lock_acquire(&lock_files);  // File critical sections start

  f->eax = (uint32_t) (filesys_remove(remove_file_name));
  
  lock_release(&lock_files);  // File critical sections end

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] REMOVE ----------\n");
  printf("\t[<-0] File Name   : %p (%s)\n", remove_file_name, remove_file_name);
  printf("\t[-->] Result      : %d\n", f->eax);
#endif
}

void
syscall_handle_open (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);                    // Validating

  char* open_file_name = (char*) *((addr_t*) esp + 1);  // Fetching

  validate_user_address(open_file_name);                // Validating ref-args

  lock_acquire(&lock_files);

  struct file* open_file = filesys_open(open_file_name);
  struct thread* current_thread = thread_current();

  /* Add to file descriptor table */
  int open_descriptor = file_add_descriptor_table(current_thread, open_file);
  if (open_descriptor == FILE_DESCRIPTOR_FAILED)
  {
    file_close(open_file);
  }

  f->eax = open_descriptor;
  
  lock_release(&lock_files);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] OPEN ------------\n");
  printf("\t[<-0] File Name   : %p (%s)\n", open_file_name, open_file_name);
  printf("\t[-->] Descriptor  : %d\n", f->eax);
#endif
}

void
syscall_handle_filesize (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);                      // Validating

  int filesize_descriptor = *(int*) ((addr_t*) esp + 1);  // Fetching

  struct thread* current_thread = thread_current();
  struct file* filesize_file = file_find_descriptor_table(current_thread, filesize_descriptor);

  f->eax = file_length(filesize_file);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] FILESIZE --------\n");
  printf("\t[<-0] Descriptor  : %d\n", filesize_descriptor);
  printf("\t[-->] File size   : %u\n", f->eax);
#endif
}

void
syscall_handle_read (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 3);                    // Validating

  int read_descriptor = (int) *((addr_t*) esp + 1);     // Fetching
  void* read_buffer = (void*) *((addr_t*) esp + 2);
  unsigned read_size = (unsigned) *((addr_t*) esp + 3);

  validate_user_address(read_buffer);                   // Validating ref-args

  lock_acquire(&lock_files);                            // Critical section for file start

  struct thread* current_thread = thread_current();

  /* Cannot read from preserved unavailable streams: STDOUT, (STDERR)*/
#ifdef FILE_DESCRIPTOR_STDERR
  if (read_descriptor == FILE_DESCRIPTOR_STDOUT || 
      read_descriptor == FILE_DESCRIPTOR_STDERR ||
      read_descriptor > FILE_DESCRIPTOR_LIMIT   ||
      current_thread->file_descriptor_table[read_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    lock_release(&lock_files);
    return;
  }
#else
  if (read_descriptor == FILE_DESCRIPTOR_STDOUT ||
      read_descriptor > FILE_DESCRIPTOR_LIMIT   ||
      current_thread->file_descriptor_table[read_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    lock_release(&lock_files);
    return;
  }
#endif

  if (read_descriptor == FILE_DESCRIPTOR_STDIN)
  {
    size_t offset = 0;
    for (offset = 0; offset < read_size; offset++)
    {
      *((unsigned char*) read_buffer + offset) = input_getc();
      if (*((unsigned char*) read_buffer + offset) == '\0')
      {
        break;
      }
    }
    f->eax = offset;
    lock_release(&lock_files);
    return;
  }
  else
  {
    f->eax = file_read(current_thread->file_descriptor_table[read_descriptor], read_buffer, read_size);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] READ ------------\n");
  printf("\t[<-0] Descriptor  : %d\n", read_descriptor);
  printf("\t[<-1] Buffer      : %p\n", read_buffer);
  printf("\t[<-2] Size        : %u\n", read_size);
  printf("\t[-->] Read size   : %u\n", f->eax);
#endif
  }

  lock_release(&lock_files);  // Critical secion for file ends
}

void
syscall_handle_write (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 3);                      // Validating

  int write_descriptor = (int) *((addr_t*) esp + 1);      // Fetching
  void* write_buffer = (void*) *((addr_t*) esp + 2);
  unsigned write_size = (unsigned) *((addr_t*) esp + 3);

  validate_user_address(write_buffer);                    // Validating ref-args

  lock_acquire(&lock_files);  // Critical section for file start

  struct thread* current_thread = thread_current();

  /* Cannot write to preserved unavailable streams: STDIN, (STDERR)*/
#ifdef FILE_DESCRIPTOR_STDERR
  if (write_descriptor == FILE_DESCRIPTOR_STDIN   ||
      write_descriptor == FILE_DESCRIPTOR_STDERR  ||
      write_descriptor > FILE_DESCRIPTOR_LIMIT    ||
      current_thread->file_descriptor_table[write_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    lock_release(&lock_files);
    return;
  }
#else
  if (write_descriptor == FILE_DESCRIPTOR_STDIN   ||
      write_descriptor > FILE_DESCRIPTOR_LIMIT    ||
      current_thread->file_descriptor_table[write_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    lock_release(&lock_files);
    return;
  }
#endif

  if (write_descriptor == FILE_DESCRIPTOR_STDOUT)
  {
    putbuf((char*) write_buffer, write_size);
    f->eax = write_size;
  }
  else
  {
    f->eax = file_write(current_thread->file_descriptor_table[write_descriptor], write_buffer, write_size);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] WRITE -----------\n");
  printf("\t[<-0] Descriptor  : %d\n", write_descriptor);
  printf("\t[<-1] Buffer      : %p\n", write_buffer);
  printf("\t[<-2] Size        : %u\n", write_size);
  printf("\t[-->] Write size  : %u\n", f->eax);
#endif
  }

  lock_release(&lock_files);  // Critical section for file end
}

void
syscall_handle_seek (void* esp, struct intr_frame* f UNUSED)
{
  validate_argument_address(esp, 2);                        // Validating

  int seek_descriptor = (int) *((addr_t*) esp + 1);         // Fetching
  unsigned seek_position = (unsigned) *((addr_t*) esp + 2);

  struct thread* current_thread = thread_current();
  struct file* seek_file = file_find_descriptor_table(current_thread, seek_descriptor);
  
  lock_acquire(&lock_files);                                // Critical section for file start

#ifdef FILE_DESCRIPTOR_STDERR
  if (seek_descriptor == FILE_DESCRIPTOR_STDIN || seek_descriptor == FILE_DESCRIPTOR_STDOUT || seek_descriptor == FILE_DESCRIPTOR_STDERR)
  {
    syscall_handle_exit(NULL, NULL);  // `seek()` on invalid streams
  }
#else
  if (seek_descriptor == FILE_DESCRIPTOR_STDIN || seek_descriptor == FILE_DESCRIPTOR_STDOUT)
  {
    syscall_handle_exit(NULL, NULL);  // `seek()` on invalid streams
  }
#endif

  file_seek(seek_file, seek_position);

  lock_release(&lock_files);                                // Critical section for file end

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] SEEK ------------\n");
  printf("\t[<-0] Descriptor  : %d\n", seek_descriptor);
  printf("\t[<-1] Position    : %u\n", seek_position);
  printf("\t[-->] - \n");
#endif
}

void
syscall_handle_tell (void* esp, struct intr_frame* f)
{
  validate_argument_address(esp, 1);                  // Validating

  int tell_descriptor = (int) *((addr_t*) esp + 1);   // Fetching

  struct thread* current_thread = thread_current();
  struct file* tell_file = file_find_descriptor_table(current_thread, tell_descriptor);

  f->eax = (unsigned) file_tell(tell_file);           // No critical sections for `tell`.

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] TELL ------------\n");
  printf("\t[<-0] Descriptor  : %d\n", tell_descriptor);
  printf("\t[-->] Position    : %u\n", f->eax);
#endif
}

void
syscall_handle_close (void* esp, struct intr_frame* f UNUSED)
{
  validate_argument_address(esp, 1);                  // Validating

  int close_descriptor = (int) *((addr_t*) esp + 1);  // Fetching

  struct thread* current_thread = thread_current();

  file_close(current_thread->file_descriptor_table[close_descriptor]);  // Close!
  file_delete_descriptor_table(current_thread, close_descriptor);
  
#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t[***] CLOSE -----------\n");
  printf("\t[<-0] Descriptor  : %d\n", close_descriptor);
  printf("\t[-->] - \n");
#endif
}


void
syscall_handle_mmap (void* esp, struct intr_frame* f)
{
  return;
}

void
syscall_handle_munmap (void* esp, struct intr_frame* f UNUSED)
{
  return;
}


void
syscall_handle_chdir (void* esp, struct intr_frame* f)
{
  return;
}

void
syscall_handle_mkdir (void* esp, struct intr_frame* f)
{
  return;
}

void
syscall_handle_readdir (void* esp, struct intr_frame* f)
{
  return; 
}

void
syscall_handle_isdir (void* esp, struct intr_frame* f)
{
  return;
}

void
syscall_handle_inumber (void* esp, struct intr_frame* f)
{
  return;
}

struct file*
file_find_descriptor_table (struct thread* thrd, int descriptor)
{
#ifdef FILE_DESCRIPTOR_STDERR
  if (descriptor <= FILE_DESCRIPTOR_STDERR || descriptor > thrd->file_descriptor_index)
  {
    return NULL;
  }
#else
  if (descriptor <= FILE_DESCRIPTOR_STDOUT || descriptor > thrd->file_descriptor_index)
  {
    return NULL;
  }
#endif

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t\t[ F ] Descriptor  : #%3d\n", descriptor);
  printf("\t\t[ F ] Address     : %p\n", thrd->file_descriptor_table[descriptor]);
#endif

  return thrd->file_descriptor_table[descriptor];
}

int
file_add_descriptor_table (struct thread* thrd, struct file* add_file)
{
  while(thrd->file_descriptor_index < FILE_DESCRIPTOR_LIMIT && thrd->file_descriptor_table[(thrd->file_descriptor_index)++] != NULL);

  if (thrd->file_descriptor_index < FILE_DESCRIPTOR_LIMIT && add_file != NULL)
  {
    thrd->file_descriptor_table[thrd->file_descriptor_index] = add_file;

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t\t[ F ] Descriptor  : #%3d\n", thrd->file_descriptor_index);
  printf("\t\t[ F ] Address     : %p\n", thrd->file_descriptor_table[thrd->file_descriptor_index]);
#endif

    return thrd->file_descriptor_index;
  }
  else
  {
    return FILE_DESCRIPTOR_FAILED;
  }
}

void
file_delete_descriptor_table (struct thread* thrd, int descriptor)
{
#ifndef FILE_DESCRIPTOR_STDERR
  if (descriptor <= FILE_DESCRIPTOR_STDOUT || descriptor >= FILE_DESCRIPTOR_LIMIT)
  {
    return;
  }
#else
  if (descriptor <= FILE_DESCRIPTOR_STDERR || descriptor >= FILE_DESCRIPTOR_LIMIT)
  {
    return;
  }
#endif
  thrd->file_descriptor_table[descriptor] = NULL;

#ifdef USERPROG_SYSCALL_DEBUG
  printf("\t\t[ F ] Descriptor  : #%3d\n", thrd->file_descriptor_index);
  printf("\t\t[ F ] Address     : %p\n", thrd->file_descriptor_table[thrd->file_descriptor_index]);
#endif
}