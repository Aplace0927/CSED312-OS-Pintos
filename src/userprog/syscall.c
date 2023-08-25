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
  lock_init(&lock_file_io);
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
#ifdef USERPROG_SYSCALL_DEBUG
    printf("[*] Syscall ID #%d (%p): ", syscall_id, syscall_function[syscall_id]);
#endif
    syscall_function[syscall_id](f->esp, f);
  }
  else
  {
#ifdef USERPROG_SYSCALL_DEBUG
    printf("[!] Syscall ID #%d [UNKNOWN]\n", syscall_id);
#endif
    syscall_handle_exit(NULL, NULL);
  }
}

void
validate_user_address (void* addr)
{
  if (addr == NULL || !is_user_vaddr(addr))
  {
    syscall_handle_exit(NULL, NULL);
  }
}


/* Syscall handler functions */

void
syscall_handle_halt (void* esp UNUSED, struct intr_frame* f UNUSED)
{
#ifdef USERPROG_SYSCALL_DEBUG
  printf("Halt() -> (void)\n");
#endif

  shutdown_power_off();
  NOT_REACHED();
}

void
syscall_handle_exit (void* esp, struct intr_frame* f UNUSED)
{
  struct thread* current_thread = thread_current();

  if (esp)
  {
    current_thread->exit_code = (int) *((addr_t*)esp + 1);  // Arguments
  }
  else
  {
    current_thread->exit_code = -1;
  }

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Exit([%d]) -> (void)\n", current_thread->exit_code);
#endif

  printf("%s: exit(%d)\n", current_thread->name, current_thread->exit_code);
  //palloc_free_multiple(current_thread->file_descriptor_table, FILE_DESCRIPTOR_PAGES);

  thread_exit();
}

void
syscall_handle_exec (void* esp, struct intr_frame* f)
{
  /* Arguments */
  char* exec_name = (char*) *((addr_t*) esp + 1);

  /* Validate referencing arguments */
  validate_user_address(exec_name);

  char* exec_copy = palloc_get_page(PAL_ZERO);
  
  if (exec_copy == NULL)
  {
    syscall_handle_exit(NULL, NULL);
  }

  strlcpy(exec_copy, exec_name, strlen(exec_name) + 1);
 
  f->eax = process_execute(exec_copy);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Exec([%p]) -> <%u>\n", exec_name, f->eax);
#endif
}

void
syscall_handle_wait (void* esp, struct intr_frame* f)
{
  /* Arguments */
  int wait_pid = (int) *((addr_t*) esp + 1);
  
  process_wait(wait_pid);
}

void
syscall_handle_create (void* esp, struct intr_frame* f)
{
  /* Arguments */
  char* create_file_name = (char*) *((addr_t*) esp + 1);
  unsigned create_init_size = (unsigned*) *((addr_t*) + 2);

  /* Validate referencing arguments */
  validate_user_address(create_file_name);

  f->eax = filesys_create(create_file_name, create_init_size);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Exec([%p] [%u]) -> <%u>\n", create_file_name, create_init_size, f->eax);
#endif
}

void
syscall_handle_remove (void* esp, struct intr_frame* f)
{
  /* Arguments */
  char* remove_file_name = (char*) *((addr_t*) esp + 1);

  /* Validate referencing arguments */
  validate_user_address(remove_file_name);

  f->eax = filesys_remove(remove_file_name);
}

void
syscall_handle_open (void* esp, struct intr_frame* f)
{
  /* Arguments */
  char* open_file_name = (char*) *((addr_t*) esp + 1);

  /* Validate referencing arguments */
  validate_user_address(open_file_name);

  struct file* open_file = filesys_open(open_file_name);
  struct thread* current_thread = thread_current();

  /* Add to file descriptor table */
  int open_descriptor = file_add_descriptor_table(current_thread, open_file);
  if (open_descriptor == FILE_DESCRIPTOR_FAILED)
  {
    file_close(open_file);
  }

  f->eax = open_descriptor;
}

void
syscall_handle_filesize (void* esp, struct intr_frame* f)
{
  /* Arguments */
  int filesize_descriptor = *(int*) (esp);

  struct thread* current_thread = thread_current();
  struct file* filesize_file = file_find_descriptor_table(current_thread, filesize_descriptor);

  f->eax = file_length(filesize_file);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Filesize([%d]) -> <%u>\n", filesize_descriptor, f->eax);
#endif
}

void
syscall_handle_read (void* esp, struct intr_frame* f)
{
  /* Arguments */
  int read_descriptor = (int) *((addr_t*) esp + 1);
  void* read_buffer = (void*) *((addr_t*) esp + 2);
  unsigned read_size = (unsigned) *((addr_t*) esp + 3);

  /* Validate referencing arguments */
  validate_user_address(read_buffer);

  struct thread* current_thread = thread_current();

  /* Cannot read from preserved unavailable streams: STDOUT, (STDERR)*/
#ifdef FILE_DESCRIPTOR_STDERR
  if (read_descriptor == FILE_DESCRIPTOR_STDOUT || 
      read_descriptor == FILE_DESCRIPTOR_STDERR ||
      read_descriptor > FILE_DESCRIPTOR_LIMIT   ||
      current_thread->file_descriptor_table[read_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    return;
  }
#else
  if (read_descriptor == FILE_DESCRIPTOR_STDOUT ||
      read_descriptor > FILE_DESCRIPTOR_LIMIT   ||
      current_thread->file_descriptor_table[read_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    return;
  }
#endif

  lock_acquire(&lock_file_io);  // Prevent race condition during read

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
    return;
  }
  else
  {
    f->eax = file_read(current_thread->file_descriptor_table[read_descriptor], read_buffer, read_size);
  }

  lock_release(&lock_file_io);  // Release lock after read

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Read([%d] [%p] [%u]) -> <%u>\n", read_descriptor, read_buffer, read_size, f->eax);
#endif
}

void
syscall_handle_write (void* esp, struct intr_frame* f)
{
  /* Arguments */
  int write_descriptor = (int) *((addr_t*) esp + 1);
  void* write_buffer = (void*) *((addr_t*) esp + 2);
  unsigned write_size = (unsigned) *((addr_t*) esp + 3);

  /* Validate referencing arguments */
  validate_user_address(write_buffer);

  struct thread* current_thread = thread_current();

  /* Cannot write to preserved unavailable streams: STDIN, (STDERR)*/
#ifdef FILE_DESCRIPTOR_STDERR
  if (write_descriptor == FILE_DESCRIPTOR_STDIN   ||
      write_descriptor == FILE_DESCRIPTOR_STDERR  ||
      write_descriptor > FILE_DESCRIPTOR_LIMIT    ||
      current_thread->file_descriptor_table[write_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    return;
  }
#else
  if (write_descriptor == FILE_DESCRIPTOR_STDIN   ||
      write_descriptor > FILE_DESCRIPTOR_LIMIT    ||
      current_thread->file_descriptor_table[write_descriptor] == NULL)
  {
    f->eax = (int32_t) -1;
    return;
  }
#endif

  lock_acquire(&lock_file_io);  // Prevent race condition during write

  if (write_descriptor == FILE_DESCRIPTOR_STDOUT)
  {
    putbuf((char*) write_buffer, write_size);
    f->eax = write_size;
  }
  else
  {
    f->eax = file_write(current_thread->file_descriptor_table[write_descriptor], write_buffer, write_size);
  }

  lock_release(&lock_file_io);  // Release lock after write

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Write([%d] [%p] [%u]) -> <%u>\n", write_descriptor, write_buffer, write_size, f->eax);
#endif
}

void
syscall_handle_seek (void* esp, struct intr_frame* f UNUSED)
{
  /* Arguments */
  int seek_descriptor = (int) *((addr_t*) esp + 1);
  unsigned seek_position = (unsigned) *((addr_t*) esp + 2);

  struct thread* current_thread = thread_current();
  struct file* seek_file = file_find_descriptor_table(current_thread, seek_descriptor);
  
  if (seek_file == NULL)
  {
    return;
  }

  validate_user_address(seek_file);
  file_seek(seek_file, seek_position);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Seek([%d] [%u])\n", seek_descriptor, seek_position);
#endif
}

void
syscall_handle_tell (void* esp, struct intr_frame* f)
{
  /* Arguments */
  int tell_descriptor = (int) *((addr_t*) esp + 1);

  struct thread* current_thread = thread_current();
  struct file* tell_file = file_find_descriptor_table(current_thread, tell_descriptor);

  if(tell_file == NULL)
  {
    return;
  }

  validate_user_address(tell_file);
  f->eax = (unsigned) file_tell(tell_file);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Tell([%d]) -> <%u>\n", tell_descriptor, f->eax);
#endif

  /*
    Something weird:
      in file_tell(): off_t is defined as int32_t
      but tell() in /lib/user/syscall.h: returns unsigned
  */
}

void
syscall_handle_close (void* esp, struct intr_frame* f UNUSED)
{
  /* Arguments */
  int close_descriptor = (int) *((addr_t*) esp + 1);

  struct thread* current_thread = thread_current();
  file_delete_descriptor_table(current_thread, close_descriptor);

#ifdef USERPROG_SYSCALL_DEBUG
  printf("Close([%d])\n", close_descriptor);
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
#ifndef FILE_DESCRIPTOR_STDERR
  if (descriptor <= FILE_DESCRIPTOR_STDOUT || descriptor > thrd->file_descriptor_index)
  {
    return NULL;
  }
#else
  if (descriptor <= FILE_DESCRIPTOR_STDERR || descriptor > thrd->file_descriptor_index)
  {
    return NULL;
  }
#endif

#ifdef USERPROG_SYSCALL_DEBUG
  printf("FD #%03d : {%p}\n", descriptor, thrd->file_descriptor_table[descriptor]);
#endif

  return thrd->file_descriptor_table[descriptor];
}

int
file_add_descriptor_table (struct thread* thrd, struct file* add_file)
{
  while(thrd->file_descriptor_index < FILE_DESCRIPTOR_LIMIT && thrd->file_descriptor_table[(thrd->file_descriptor_index)++] != NULL);

  if (thrd->file_descriptor_index < FILE_DESCRIPTOR_LIMIT)
  {
    thrd->file_descriptor_table[thrd->file_descriptor_index] = add_file;

#ifdef USERPROG_SYSCALL_DEBUG
    printf("FD #%03d : {%p}\n", thrd->file_descriptor_index, thrd->file_descriptor_table[thrd->file_descriptor_index]);
#endif

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
  printf("FD #%03d : {%p}\n", descriptor, thrd->file_descriptor_table[descriptor]);
#endif
}