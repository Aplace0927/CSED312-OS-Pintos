#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define USERPROG_CMD_MAX_LEN 0x100

#define ADDR_SIZE 4

#if ADDR_SIZE == 2
#define addr_t uint16_t
#elif ADDR_SIZE == 4
#define addr_t uint32_t
#elif ADDR_SIZE == 8
#define addr_t uint64_t
#endif

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void userprog_parse_filename(const char*, char*);
void userprog_intrframe_push_stack(const char*, void**);
#endif /* userprog/process.h */
