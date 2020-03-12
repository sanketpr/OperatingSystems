#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"

void syscall_init(void);
void syscall_halt(void) NO_RETURN;
void syscall_exit(int) NO_RETURN;
pid_t syscall_exec(const char *);
int syscall_wait(pid_t);
bool syscall_create(const char *, unsigned );
bool syscall_remove(const char *);
int syscall_open(const char *);
int syscall_filesize(int);
int syscall_read(int, void *, unsigned);
int syscall_write(int, const void *, unsigned );
void syscall_seek(int, unsigned);
unsigned syscall_tell(int);
void syscall_close(int);

#endif /* userprog/syscall.h */
