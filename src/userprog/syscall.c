#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "pagedir.h"

static void syscall_handler(struct intr_frame *);
bool check_address(int * , int);
static struct lock lock_f;
static int fd_counter = 2;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&lock_f);
}

static void
syscall_handler (struct intr_frame *f)
{
	 int *arg = f->esp;
	 switch (*arg)
	 {
		   case SYS_HALT:
			    syscall_halt();
			 break;

		   case SYS_EXIT:
			    if (check_address(arg,1))
				      syscall_exit(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_EXEC:
			    if (check_address(arg,1))
				      f->eax = syscall_exec(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_WAIT:
			    if (check_address(arg,1))
				      f->eax = syscall_wait(*(arg + 1));
		    	else
				      syscall_exit(-1);
			 break;

		   case SYS_CREATE:
			    if (check_address(arg,2))
				      f->eax = syscall_create(*(arg + 1), *(arg + 2));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_REMOVE:
			    if (check_address(arg,1))
				      f->eax = syscall_remove(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_OPEN:
			    if (check_address(arg,1))
				      f->eax = syscall_open(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_FILESIZE:
			    if (check_address(arg,1))
				      f->eax = syscall_filesize(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_READ:
			    if (check_address(arg,3))
				      f->eax = syscall_read(*(arg + 1), *(arg + 2), *(arg + 3));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_WRITE:
			    if (check_address(arg,3))
				      f->eax = syscall_write(*(arg + 1), *(arg + 2), *(arg + 3));
			    else
				      syscall_exit(-1);
			  break;

		   case SYS_SEEK:
			    if(check_address(arg,2))
				      syscall_seek(*(arg + 1), *(arg + 2));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_TELL:
			    if (check_address(arg,1))
				      f->eax = syscall_tell(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   case SYS_CLOSE:
			    if (check_address(arg,1))
				      syscall_close(*(arg + 1));
			    else
				      syscall_exit(-1);
			 break;

		   default:
			    syscall_exit(-1);
	 }
}

bool check_address(int * pargs, int num_args)
{
	int i = 1 ;

	for (i=1; i<= num_args; i++)
	{
		if (!is_user_vaddr(pargs+i)) {
			// Just another way to return false
			return 1 == 2;
		}
	}
	// And return true
	return 1 == 1;
}

void syscall_halt(void)
{
	shutdown_power_off();
}

void syscall_exit(int status)
{
	struct thread *t;

	t = thread_current();
	if (lock_held_by_current_thread(&lock_f))
  {
    lock_release(&lock_f);
  }

	t->return_status = status;
	printf("%s: exit(%d)\n", t->name, t->return_status);
	thread_exit();
}

pid_t syscall_exec(const char *executable)
{
	tid_t id;
	lock_acquire(&lock_f);
	id = process_execute(executable);
	lock_release(&lock_f);
	return id;
}

int syscall_wait(pid_t pid)
{
	return process_wait(pid);
}

bool syscall_create(const char *file, unsigned initial_size)
{
  bool status;
	if (file != NULL)
	{
		lock_acquire(&lock_f);
		status = filesys_create(file, initial_size);
		lock_release(&lock_f);
		return status;
	}
	syscall_exit(-1);
}

bool syscall_remove(const char *file)
{
  bool status;
	if (file != NULL)
	{
		lock_acquire(&lock_f);
		status = filesys_remove(file);
		lock_release(&lock_f);
    return status;
	}
  syscall_exit(-1);
}

int syscall_open(const char *file)
{
	if (file != NULL)
	{
    struct file *actual_file = NULL;
		struct file_info *file_desc = malloc(sizeof(struct file_info));

		lock_acquire(&lock_f);
		actual_file = filesys_open(file);
		lock_release(&lock_f);

		if (actual_file != NULL)
    {
      file_desc->s = actual_file;

      lock_acquire(&lock_f);
  		file_desc->fd = fd_counter;
      fd_counter++;
      lock_release(&lock_f);
  		list_push_back(&thread_current()->open_files, &file_desc->store_file);

  		return file_desc->fd;
    }
	}
	else
	{
		syscall_exit(-1);
	}
	return -1;
}

int syscall_filesize(int fd)
{
  int file_size = 0;
	struct file_info *f;
	struct list_elem *e;
	for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
	{
		f = list_entry(e, struct file_info, store_file);
		if (f->fd == fd) {
			lock_acquire(&lock_f);
			file_size = file_length(f->s);
			lock_release(&lock_f);
			return file_size;

		}
	}

	return -1;
}

int syscall_read(int fd, void *buffer, unsigned size)
{
	int size_read;
	unsigned int offset = 0;
	struct file_info *f;

	if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size))
		syscall_exit(-1);

  if (fd == 0)
  {
    for (offset = 0; offset < size; ++offset)
    {
      *(uint8_t *)(buffer + offset) = input_getc();
    }
		return size;
  }
  if (fd == 1)
  {
    return -1;
  }
  else
  {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
    {
      f = list_entry(e, struct file_info, store_file);
      if (f->fd == fd)
      {
        lock_acquire(&lock_f);
    		size_read = file_read(f->s, buffer, size);
    		lock_release(&lock_f);
    		return size_read;
      }
    }
		return -1;
  }
}

int syscall_write(int fd, const void *buffer, unsigned size)
{
	int size_written;
  struct file_info *f;

	if (!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size))
		syscall_exit(-1);
	if(fd == 0)
		return -1;
	if(fd == 1)
	{
		putbuf(buffer, size);
		return size;
  }
  else
  {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
    {
      f = list_entry(e, struct file_info, store_file);
      if (f->fd == fd)
      {
        lock_acquire(&lock_f);
        size_written = file_write(f->s, buffer, size);
    		lock_release(&lock_f);
    		return size_written;
      }
    }
		return -1;
  }
}

void syscall_seek(int fd, unsigned position)
{
	struct file_info *file_desc = NULL, *f;
	struct list_elem *e;
	for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
	{
		f = list_entry(e, struct file_info, store_file);
		if(f->fd == fd)
		{
			file_desc = f;
			break;
		}
	}

	if(file_desc != NULL)
	{
		lock_acquire(&lock_f);
		file_seek(file_desc->s, position);
		lock_release(&lock_f);
	}
	else
		syscall_exit(-1);
}

unsigned syscall_tell(int fd)
{
	unsigned pos = 0;
	struct file_info *f;
	struct list_elem *e;
	for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
	{
		f = list_entry(e, struct file_info, store_file);
		if(f->fd == fd)
		{
      lock_acquire(&lock_f);
  		pos = file_tell(f->s);
  		lock_release(&lock_f);
  		return pos;
		}
	}
	return -1;
}

void syscall_close(int fd)
{
	struct file_info *file_desc = NULL, *f;
	struct list_elem *e;
	for (e = list_begin(&thread_current()->open_files); e != list_end(&thread_current()->open_files); e = list_next(e))
	{
		f = list_entry(e, struct file_info, store_file);
		if(f->fd == fd)
		{
			file_desc = f;
			break;
		}
	}

	if(file_desc != NULL)
	{
		list_remove(&file_desc->store_file);
		lock_acquire(&lock_f);
		file_close(file_desc->s);
		lock_release(&lock_f);
		free(file_desc);
	}
	else
		syscall_exit(-1);
}
