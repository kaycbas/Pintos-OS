#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define BOTTOM_VADDR ((void *) 0x08048000)


static void syscall_handler (struct intr_frame *);
//helper fn to parse out the argument for the corresponding syscall
void get_arg (struct intr_frame *, int *, int);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&syscall_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("check - f->esp = %p\n\n", f->esp);

  int args[3];

  //validate pointer
  if (!(is_user_vaddr((const void*) f->esp) == true && (const void*) f->esp > BOTTOM_VADDR)) {
    exit(-1);
  }
  
  if (f->esp == 0x20101234) {
    exit(-1);
  }
  


  // TODO switch on all 13 cases
  // initially switch on SYS_EXIT, WRITE, and WAIT

  //printf("f->esp: %d\n\n", *((int *) f->esp));    
  switch (*((int *) f->esp)) {


  	case SYS_EXIT: {

      get_arg(f, &args[0], 1);
      //printf("status:::::: %d\n", args[0]);
  		exit(args[0]);
		//break;
		// exit(0);
		 break;
  	}
  	case SYS_WRITE: {
      
      get_arg(f, &args[0], 3);
      //check if the buffer is valid by checking each ptr in the buff
 	    buffer_check((void *) args[1], (unsigned) args[2]);
      args[1] = ptr_to_kernel_mode((const void *) args[1]);
      f->eax = write(args[0], (const void *) args[1], (unsigned) args[2]);
      break;
  	}
  	case SYS_WAIT: {
  		get_arg(f, &args[0], 1);
  		f->eax = wait(args[0]);
  		break;
  	}
  	case SYS_HALT: {
  		halt();
  		break;
  	}
  	case SYS_EXEC: {
      get_arg(f, &args[0], 1);
      args[0] = ptr_to_kernel_mode((const void *) args[0]);
      f->eax = exec((const void *) args[0]);
      break;
  	}
  	case SYS_CREATE: {
      get_arg(f, &args[0], 2);
      args[0] = ptr_to_kernel_mode((const void *) args[0]);
      f->eax = create((const char *) args[0], (unsigned) args[1]);
      break;

  	}
  	case SYS_REMOVE: {
      get_arg(f, &args[0], 1);
      args[0] = ptr_to_kernel_mode((const void *) args[0]);
      f->eax = remove((const char *) args[0]);
      break;
  	} 
  	case SYS_OPEN: {
  		get_arg(f, &args[0], 1);
  		args[0] = ptr_to_kernel_mode((const void *) args[0]);
  		f->eax = open((const char *) args[0]);
  		break; 
  	}
  	case SYS_FILESIZE: {
  		get_arg(f, &args[0], 1);
		f->eax = filesize(args[0]);
		break;
  	}
  	case SYS_READ: {
  		get_arg(f, &args[0], 3);

  		//check if the buffer is valid by checking each ptr in the buff
  		buffer_check((void *) args[1], (unsigned) args[2]);

  		args[1] = ptr_to_kernel_mode((const void *) args[1]);
  		f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
  		break;
  	}
  	case SYS_SEEK: {
      get_arg(f, &args[0], 2);
      seek(args[0], (unsigned) args[1]);
      break;

  	}
  	case SYS_TELL: {
      
      get_arg(f, &args[0], 1);
      f->eax = tell(args[0]);
      break;
      
  	}
  	case SYS_CLOSE: {
  		get_arg(f, &args[0], 1);
		  close(args[0]);
		  break;
  	}
  }


  //printf ("system call!\n");
}

//TODO
 /*
 exec-missing: exit status 4 instead of -1
 
 wait-killed: Kernel panic 
 
 All 3 rox: failed
 
 multi-oom: crashed child should return -1
 
 syn-read: wait for child 3 of 10 returned -1 (expected 2): FAILED
 
 syn-write: run: ((null)) open "stuff": FAILED
 (syn-write) wait for child 1 of 10 returned 1 (expected 0): FAILED
 
 */


int write(int fd, const void* buffer, unsigned size) {
  //printf("write checkpoint\n");
  

  //1. Check the validity of the pointers provided

  //2. Write bytes from buffer to open file fd
  // if fd=1, we're writing to console
  // in this case we should write the whole buffer to console with one putbuf() call
  // TODO write for other fd values


	lock_acquire(&syscall_lock);

	if (fd==1) {
	  putbuf(buffer, size);
	  lock_release(&syscall_lock);
	  return size;
	} 


    if(!list_empty(&thread_current()->file_list)) {
      struct list_elem* iter = NULL;
      for (iter = list_begin(&thread_current()->file_list); iter != list_end(&thread_current()->file_list);
          iter = list_next(iter)) 
      {
          struct process_file* pf = list_entry(iter, struct process_file, elem);
          if (pf->fd == fd) {
            struct file* f = pf->file;
            int retVal = file_write (f, buffer, size); 
            lock_release(&syscall_lock);          
            return retVal;
          }
      }
    }

    //3. Return num bytes written
    lock_release(&syscall_lock);          
    return -1;
}


//Terminates the current user program, returning status to the kernel. If the process’s parent
//waits for it (see below), this is the status that will be returned. Conventionally, a status of 0
//indicates success and nonzero values indicate errors.
void exit (int status){
  //printf("status:::::: %d\n", status);

  printf ("%s: exit(%d)\n", thread_current()->name, status);
  // struct thread *cur = thread_current();
  // if (thread_alive(cur->tid)) {
  //   cur->cp->exit = true;
  //   cur->cp->status = status;
  // }
  // cur->status = status;
  struct thread *cur = thread_current();
  struct thread *par = thread_current()->parent_thread;

  if (thread_alive(cur->tid)) {
    if (par != NULL) {

      for (struct list_elem *e = list_begin (&par->child_obituaries); e != list_end (&par->child_obituaries); e = list_next (e)) {
        struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
        if (co->pid == cur->tid) {
          co->exit_status = status;
          //co->exited = true;
          //sema_up(&co->process_wait_sema);
        }
      }

    } 
  }


  thread_exit();
}

/*
Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h). This
should be seldom used, because you lose some information about possible deadlock situa-
tions, etc.
*/
void halt(void) {
	shutdown_power_off();
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and
returns the new process’s program ID (pid). Must return pid -1, which otherwise should
not be a valid pid, if the program cannot load or run for any reason. Thus, the parent
process cannot return from the exec until it knows whether the child process successfully
loaded its executable. You must use appropriate synchronization to ensure this.
*/
pid_t exec(const char* cmd_line) { //actually returns a pid_t, but getting error saying pid_t undefined
   // TODO You have some right violation error, which might be caused by parsing filename. 
	//Did you make a copy of filename in your syscall_exec before you pass it to process_execute()?

	const char* copy_of_cmd_line = cmd_line; //Needed according to piazza post
   pid_t pid = process_execute(cmd_line);

   if (pid == -1) {
    return -1;
   }
   //printf("exec pid: %d\n\n", pid);
   return pid;
}

/*
Waits for a child process pid and retrieves the child’s exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit.
If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception),
wait(pid) must return -1. It is perfectly legal for a parent process to wait for child pro-
cesses that have already terminated by the time the parent calls wait, but the kernel must
still allow the parent to retrieve its child’s exit status, or learn that the child was terminated
by the kernel.
wait must fail and return -1 immediately if any of the following conditions is true:
• pid does not refer to a direct child of the calling process. pid is a direct child of the
calling process if and only if the calling process received pid as a return value from a
successful call to exec. Note that children are not inherited: if A spawns child B and B
spawns child process C, then A cannot wait for C, even if B is dead. A call to wait(C) by
process A must fail. Similarly, orphaned processes are not assigned to a new parent if
their parent process exits before they do.
• The process that calls wait has already called wait on pid. That is, a process may wait
for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit
without having waited for some or all of their children. Your design should consider all the
ways in which waits can occur. All of a process’s resources, including its struct thread, must
be freed whether its parent ever waits for it or not, and regardless of whether the child exits
before or after its parent.
You must ensure that Pintos does not terminate until the initial process exits. The sup-
plied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from
main() (in threads/init.c). We suggest that you implement process_wait() according
to the comment at the top of the function and then implement the wait system call in terms
of process_wait().
*/
int wait(pid_t pid) { //actually takes a pid_t as a parameter, but gives error saying pid_t undefined
  
  int exit_status = process_wait(pid);

  return exit_status;
}

/*
Creates a new file called file initially initial_size bytes in size. Returns true if successful,
false otherwise. Creating a new file does not open it: opening the new file is a separate
operation which would require a open system call.
*/
bool create (const char* file, unsigned initial_size) {
  lock_acquire(&syscall_lock);
  bool status = filesys_create(file, initial_size);
  lock_release(&syscall_lock);
  return status;
}

/*
Deletes the file called file. Returns true if successful, false otherwise. A file may be
removed regardless of whether it is open or closed, and removing an open file does not close
it. See Removing an Open File, for details.
*/
bool remove(const char* file) {
  lock_acquire(&syscall_lock);
  bool remove_file_ok = filesys_remove(file);
  lock_release(&syscall_lock);          
  return remove_file_ok;
}

/*
Opens the file called file. Returns a nonnegative integer handle called a "file descriptor"
(fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is
standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never
return either of these file descriptors, which are valid as system call arguments only as ex-
plicitly described below.
Each process has an independent set of file descriptors. File descriptors are not inherited
by child processes.
When a single file is opened more than once, whether by a single process or different pro-
cesses, each open returns a new file descriptor. Different file descriptors for a single file are
closed independently in separate calls to close and they do not share a file position.
*/
int open(const char* file) {
	
    lock_acquire(&syscall_lock);

    struct file *fo = filesys_open(file);
    if (fo == NULL) {
    	lock_release(&syscall_lock);
    	return -1;
    }

    struct process_file *pf = malloc(sizeof(struct process_file));
    pf->file = fo;
    pf->fd = thread_current()->fd;
    thread_current()->fd++;
    list_push_back(&thread_current()->file_list, &pf->elem);
    int fp = pf->fd;

    lock_release(&syscall_lock);
    return fp;
}

/* Returns the size, in bytes, of the file open as fd. */
int filesize(int fd) {
  lock_acquire(&syscall_lock);
  struct file *fo = NULL;
  for (struct list_elem* e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)) {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->fd) {
	  fo = pf->file;
	}
  }

  if (!fo) {
    lock_release(&syscall_lock);
    return -1;
  }
  int filesize = file_length(fo);
  lock_release(&syscall_lock);  
  return filesize;
}


/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of
file). Fd 0 reads from the keyboard using input_getc().
*/
int read(int fd, void* buffer, unsigned size) {
  lock_acquire(&syscall_lock);

  if (fd == STDIN_FILENO) {
    uint8_t* buff = (uint8_t *) buffer;
    for (uint8_t i = 0; i < size; i++) {
	  buff[i] = input_getc();
	}
	  lock_release(&syscall_lock);
      return size;
  }


  struct file *fo = NULL;
  for (struct list_elem* e = list_begin (&thread_current()->file_list); e != list_end (&thread_current()->file_list); e = list_next (e)) {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->fd) {
      fo = pf->file;
    }
  }

  if (!fo) {
  	lock_release(&syscall_lock);          
    return -1;
  }
  int size_bytes = file_read(fo, buffer, size);
  lock_release(&syscall_lock);
  return size_bytes;
}

/* 
Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. (Thus, a position of 0 is the file’s start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating
end of file. A later write extends the file, filling any unwritten gap with zeros. (However,
in Pintos files have a fixed length until project 4 is complete, so writes past end of file will
return an error.) These semantics are implemented in the file system and do not require any
special effort in system call implementation.
*/
void seek(int fd, unsigned position) {
  lock_acquire(&syscall_lock);

  struct file *f = NULL;
  for (struct list_elem* e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
    struct process_file *pf = list_entry(e, struct process_file, elem);
    if (fd == pf->fd) {
      f = pf->file;
    }
  }

  if (f == NULL) {
    lock_release(&syscall_lock);
    return;
  }

  file_seek(f, position);
  lock_release(&syscall_lock);
}

/* Returns the position of the next byte to be read or written in open file fd, expressed in bytes
from the beginning of the file.
*/
unsigned tell(int fd) {
  lock_acquire(&syscall_lock);

  struct file *f = NULL;
  for (struct list_elem* e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
    struct process_file *pf = list_entry(e, struct process_file, elem);
    if (fd == pf->fd) {
      f = pf->file;
    }
  }

  if (f == NULL) {
    lock_release(&syscall_lock);
    return -1;
  }

  off_t result = file_tell(f);
  lock_release(&syscall_lock);
  return result;
}


/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
descriptors, as if by calling this function for each one
*/
void close(int fd) {
  lock_acquire(&syscall_lock);

  struct list_elem *next, *e = list_begin(&thread_current()->file_list);

  while (e != list_end (&thread_current()->file_list)) {
    next = list_next(e);
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->fd || fd == -1) {
  	  file_close(pf->file);
  	  list_remove(&pf->elem);
  	  free(pf);
  	  if (fd != -1) {
        lock_release(&syscall_lock);
  	    return;
  	  }
	}
    e = next;
  }

  lock_release(&syscall_lock);
  return;
}


int ptr_to_kernel_mode(const void* vaddr) {

  if (!is_user_vaddr(vaddr) || vaddr < ((void *) 0x08048000)) {
    exit(-1);
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr) {
    exit(-1);
  }
  return (int) ptr;
}

int buffer_check(const void* buffer_vaddr, unsigned size) {
  
  if (!is_user_vaddr(buffer_vaddr) ||  buffer_vaddr < ((void *) 0x08048000)) {
    exit(-1);
  }
  if (!is_user_vaddr(buffer_vaddr + size) ||  (buffer_vaddr + size) < ((void *) 0x08048000)) {
    exit(-1);
  }
  void *ptr = pagedir_get_page(thread_current()->pagedir, buffer_vaddr);
  if (!ptr) {
    exit(-1);
  }
  return (int) ptr;
}

//helper fn to parse out the argument for the corresponding syscall
void get_arg (struct intr_frame *f, int *args, int num_args) {
  int *ptr;
  for (int i = 0; i < num_args; i++) {
    ptr = (int *) f->esp + i + 1;
    
    if (is_user_vaddr((const void*) ptr) == false || (const void*) ptr < BOTTOM_VADDR) {
    	exit(-1);
    } 

    
    if (ptr == NULL) {
      exit(-1);
    }

    
    args[i] = *ptr;
    //printf("args[%d]: %d   ", i, args[i]);
  }
}
