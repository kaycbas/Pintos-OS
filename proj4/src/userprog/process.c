#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *fn_tkn_str;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);


  /* Make another copy of FILE_NAME for tokenizing.
     This is necessary because strtok_r doesn't accept const arguments 
     AND it alters the original string (so we can't use fn_copy) */
  fn_tkn_str = palloc_get_page (0);
  if (fn_tkn_str == NULL)
    return TID_ERROR;
  strlcpy (fn_tkn_str, file_name, PGSIZE);

  
  //get the first argument from file_name and assign value to exec_name
  char *save_ptr;
  char *exec_name = strtok_r(fn_tkn_str, " ", &save_ptr);

  /* Create a new thread to execute exec_name. */
  lock_acquire(&thread_current()->creation_lock);

  tid = thread_create (exec_name, PRI_DEFAULT, start_process, fn_copy);
  sema_down(&thread_current()->load_wait_sema);

  for (struct list_elem *e = list_begin (&thread_current()->child_obituaries); e != list_end (&thread_current()->child_obituaries); e = list_next (e)) {
      struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
      if (co->pid == tid) {
        if (co->exit_status == -1) {
          lock_release(&thread_current()->creation_lock);
          return -1;
        }
      }
    }
  lock_release(&thread_current()->creation_lock);


  // temp //
  //printf("tid: %d\n\n\n", tid);
  //process_wait(tid);

  //

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  
  //get the first argument from file_name and assign value to exec_name
  //char *save_ptr;
  //char *exec_name = strtok_r(file_name, " ", &save_ptr);

  //load needs access to the raw file name because it calls setup stack, which needs
  //access to all the arguments in the raw file name
  success = load (file_name, &if_.eip, &if_.esp);
  sema_up(&thread_current()->parent_thread->load_wait_sema);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {

    struct thread *cur = thread_current();
    struct thread *par = thread_current()->parent_thread;

    for (struct list_elem *e = list_begin (&par->child_obituaries); e != list_end (&par->child_obituaries); e = list_next (e)) {
      struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
      if (co->pid == cur->tid) {
        co->exit_status = -1;
      }
    }

    thread_exit ();

  }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  //TODO this is returning -1 when it should be returning 1 in syn-read & syn-write
  
  struct thread* cur = thread_current();
  //struct thread* chi = get_thread(child_tid);
  //printf("waiting....................\n\n\n");


  bool isChild = false;
  struct semaphore *child_sema = NULL;


  for (struct list_elem *e = list_begin (&cur->child_obituaries); e != list_end (&cur->child_obituaries); e = list_next (e)) {
    struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
    if (co->pid == child_tid) {
      isChild = true;
      child_sema = &co->process_wait_sema;
    }
  }

  if (isChild) {
  	sema_down(child_sema);
  } else {
  	return -1;
  }


  //timer_sleep(2000);
  int ex_status = 1;
  
  for (struct list_elem *e = list_begin (&cur->child_obituaries); e != list_end (&cur->child_obituaries); e = list_next (e)) {
    struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
    if (co->pid == child_tid) {
    	//printf("setting\n\n");
      ex_status = co->exit_status;
      if (co->exited) {
      	list_remove(&co->dead_child_elem);
      }
    }	
  }
  

  return ex_status;
}

/* Free the current processing's resources. */
void
process_exit (void)
{
  
  uint32_t *pd;
  struct thread *cur = thread_current();
  struct thread *par = thread_current()->parent_thread;
  //TODO - free resources
  lock_acquire(&syscall_lock);

  // empty file list

  // for (struct list_elem *e = list_begin (&cur->file_list); e != list_end (&cur->file_list); e = list_next (e)) {
  //     struct process_file *pf = list_entry (e, struct process_file, elem);  
  //     file_close(pf->file);
  //     list_remove(&pf->elem);
  //     free(pf);
  // }


if (thread_alive(cur->tid)) {
    if (par != NULL) {

      for (struct list_elem *e = list_begin (&par->child_obituaries); e != list_end (&par->child_obituaries); e = list_next (e)) {
        struct child_obituary *co = list_entry (e, struct child_obituary, dead_child_elem);
        if (co->pid == cur->tid) {
          co->exited = true;
          sema_up(&co->process_wait_sema);
        }
      }

    } 
  }



  if (cur->exec_file != NULL) {
    file_close(cur->exec_file);
  }


  lock_release(&syscall_lock);

  // empty child list
  // for (struct list_elem *el = list_begin (&cur->child_list); el != list_end (&cur->child_list); el = list_next (el)) {
  //     struct thread *cp = list_entry (el, struct thread, elem);  
  //     list_remove(&cp->elem);
  //     free(cp);
  // }

  // Set exit value to true in case killed by the kernel
  // if (thread_alive(cur->parent_thread) && cur->cp != NULL && cur->exec_file != NULL) {
  //   cur->cp->exit = true;
  // }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //copy of file name used for extracting executable
  //necessary because strtok_r alters original string
  char *fn_tkn_str = palloc_get_page (0);
  if (fn_tkn_str == NULL)
    return TID_ERROR;
  strlcpy (fn_tkn_str, file_name, PGSIZE);

  char *save_ptr;
  char *exec_name = strtok_r(fn_tkn_str, " ", &save_ptr);

  /* Open executable file. */
  lock_acquire(&syscall_lock);
  file = filesys_open (exec_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  t->exec_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //TODO change
  lock_release(&syscall_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      //uint8_t *kpage = frame_alloc (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          //free_frame(kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          //free_frame(kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

#define WORD_SIZE 4
#define DEFAULT_NUM_ARGS 2 //default to have a command and a parameter

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* file_name) 
{
	//printf("setting up stack\n");

  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  //kpage = frame_alloc(PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
        //free_frame(kpage);
    }

	//printf("checkpoint 1\n");

	//// New stuff ////

	//copy of file name used for extracting arguments
	//strtok_r doesn't accept const
	char *fn_tkn_str = palloc_get_page (0);
	if (fn_tkn_str == NULL)
		return TID_ERROR;
	strlcpy (fn_tkn_str, file_name, PGSIZE);

	//printf("checkpoint 2\n");

	char *tokens[30]; //array to store tokens and then iterate over backwards
	uint8_t max_tkns = sizeof(tokens)/sizeof(tokens[0]);	//max tokens that can be stored
	char *tkn_ptr; //used for iterating through file name string
	char *save_ptr; //keeps track of which token we're on in loop
	int argc = 0; //number of arguments
	

	tkn_ptr = strtok_r(fn_tkn_str, " ", &save_ptr);
	int i;

	//printf("checkpoint 4\n");
	// tokenize raw file name and store each token in array
	for (i=0; i<max_tkns && tkn_ptr != NULL; i++, (tkn_ptr = strtok_r(NULL, " ", &save_ptr))) {
		//printf("i=%d\n", i);
		tokens[i] = tkn_ptr;
		//printf("tokens[%d]: %s\n", i, tokens[i]);
	}

	//store num arguments
	argc = i;
	i--;

	char **argv = malloc(argc * sizeof(char *)); //a char array of the args data and the addresses of that data

	//printf("checkpoint 5\n");
	// iterate backward over token array and copy each one to the stack
	while (i>=0) {

		*esp -= sizeof(char);
		memset(*esp, '\0', sizeof(char));

		//printf("strlen: %d\n", strlen(tokens[i]));
		//printf("str: %s\n", tokens[i]);
		//printf("checkpoint 5.25\n");
		*esp -= strlen(tokens[i]);
		//printf("checkpoint 5.5\n");
		memcpy(*esp, tokens[i], sizeof(char) * strlen(tokens[i]));

		argv[i] = *esp;
		i--;
	}
	//printf("checkpoint 6\n");

	uint8_t word_align; //used to align the stack pointer to the WORD_SIZE

	//3. Write the necessary number of 0s to word-align to 4 bytes. A little modulus math and mem-
	//set will get the job done.
	word_align = (uint8_t) *esp % WORD_SIZE;
	*esp -= word_align;
	memset(*esp, 0, word_align);

	//4. Write the last argument, consisting of four bytes of 0’s.
	*esp -= WORD_SIZE;
	memset(*esp, 0, WORD_SIZE);
	argv[argc] = *esp;


	//5. Write the addresses pointing to each of the arguments. You’ll need to figure out how to
	//reference the addresses after writing all the arguments. These are char*s.
	//iterate backwards over argv and push data onto stack

	for (int i = (argc-1); i >= 0; i--) {
	  *esp -= sizeof(char *);
	  memcpy(*esp, &argv[i], sizeof(char *));
	}

	

	char *addr;
	//push argv, argc, return address onto stack
	//6. Write the address of argv[0]. This will be a char**.
	addr = *esp;
	*esp -= sizeof(char **);
	memcpy(*esp, &addr, sizeof(char **));
	//7. Write the number of arguments (argc). Make sure that this spans over 4 bytes.
	
	*esp -= 4;
	memset(*esp, argc, 1);
	
	//8. Write a NULL pointer as the return address. This will be a void*.
	*esp -= sizeof(void *);
	memcpy(*esp, &argv[argc+1], sizeof(void *));

	
	//free argv to avoid seg fault
	//free(argv);

	//hex_dump((uintptr_t)*esp, *esp, PHYS_BASE - *esp, true);

	return success;

}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
