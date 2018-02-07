#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define BLOCK_PTRS 12

#define INDIRECT_PTRS 128
#define MAX_BLOCKS 16522

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t blocks[BLOCK_PTRS];
    uint32_t index;
    uint32_t numAllocated;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[110];  //change if i change inode struct             /* Not used. */
    block_sector_t parent; // Block sector of the parent inode
    bool isdir;
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);;
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
  
    block_sector_t blocks[BLOCK_PTRS];
    uint32_t index;
    uint32_t numAllocated;

    off_t length;                       /* ADDED - length of file in bytes */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock lock;

    bool isdir; // indicates whether an inode is a directory
    block_sector_t parent; // Block sector of the parent inode

  };

struct indirect_block 
  {
    block_sector_t blocks[128];
    uint32_t index;
  };


int inode_dealloc_indirect(block_sector_t* indirect_ptr, size_t numBlocks);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
  ASSERT (inode != NULL);
  //printf("\n pos: %d \n", pos);
  //printf("\n inode length: %d \n", inode->length);
  if (pos < inode->length) {
    //printf ("\n pos: %d\n\n", pos);
    int blockNum = pos / BLOCK_SECTOR_SIZE;
    //printf ("\nblockNum: %d\n\n", blockNum);
    if (blockNum < 10) {
      //printf("sector in byte-to-sect: %d \n", inode->blocks[blockNum]);
      return inode->blocks[blockNum];
    } else if (blockNum < (10 + 128)) {
      //printf ("\nblockNum: %d\n\n", blockNum);
      //printf ("\n check \n\n");
      blockNum -= 10;
      struct indirect_block ib;
      block_read(fs_device, inode->blocks[10], &ib);
      return ib.blocks[blockNum];
    } else {
     
      blockNum -= 138;
      int dibIndex = blockNum / INDIRECT_PTRS;
      blockNum = blockNum % INDIRECT_PTRS;

      struct indirect_block dib;
      struct indirect_block ib;
      block_read(fs_device, inode->blocks[11], &dib);
      block_read(fs_device, dib.blocks[dibIndex], &ib);
      return ib.blocks[blockNum];

    }
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

bool inode_alloc(struct inode_disk* disk_inode);

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
   // TODO check if it's a dir (add parameter)
bool
inode_create (block_sector_t sector, off_t length, bool isdir)
{

  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  //FOR DEBUGGING
  //printf("\n*******\n\n size: %i\n\n\n", sizeof *disk_inode);
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->index = 0;
      disk_inode->numAllocated = 0;

      disk_inode->parent = ROOT_DIR_SECTOR;
      disk_inode->isdir = isdir;

      //printf("\nallocating disk_inode at sector %d \n", sector);
      if (inode_alloc(disk_inode)) {
        block_write (fs_device, sector, disk_inode);
        success = true; 
      }

      free (disk_inode);
    }
  return success;
}

int inode_alloc_indirect (block_sector_t* indirect_ptr, size_t numBlocks);

//allocates an inode
bool inode_alloc(struct inode_disk* disk_inode) {

  size_t numSectors = bytes_to_sectors (disk_inode->length);

  if (numSectors > MAX_BLOCKS) {
    numSectors = MAX_BLOCKS;
  } 

  size_t numDirectSectors;
  size_t numIndirectSectors;
  size_t numDoubleIndirectSectors;

  if (numSectors > 138) {
    numDirectSectors = 10;
    numIndirectSectors = 128;
    numDoubleIndirectSectors = numSectors - 138;
  } else if ((numSectors > 10) && (numSectors <= 138)) {
    numDirectSectors = 10;
    numIndirectSectors = numSectors - 10;
    numDoubleIndirectSectors = 0;
  } else {
    numDirectSectors = numSectors;
    numIndirectSectors = 0;
    numDoubleIndirectSectors = 0;
  }

  //printf("\nallocating %d direct \n", numDirectSectors);
  //printf("\nof length: %d\n", disk_inode->length);
  //printf("\nso %d total sectors \n", numSectors);
  //printf("\nmeaning %d direct blocks at locations...\n", numDirectSectors);
  
  //printf("\nallocating %d doub direct \n", numDirectSectors);

  char zeroBuffer[BLOCK_SECTOR_SIZE];


  //allocate direct blocks
  while (numDirectSectors>0 && disk_inode->index<10) {
    free_map_allocate(1, &disk_inode->blocks[disk_inode->index]);
    //printf("\n %d \n", disk_inode->blocks[disk_inode->index]);
    block_write(fs_device, disk_inode->blocks[disk_inode->index], &zeroBuffer);
    disk_inode->index++;
    numDirectSectors--;
    disk_inode->numAllocated++;
  }

  //printf("\nand %d blocks in the indirect \n", numIndirectSectors);
  //printf("\nat locations... \n");
  


  if (numIndirectSectors>0 && disk_inode->index==10) {
    disk_inode->numAllocated += inode_alloc_indirect(&disk_inode->blocks[disk_inode->index], numIndirectSectors);
    if(disk_inode->numAllocated == 138) {
      disk_inode->index++;
    }
  }

  //printf("\nand %d blocks in the double indirect \n", numDoubleIndirectSectors);

  if (numDoubleIndirectSectors>0 && disk_inode->index==11) {
    struct indirect_block dib;
    free_map_allocate(1, &disk_inode->blocks[11]);

    int i = 0;
    int numAllocated = 0;

    while(numDoubleIndirectSectors>0 && i<INDIRECT_PTRS) {
      numAllocated = 0;
      numAllocated = inode_alloc_indirect(&dib.blocks[i], numDoubleIndirectSectors);
      numDoubleIndirectSectors -= numAllocated;
      i++;
    }
    dib.index = i;
    block_write(fs_device, disk_inode->blocks[11], &dib);
  }
  
  return true;

}


//alloc indirect inode
int inode_alloc_indirect (block_sector_t* indirect_ptr, size_t numBlocks) {

  struct indirect_block ib;
  ib.index = 0;
  char zeroBuffer[BLOCK_SECTOR_SIZE];

  free_map_allocate(1, indirect_ptr);
  numBlocks = numBlocks > INDIRECT_PTRS ? INDIRECT_PTRS : numBlocks;
  
  int i;
  for (i=0; i<numBlocks; i++) {
    free_map_allocate(1, &ib.blocks[i]);
    //printf("\n %d  \n", ib.blocks[i]);
  
    block_write(fs_device, ib.blocks[i], zeroBuffer);
    ib.index++;
  }

  block_write(fs_device, *indirect_ptr, &ib);
  return i;
}

int inode_extend_indirect(block_sector_t* indirect_ptr, size_t extendSectors) {
  struct indirect_block ib;
  char zeroBuffer[BLOCK_SECTOR_SIZE];

  block_read(fs_device, *indirect_ptr, &ib);
  int num = 0;
  while (ib.index < 128 && extendSectors > 0) {
    free_map_allocate(1, &ib.blocks[ib.index]);
    //printf("\n %d  \n", ib.blocks[i]);
  
    block_write(fs_device, ib.blocks[ib.index], &zeroBuffer);
    ib.index++;
    extendSectors--;
    num++;
  }

  block_write(fs_device,*indirect_ptr, &ib);
  return num;
}

void inode_dealloc(struct inode* inode) {

  size_t numSectors = bytes_to_sectors (inode->length);

  size_t numDirectSectors;
  size_t numIndirectSectors;
  size_t numDoubleIndirectSectors;


  if (numSectors > 138) {
    numDirectSectors = 10;
    numIndirectSectors = 128;
    numDoubleIndirectSectors = numSectors - 138;
  } else if ((numSectors > 10) && (numSectors <= 138)) {
    numDirectSectors = 10;
    numIndirectSectors = numSectors - 10;
    numDoubleIndirectSectors = 0;
  } else {
    numDirectSectors = numSectors;
    numIndirectSectors = 0;
    numDoubleIndirectSectors = 0;
  }


  //dealloc direct blocks
  for (int i=0; i<numDirectSectors; i++) {
    free_map_release(inode->blocks[i], 1);
  }

  //dealloc indirect blocks
  if (numIndirectSectors>0) {
    inode_dealloc_indirect(&inode->blocks[10], numIndirectSectors);
  }

  if (numDoubleIndirectSectors>0) {
    struct indirect_block dib;
    block_read(fs_device, inode->blocks[11], &dib);

    int i = 0;
    int numDeallocated = 0;

    while(numDoubleIndirectSectors>0 && i<INDIRECT_PTRS) {
      numDeallocated = 0;
      numDeallocated = inode_dealloc_indirect(&dib.blocks[i], numDoubleIndirectSectors);
      numDoubleIndirectSectors -= numDeallocated;
      i++;
    }
  }
}

int inode_dealloc_indirect(block_sector_t* indirect_ptr, size_t numBlocks) {

  numBlocks = numBlocks > INDIRECT_PTRS ? INDIRECT_PTRS : numBlocks;

  struct indirect_block ib;
  block_read(fs_device, *indirect_ptr, &ib);

  for (int i = 0; i<numBlocks; i++) {
    free_map_release(ib.blocks[i], 1);
  }

  free_map_release(*indirect_ptr, 1);
  return numBlocks;
}

//extends INODE to POS bytes
bool inode_extend(struct inode *inode, off_t pos) {
  if (pos < inode->length) {
    return false;
  }
  size_t extendBytes = pos - inode->length;
  size_t extendSectors = bytes_to_sectors(extendBytes);
  inode->length = pos<(MAX_BLOCKS*512) ? pos : (MAX_BLOCKS*512);


  char zeroBuffer[BLOCK_SECTOR_SIZE];

  //allocate direct blocks
  while (inode->index < 10 && extendSectors > 0) {
    free_map_allocate(1, &inode->blocks[inode->index]);
    //printf("\n %d \n", disk_inode->blocks[disk_inode->index]);
    block_write(fs_device, inode->blocks[inode->index], &zeroBuffer);
    inode->index++;
    extendSectors--;
    inode->numAllocated++;
  }

  if (inode->index == 10 && extendSectors > 0) {
    if (inode->numAllocated == 10) {
      inode->numAllocated += inode_alloc_indirect(&inode->blocks[10], extendSectors);
      if(inode->numAllocated == 138) {
        inode->index++;
      }
    } else {
      inode->numAllocated += inode_extend_indirect(&inode->blocks[10], extendSectors);
      if(inode->numAllocated == 138) {
        inode->index++;
      }
    }
  }


  if (inode->index == 11 && extendSectors > 0) {
    struct indirect_block dib;
    if(inode->numAllocated == 138) {
      free_map_allocate(1, &inode->blocks[11]);
      int i = 0;
      while(extendSectors>0 && i<128) {
        int numAllocd = 0;
        numAllocd = inode_alloc_indirect(&dib.blocks[i], extendSectors);
        extendSectors -= numAllocd;
        inode->numAllocated += numAllocd;
        i++;
      }
      dib.index = i;
    } else {
      block_read(fs_device, inode->blocks[11], &dib);
      while(extendSectors>0 && dib.index<128) {
        int numAllocd = 0;
        numAllocd += inode_alloc_indirect(&dib.blocks[dib.index], extendSectors);
        extendSectors -= numAllocd;
        inode->numAllocated += numAllocd;
        dib.index++;
      }
    }
    block_write(fs_device, inode->blocks[11], &dib);
  }

  return true;  
}


/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;


  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  struct inode_disk disk_inode;
  block_read (fs_device, inode->sector, &disk_inode);
  inode->length = disk_inode.length;
  inode->parent = disk_inode.parent;
  inode->isdir = disk_inode.isdir;
  inode->index = disk_inode.index;
  //lock_init(&inode->lock);
  inode->numAllocated = disk_inode.numAllocated;
  memcpy(&inode->blocks, &disk_inode.blocks, BLOCK_PTRS * sizeof(block_sector_t));

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  //printf("\n blocknum \n");
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
    
      /* Deallocate blocks if removed. */
      if (inode->removed) {
          free_map_release (inode->sector, 1);
          inode_dealloc(inode);
      } else {
        struct inode_disk disk_inode;
        disk_inode.index = inode->index;
        disk_inode.length = inode->length;
        disk_inode.magic = INODE_MAGIC;
        disk_inode.numAllocated = inode->numAllocated;
        //disk_inode.blocks = inode->blocks;

        disk_inode.parent = inode->parent;
        disk_inode.isdir = inode->isdir;
        memcpy(&disk_inode.blocks, &inode->blocks, BLOCK_PTRS * sizeof(block_sector_t));
        block_write(fs_device, inode->sector, &disk_inode);
      }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  //printf("\n reading\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  if (inode->length < offset + size) {
    return 0;
  }

  while (size > 0) 
    {
      //printf("\n sector: %d \n", inode->sector);
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          //printf("\n sector: %d \n", sector_idx);
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  //printf("\n writing\n");
  //printf("\n size: %d \n", size);

  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (inode->length < offset + size) {
    //printf("\ntrying to extend\n");
    //lock_acquire(&inode->lock);
    inode_extend(inode, offset + size);
    //lock_release(&inode->lock);
    //printf("\nshould've extended\n");
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      //printf("\n write to sector: %d \n", sector_idx);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  //printf("\n length: %d \n", inode->len);
  return inode->length;
}

block_sector_t inode_get_parent (const struct inode* inode) {
  return inode->parent;
}

bool inode_add_parent (block_sector_t parent_sector, block_sector_t child_sector) {
  struct inode* inode = inode_open(child_sector);
  if (inode == NULL) {
    return false;
  }
  inode->parent = parent_sector;
  inode_close(inode);
  return true;
}

bool inode_is_dir (const struct inode* inode) {
  return inode->isdir;
}