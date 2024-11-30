/*

  MyFS: a tiny file-system written for educational purposes

  MyFS is 

  Copyright 2018-21 by

  University of Alaska Anchorage, College of Engineering.

  Copyright 2022-24

  University of Texas at El Paso, Department of Computer Science.

  Contributors: Christoph Lauter 
                ... and
                ...

  and based on 

  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall myfs.c implementation.c `pkg-config fuse --cflags --libs` -o myfs

*/

#include <stddef.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>


/* The filesystem you implement must support all the 13 operations
   stubbed out below. There need not be support for access rights,
   links, symbolic links. There needs to be support for access and
   modification times and information for statfs.

   The filesystem must run in memory, using the memory of size 
   fssize pointed to by fsptr. The memory comes from mmap and 
   is backed with a file if a backup-file is indicated. When
   the filesystem is unmounted, the memory is written back to 
   that backup-file. When the filesystem is mounted again from
   the backup-file, the same memory appears at the newly mapped
   in virtual address. The filesystem datastructures hence must not
   store any pointer directly to the memory pointed to by fsptr; it
   must rather store offsets from the beginning of the memory region.

   When a filesystem is mounted for the first time, the whole memory
   region of size fssize pointed to by fsptr reads as zero-bytes. When
   a backup-file is used and the filesystem is mounted again, certain
   parts of the memory, which have previously been written, may read
   as non-zero bytes. The size of the memory region is at least 2048
   bytes.

   CAUTION:

   * You MUST NOT use any global variables in your program for reasons
   due to the way FUSE is designed.

   You can find ways to store a structure containing all "global" data
   at the start of the memory region representing the filesystem.

   * You MUST NOT store (the value of) pointers into the memory region
   that represents the filesystem. Pointers are virtual memory
   addresses and these addresses are ephemeral. Everything will seem
   okay UNTIL you remount the filesystem again.

   You may store offsets/indices (of type size_t) into the
   filesystem. These offsets/indices are like pointers: instead of
   storing the pointer, you store how far it is away from the start of
   the memory region. You may want to define a type for your offsets
   and to write two functions that can convert from pointers to
   offsets and vice versa.

   * You may use any function out of libc for your filesystem,
   including (but not limited to) malloc, calloc, free, strdup,
   strlen, strncpy, strchr, strrchr, memset, memcpy. However, your
   filesystem MUST NOT depend on memory outside of the filesystem
   memory region. Only this part of the virtual memory address space
   gets saved into the backup-file. As a matter of course, your FUSE
   process, which implements the filesystem, MUST NOT leak memory: be
   careful in particular not to leak tiny amounts of memory that
   accumulate over time. In a working setup, a FUSE process is
   supposed to run for a long time!

   It is possible to check for memory leaks by running the FUSE
   process inside valgrind:

   valgrind --leak-check=full ./myfs --backupfile=test.myfs ~/fuse-mnt/ -f

   However, the analysis of the leak indications displayed by valgrind
   is difficult as libfuse contains some small memory leaks (which do
   not accumulate over time). We cannot (easily) fix these memory
   leaks inside libfuse.

   * Avoid putting debug messages into the code. You may use fprintf
   for debugging purposes but they should all go away in the final
   version of the code. Using gdb is more professional, though.

   * You MUST NOT fail with exit(1) in case of an error. All the
   functions you have to implement have ways to indicated failure
   cases. Use these, mapping your internal errors intelligently onto
   the POSIX error conditions.

   * And of course: your code MUST NOT SEGFAULT!

   It is reasonable to proceed in the following order:

   (1)   Design and implement a mechanism that initializes a filesystem
         whenever the memory space is fresh. That mechanism can be
         implemented in the form of a filesystem handle into which the
         filesystem raw memory pointer and sizes are translated.
         Check that the filesystem does not get reinitialized at mount
         time if you initialized it once and unmounted it but that all
         pieces of information (in the handle) get read back correctly
         from the backup-file. 

   (2)   Design and implement functions to find and allocate free memory
         regions inside the filesystem memory space. There need to be 
         functions to free these regions again, too. Any "global" variable
         goes into the handle structure the mechanism designed at step (1) 
         provides.

   (3)   Carefully design a data structure able to represent all the
         pieces of information that are needed for files and
         (sub-)directories.  You need to store the location of the
         root directory in a "global" variable that, again, goes into the 
         handle designed at step (1).
          
   (4)   Write __myfs_getattr_implem and debug it thoroughly, as best as
         you can with a filesystem that is reduced to one
         function. Writing this function will make you write helper
         functions to traverse paths, following the appropriate
         subdirectories inside the file system. Strive for modularity for
         these filesystem traversal functions.

   (5)   Design and implement __myfs_readdir_implem. You cannot test it
         besides by listing your root directory with ls -la and looking
         at the date of last access/modification of the directory (.). 
         Be sure to understand the signature of that function and use
         caution not to provoke segfaults nor to leak memory.

   (6)   Design and implement __myfs_mknod_implem. You can now touch files 
         with 

         touch foo

         and check that they start to exist (with the appropriate
         access/modification times) with ls -la.

   (7)   Design and implement __myfs_mkdir_implem. Test as above.

   (8)   Design and implement __myfs_truncate_implem. You can now 
         create files filled with zeros:

         truncate -s 1024 foo

   (9)   Design and implement __myfs_statfs_implem. Test by running
         df before and after the truncation of a file to various lengths. 
         The free "disk" space must change accordingly.

   (10)  Design, implement and test __myfs_utimens_implem. You can now 
         touch files at different dates (in the past, in the future).

   (11)  Design and implement __myfs_open_implem. The function can 
         only be tested once __myfs_read_implem and __myfs_write_implem are
         implemented.

   (12)  Design, implement and test __myfs_read_implem and
         __myfs_write_implem. You can now write to files and read the data 
         back:

         echo "Hello world" > foo
         echo "Hallo ihr da" >> foo
         cat foo

         Be sure to test the case when you unmount and remount the
         filesystem: the files must still be there, contain the same
         information and have the same access and/or modification
         times.

   (13)  Design, implement and test __myfs_unlink_implem. You can now
         remove files.

   (14)  Design, implement and test __myfs_unlink_implem. You can now
         remove directories.

   (15)  Design, implement and test __myfs_rename_implem. This function
         is extremely complicated to implement. Be sure to cover all 
         cases that are documented in man 2 rename. The case when the 
         new path exists already is really hard to implement. Be sure to 
         never leave the filessystem in a bad state! Test thoroughly 
         using mv on (filled and empty) directories and files onto 
         inexistant and already existing directories and files.

   (16)  Design, implement and test any function that your instructor
         might have left out from this list. There are 13 functions 
         __myfs_XXX_implem you have to write.

   (17)  Go over all functions again, testing them one-by-one, trying
         to exercise all special conditions (error conditions): set
         breakpoints in gdb and use a sequence of bash commands inside
         your mounted filesystem to trigger these special cases. Be
         sure to cover all funny cases that arise when the filesystem
         is full but files are supposed to get written to or truncated
         to longer length. There must not be any segfault; the user
         space program using your filesystem just has to report an
         error. Also be sure to unmount and remount your filesystem,
         in order to be sure that it contents do not change by
         unmounting and remounting. Try to mount two of your
         filesystems at different places and copy and move (rename!)
         (heavy) files (your favorite movie or song, an image of a cat
         etc.) from one mount-point to the other. None of the two FUSE
         processes must provoke errors. Find ways to test the case
         when files have holes as the process that wrote them seeked
         beyond the end of the file several times. Your filesystem must
         support these operations at least by making the holes explicit 
         zeros (use dd to test this aspect).

   (18)  Run some heavy testing: copy your favorite movie into your
         filesystem and try to watch it out of the filesystem.

*/

/* Helper types and functions */

//Overall Process
// A. When Filesystem Starts:
//    1. Get memory pointer (fsptr) and size
//    2. Check if initialized (magic number)
//    3. If not, set up initial structures

// B. When Creating a File:
//    1. Find free space (from free_list)
//    2. Create file entry
//    3. Link it into directory structure
//    4. Update free space tracking

// C. When Reading/Writing:
//    1. Find file in directory structure
//    2. Access its data using offsets
//    3. Perform operation

// D. When Unmounting:
//    1. Save to backup file (if using one)
//    2. All offsets remain valid for next mount

/* YOUR HELPER FUNCTIONS GO HERE */

//magic number for initialization check
#define MAGIC_NUM 0x77777777
//size of each block
#define MYFS_BLOCK_SIZE 1024
//max filename length
#define MYFS_MAX_FILENAME 255
//max path length
#define MYFS_MAX_PATH 4096

//file types
#define MYFS_TYPE_FILE 0
#define MYFS_TYPE_DIR 1

//offset type def
typedef size_t myfs_offset_t;

//filesystem header struct, this goes start of mem and keeps track of filesystem info
struct myfs_header_struct{
      //check if filesutem is intialized or not
      uint32_t magic;
      //where the root dir is located
      myfs_offset_t root_dir;
      //first free block
      myfs_offset_t free_list;
      //total num of blocks in filesystem
      size_t total_blocks;
      //num of blocks that are free
      size_t free_blocks;
      //size of each block
      size_t block_size;
};
typedef struct myfs_header_struct myfs_header_t;

//struct to manage mem blocks in filesystem kind of a linked list of free spaces
struct myfs_block_header {
      //points to next free block
      myfs_offset_t next;
      //size of the curr block
      size_t size;
}; 
typedef struct myfs_block_header myfs_block_header_t;


//file and directory struct
struct myfs_file_struct{
      //name of file and + 1 for null terminator
      char name[MYFS_MAX_FILENAME + 1];
      //type of file is it a file or is it a dir
      uint32_t type;
      //where the content is stored
      myfs_offset_t data_block;
      //next file or dir in same dir
      myfs_offset_t next;
      //parent dir
      myfs_offset_t parent;
      //size of the file
      size_t size;
      //last accessed time
      struct timespec last_access_time;
      //last modifed time
      struct timespec last_modified_time;

};
typedef struct myfs_file_struct myfs_file_t;

/*

FUNCTIONS FOR CONVERTING POINTERS TO OFFSETS AND OFFSETS TO POINTERS

*/

//convert offset to pointer
static inline void* offset_to_ptr(void *fsptr, myfs_offset_t offset) {
      if (offset == 0) {
            return NULL;
      }
      //add offset to base adress
      return (char *)fsptr + offset;
}

//convert pointer to offset
static inline myfs_offset_t ptr_to_offset(void *fsptr, void *ptr) {
      if (ptr == NULL || ptr < fsptr || fsptr == NULL) {
            return 0;
      }
      //distance from the start
      return (char *)ptr - (char *)fsptr;
}


/*

FUNCTIONS FOR INTIALIZING THE FILESYSTEM, CHECCKING IF FILESYSTEM IS ALREADY INITALIZED

*/

//a fucntion to intialize the filesystem
//the order for our fs is HEADER -> ROOT DIR -> FREE SPACE
static int intalize_filesystem(void *fsptr, size_t fssize) {
    printf("Initializing filesystem with size %zu bytes\n", fssize);

    // Zero out entire memory region first
    memset(fsptr, 0, fssize);

    myfs_header_t *header = (myfs_header_t *)fsptr;
    
    // Set basic header information
    header->magic = MAGIC_NUM;
    header->block_size = MYFS_BLOCK_SIZE;
    
    // Calculate usable space (total size minus header)
    size_t usable_space = fssize - sizeof(myfs_header_t);
    
    // Setup root directory right after header, aligned to block boundary
    header->root_dir = ((sizeof(myfs_header_t) + MYFS_BLOCK_SIZE - 1) 
                       & ~(MYFS_BLOCK_SIZE - 1));
    
    myfs_file_t *root = offset_to_ptr(fsptr, header->root_dir);
    if (!root) return -1;
    
    // Initialize root directory
    strcpy(root->name, "/");
    root->type = MYFS_TYPE_DIR;
    root->parent = 0;  // Root has no parent
    root->data_block = 0;  // Initially empty
    root->next = 0;
    root->size = 0;
    
    // Set timestamps
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    root->last_access_time = current_time;
    root->last_modified_time = current_time;

    // Calculate where free space starts (after root directory, aligned to block boundary)
    size_t root_end = header->root_dir + sizeof(myfs_file_t);
    header->free_list = (root_end + MYFS_BLOCK_SIZE - 1) & ~(MYFS_BLOCK_SIZE - 1);

    // Calculate actual usable space for blocks
    size_t space_for_blocks = usable_space - header->free_list;
    
    // Calculate total blocks and setup free space tracking
    header->total_blocks = space_for_blocks / MYFS_BLOCK_SIZE;
    header->free_blocks = header->total_blocks;

    // Initialize free block list
    myfs_block_header_t *first_block = offset_to_ptr(fsptr, header->free_list);
    if (!first_block) return -1;
    
    first_block->next = 0;  // This is the only free block initially
    first_block->size = space_for_blocks;

    printf("Filesystem initialized:\n");
    printf("  Total size: %zu\n", fssize);
    printf("  Usable space: %zu\n", usable_space);
    printf("  Block size: %zu\n", header->block_size);
    printf("  Total blocks: %zu\n", header->total_blocks);
    printf("  Free blocks: %zu\n", header->free_blocks);
    printf("  Root directory at: %zu\n", header->root_dir);
    printf("  Free list starts at: %zu\n", header->free_list);
    printf("  First free block size: %zu\n", first_block->size);
    
    return 0;
}

//function to check if the filestysem is already initalized
static int is_initialized(void *fsptr, size_t fssize) {

      printf("Checking if initialized: fsptr=%p, fssize=%zu\n", fsptr, fssize);

      //check pointer and size are good
      if (fsptr == NULL || fssize < sizeof(myfs_header_t)) {
            printf("Basic checks failed: fsptr=%p, fssize=%zu, header_size=%zu\n",
                  fsptr, fssize, sizeof(myfs_header_t));
            return 0;
      }
      //get header
      myfs_header_t *header = (myfs_header_t *)fsptr;
      printf("Magic number found: 0x%x (expected: 0x%x)\n", header->magic, MAGIC_NUM);
      //check if initialized
      return (header->magic == MAGIC_NUM);
}

//fucntion to intialize if needed and return header
static myfs_header_t *get_fs_header(void *fsptr, size_t fssize, int *errnoptr) {
      
      printf("get_fs_header called with size: %zu\n", fssize); // Debug print
      
      //check if initialized
      if (!is_initialized(fsptr, fssize)) {
            //initialize
            printf("Filesystem not initialized, initializing now...\n"); // Debug print
            if (intalize_filesystem(fsptr, fssize) != 0) {
                  //error
                   printf("Initialization failed\n"); // Debug print
                  *errnoptr = EFAULT;
                  return NULL;
            }
            printf("Initialization successful\n"); // Debug print
      }
      //get header
      return (myfs_header_t *)fsptr;
}

/*

FUNCTIONS FOR MEMORY ALLOCATION

*/

static myfs_offset_t allocate_block(void *fsptr, size_t size) {
    if (!fsptr || size == 0) return 0;

    myfs_header_t *header = (myfs_header_t *)fsptr;
    
    // Calculate total size needed including header
    size_t total_size = size + sizeof(myfs_block_header_t);
    
    // Round up to nearest block size
    size_t num_blocks = (total_size + MYFS_BLOCK_SIZE - 1) / MYFS_BLOCK_SIZE;
    size_t aligned_size = num_blocks * MYFS_BLOCK_SIZE;

    // Check if we have enough free blocks
    if (num_blocks > header->free_blocks) {
        printf("Request too large: needs %zu blocks (%zu bytes), only %zu blocks free\n", 
              num_blocks, aligned_size, header->free_blocks);
        return 0;
    }

    printf("Attempting to allocate %zu bytes (aligned to %zu)\n", size, aligned_size);

    // Variables for traversing the free list
    myfs_offset_t curr_offset = header->free_list;
    myfs_offset_t prev_offset = 0;
    myfs_offset_t best_fit_offset = 0;
    myfs_offset_t best_fit_prev = 0;
    size_t smallest_size_diff = SIZE_MAX;

    // Find the best fitting block (smallest block that's big enough)
    while (curr_offset != 0) {
        myfs_block_header_t *curr_block = offset_to_ptr(fsptr, curr_offset);
        if (!curr_block) return 0;

        if (curr_block->size >= aligned_size) {
            size_t size_diff = curr_block->size - aligned_size;
            if (size_diff < smallest_size_diff) {
                smallest_size_diff = size_diff;
                best_fit_offset = curr_offset;
                best_fit_prev = prev_offset;
                
                // If perfect fit, stop searching
                if (size_diff == 0) break;
            }
        }
        prev_offset = curr_offset;
        curr_offset = curr_block->next;
    }

    // If no suitable block found
    if (best_fit_offset == 0) {
        printf("No suitable block found\n");
        return 0;
    }

    myfs_block_header_t *best_block = offset_to_ptr(fsptr, best_fit_offset);
    size_t remaining_size = best_block->size - aligned_size;

    // If remaining space is enough for a new block (including header)
    if (remaining_size >= sizeof(myfs_block_header_t) + MYFS_BLOCK_SIZE) {
        // Create new block from remaining space
        myfs_offset_t new_offset = best_fit_offset + aligned_size;
        myfs_block_header_t *new_block = offset_to_ptr(fsptr, new_offset);
        if (!new_block) return 0;

        new_block->size = remaining_size;
        new_block->next = best_block->next;

        // Update free list
        if (best_fit_prev == 0) {
            header->free_list = new_offset;
        } else {
            myfs_block_header_t *prev_block = offset_to_ptr(fsptr, best_fit_prev);
            if (prev_block) prev_block->next = new_offset;
        }
    } else {
        // Use entire block
        aligned_size = best_block->size;  // Use full block size
        if (best_fit_prev == 0) {
            header->free_list = best_block->next;
        } else {
            myfs_block_header_t *prev_block = offset_to_ptr(fsptr, best_fit_prev);
            if (prev_block) prev_block->next = best_block->next;
        }
    }

    // Update allocated block header and free block count
    best_block->size = aligned_size;
    header->free_blocks -= (aligned_size / MYFS_BLOCK_SIZE);

    printf("Successfully allocated block at offset %zu, size %zu\n", 
           best_fit_offset + sizeof(myfs_block_header_t), 
           aligned_size);

    return best_fit_offset + sizeof(myfs_block_header_t);
}

static void free_block(void *fsptr, myfs_offset_t offset) {
    if (!fsptr || offset == 0) return;

    myfs_header_t *header = (myfs_header_t *)fsptr;
    
    // Get block header offset
    myfs_offset_t block_start = offset - sizeof(myfs_block_header_t);
    myfs_block_header_t *block = offset_to_ptr(fsptr, block_start);
    if (!block) return;

    // Calculate number of blocks to free
    size_t num_blocks = (block->size + MYFS_BLOCK_SIZE - 1) / MYFS_BLOCK_SIZE;
    
    // Try to coalesce with adjacent free blocks
    myfs_offset_t curr_offset = header->free_list;
    myfs_offset_t prev_offset = 0;
    
    while (curr_offset != 0) {
        myfs_block_header_t *curr_block = offset_to_ptr(fsptr, curr_offset);
        if (!curr_block) break;
        
        // Check if this block is adjacent to our freed block
        if (curr_offset + curr_block->size == block_start) {
            // Merge current block with our freed block
            curr_block->size += block->size;
            
            // Update free block count
            header->free_blocks += num_blocks;
            
            printf("Merged freed block (offset %zu, size %zu) with previous block\n", 
                   offset, block->size);
            return;
        }
        
        if (block_start + block->size == curr_offset) {
            // Merge our freed block with current block
            block->size += curr_block->size;
            block->next = curr_block->next;
            
            if (prev_offset == 0) {
                header->free_list = block_start;
            } else {
                myfs_block_header_t *prev_block = offset_to_ptr(fsptr, prev_offset);
                if (prev_block) prev_block->next = block_start;
            }
            
            // Update free block count
            header->free_blocks += num_blocks;
            
            printf("Merged freed block (offset %zu, size %zu) with next block\n", 
                   offset, block->size);
            return;
        }
        
        if (curr_offset > block_start) break;
        
        prev_offset = curr_offset;
        curr_offset = curr_block->next;
    }

    // If no merging possible, just add to free list
    block->next = header->free_list;
    header->free_list = block_start;
    header->free_blocks += num_blocks;

    printf("Freed block at offset %zu, size %zu, blocks %zu\n", 
           offset, block->size, num_blocks);
}

/*

FUNCTIONS FOR PATHS

*/

//function to find an entry (file or directory) in a directory by name to locate files/directories
static myfs_file_t* find_entry(void* fsptr, myfs_file_t* dir, const char* name) {
      printf("find_entry: searching for '%s'\n", name);
      
      if (!dir || !name) return NULL;

      // Skip leading slash if present
      while (name[0] == '/') name++;

      // Handle paths with multiple components
      char *path_copy = strdup(name);
      if (!path_copy) return NULL;

      char *saveptr = NULL;
      char *component = strtok_r(path_copy, "/", &saveptr);
      myfs_file_t *current = dir;

      while (component) {
            // Search for this component in current directory
            myfs_offset_t curr_offset = current->data_block;
            myfs_file_t *found = NULL;

            printf("find_entry: looking for component '%s' in directory '%s'\n", 
                  component, current->name);

            // Search through current directory's entries
            while (curr_offset != 0) {
                  myfs_file_t *entry = offset_to_ptr(fsptr, curr_offset);
                  if (!entry) break;

                  printf("find_entry: examining entry '%s'\n", entry->name);

                  if (entry->parent == ptr_to_offset(fsptr, current) && 
                  strcmp(entry->name, component) == 0) {
                  found = entry;
                  break;
                  }
                  curr_offset = entry->next;
            }

            if (!found) {
                  free(path_copy);
                  return NULL;
            }

            current = found;
            component = strtok_r(NULL, "/", &saveptr);
      }

      free(path_copy);
      return current;
}

static myfs_file_t* find_entry_in_dir(void* fsptr, myfs_file_t* dir, const char* name) {
      printf("find_entry_in_dir: searching for '%s' in directory '%s'\n", name, dir->name);
      
      if (!dir || !name) return NULL;

      // Skip leading slash if present
      while (name[0] == '/') name++;
      
      // Search only through entries in this directory
      myfs_offset_t curr_offset = dir->data_block;
      myfs_offset_t dir_offset = ptr_to_offset(fsptr, dir);
      
      printf("find_entry_in_dir: dir offset %zu, data block %zu\n", 
            dir_offset, curr_offset);
      
      while (curr_offset != 0) {
            myfs_file_t* entry = offset_to_ptr(fsptr, curr_offset);
            if (!entry) {
                  printf("find_entry_in_dir: invalid entry pointer\n");
                  return NULL;
            }
            
            printf("find_entry_in_dir: examining entry '%s' (parent: %zu)\n", 
                  entry->name, entry->parent);
            
            if (entry->parent == dir_offset && strcmp(entry->name, name) == 0) {
                  printf("find_entry_in_dir: found matching entry\n");
                  return entry;
            }
            
            curr_offset = entry->next;
      }
      
      printf("find_entry_in_dir: entry not found\n");
      return NULL;
}

static myfs_file_t *find_file(myfs_header_t *header, const char *path) {
      printf("find_file: looking for path '%s'\n", path);
      
      // Handle root directory case
      if (!path || path[0] == '\0' || strcmp(path, "/") == 0) {
            return offset_to_ptr(header, header->root_dir);
      }

      // Skip leading slash
      while (path[0] == '/') path++;

      // Start from root directory
      myfs_file_t *current = offset_to_ptr(header, header->root_dir);
      if (!current) return NULL;

      char *path_copy = strdup(path);
      if (!path_copy) return NULL;
      
      char *saveptr = NULL;
      char *component = strtok_r(path_copy, "/", &saveptr);
      
      while (component) {
            printf("find_file: looking for component '%s' in dir '%s'\n", 
                  component, current->name);
            
            myfs_file_t *next = find_entry_in_dir(header, current, component);
            if (!next) {
                  printf("find_file: component not found\n");
                  free(path_copy);
                  return NULL;
            }
            
            current = next;
            component = strtok_r(NULL, "/", &saveptr);
      }

      free(path_copy);
      return current;
}

static myfs_file_t* find_parent_dir(void* fsptr, const char* path, char** filename, int* errnoptr) {
    // Check inputs
    if (!fsptr || !path || !filename || !errnoptr) {
        if (errnoptr) *errnoptr = EFAULT;
        return NULL;
    }

    // Handle root directory case
    if (strcmp(path, "/") == 0) {
        *errnoptr = EEXIST;
        return NULL;
    }

    // Make a copy of the path for manipulation
    char* path_copy = strdup(path);
    if (!path_copy) {
        *errnoptr = ENOMEM;
        return NULL;
    }

    // Find the last slash in the path
    char* last_slash = strrchr(path_copy, '/');
    if (!last_slash) {
        free(path_copy);
        *errnoptr = EINVAL;
        return NULL;
    }

    // Extract the filename/dirname
    *filename = strdup(last_slash + 1);
    if (!*filename) {
        free(path_copy);
        *errnoptr = ENOMEM;
        return NULL;
    }

    // If path is just "/filename", parent is root
    if (last_slash == path_copy) {
        free(path_copy);
        myfs_header_t* header = (myfs_header_t*)fsptr;
        return offset_to_ptr(fsptr, header->root_dir);
    }

    // Null terminate at last slash to get parent path
    *last_slash = '\0';

    // Use find_file to get the parent directory
    myfs_header_t* header = (myfs_header_t*)fsptr;
    myfs_file_t* parent = find_file(header, path_copy);
    
    free(path_copy);

    // Check if parent exists and is a directory
    if (!parent) {
        free(*filename);
        *filename = NULL;
        *errnoptr = ENOENT;
        return NULL;
    }

    if (parent->type != MYFS_TYPE_DIR) {
        free(*filename);
        *filename = NULL;
        *errnoptr = ENOTDIR;
        return NULL;
    }

    return parent;
}


/* End of helper functions */

/* Implements an emulation of the stat system call on the filesystem 
   of size fssize pointed to by fsptr. 
   
   If path can be followed and describes a file or directory 
   that exists and is accessable, the access information is 
   put into stbuf. 

   On success, 0 is returned. On failure, -1 is returned and 
   the appropriate error code is put into *errnoptr.

   man 2 stat documents all possible error codes and gives more detail
   on what fields of stbuf need to be filled in. Essentially, only the
   following fields need to be supported:

   st_uid      the value passed in argument
   st_gid      the value passed in argument
   st_mode     (as fixed values S_IFDIR | 0755 for directories,
                                S_IFREG | 0755 for files)
   st_nlink    (as many as there are subdirectories (not files) for directories
                (including . and ..),
                1 for files)
   st_size     (supported only for files, where it is the real file size)
   st_atim
   st_mtim

*/
int __myfs_getattr_implem(void *fsptr, size_t fssize, int *errnoptr,
                          uid_t uid, gid_t gid,
                          const char *path, struct stat *stbuf) {

      printf("getattr called for path: %s\n", path);  // Debug print


      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            printf("Header is NULL\n");  // Debug print
            *errnoptr = EFAULT;
            return -1;
      }

      // Special case for root directory
      if (strcmp(path, "/") == 0) {
            memset(stbuf, 0, sizeof(struct stat));
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            stbuf->st_uid = uid;
            stbuf->st_gid = gid;
            stbuf->st_size = 0;
            stbuf->st_blocks = 0;
            return 0;
      }

      //get rpot dir to use it to find other entries
      myfs_file_t *root_dir = offset_to_ptr(fsptr, header->root_dir);
      if(root_dir == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entru for given path
      myfs_file_t *entry = find_entry(fsptr, root_dir, path);
      if (entry == NULL){
            *errnoptr = ENOENT;
            return -1;
      }

      //intialized the stat buff

      //clear all fields in stat struct
      memset(stbuf, 0, sizeof(struct stat));

      //fill basic info that is same from both dir and files
      //user id of owner
      stbuf -> st_uid = uid;
      //group id of owner
      stbuf -> st_gid = gid;

      //check whethere its a file or a dir
      if(entry->type == MYFS_TYPE_DIR){
            //S_IFDIR indiactes dir from INODE(7) from man
            stbuf->st_mode = S_IFDIR | 0755;

            //ncount links start wirh 2 for "." and ".." entries
            stbuf -> st_nlink = 2;

            //count all subdir in this dir, each subsir adds a link because of its ..
            myfs_offset_t child_offset = entry->data_block;
            while (child_offset != 0){
                  myfs_file_t *child_entry_file = offset_to_ptr(fsptr, child_offset);
                  if (child_entry_file->type == MYFS_TYPE_DIR){
                        stbuf -> st_nlink++;
                  }
                  child_offset = child_entry_file -> next;
            }

            //dir dont have a size
            stbuf->st_size = 0;
      }
      //its a file
      else{

            stbuf -> st_mode = S_IFREG | 0755;

            //reg files have on line
            stbuf->st_nlink = 1;

            //set size
            stbuf->st_size = entry->size;
      }

      //set time
      stbuf->st_atim = entry->last_access_time;
      stbuf->st_mtim = entry->last_modified_time;

      return 0;
}

/* Implements an emulation of the readdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   If path can be followed and describes a directory that exists and
   is accessable, the names of the subdirectories and files 
   contained in that directory are output into *namesptr. The . and ..
   directories must not be included in that listing.

   If it needs to output file and subdirectory names, the function
   starts by allocating (with calloc) an array of pointers to
   characters of the right size (n entries for n names). Sets
   *namesptr to that pointer. It then goes over all entries
   in that array and allocates, for each of them an array of
   characters of the right size (to hold the i-th name, together 
   with the appropriate '\0' terminator). It puts the pointer
   into that i-th array entry and fills the allocated array
   of characters with the appropriate name. The calling function
   will call free on each of the entries of *namesptr and 
   on *namesptr.

   The function returns the number of names that have been 
   put into namesptr. 

   If no name needs to be reported because the directory does
   not contain any file or subdirectory besides . and .., 0 is 
   returned and no allocation takes place.

   On failure, -1 is returned and the *errnoptr is set to 
   the appropriate error code. 

   The error codes are documented in man 2 readdir.

   In the case memory allocation with malloc/calloc fails, failure is
   indicated by returning -1 and setting *errnoptr to EINVAL.

*/
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                              const char *path, char ***namesptr) {
      printf("=== READDIR START ===\n");
      printf("readdir called for path: %s\n", path);
      printf("fssize: %zu\n", fssize);
      
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if (!header) {
            printf("ERROR: Failed to get filesystem header\n");
            return -1;
      }
      printf("Got filesystem header successfully. Root dir offset: %zu\n", header->root_dir);

      // Find the directory
      printf("Finding directory for path: %s\n", path);
      myfs_file_t *dir = find_file(header, path);
      if (!dir) {
            printf("ERROR: Directory not found\n");
            *errnoptr = ENOENT;
            return -1;
      }
      printf("Found directory. Type: %d, Name: %s, Parent offset: %zu, Data block: %zu\n", 
            dir->type, dir->name, dir->parent, dir->data_block);

      if (dir->type != MYFS_TYPE_DIR) {
            printf("ERROR: Path is not a directory (type=%d)\n", dir->type);
            *errnoptr = ENOTDIR;
            return -1;
      }
      printf("Confirmed path is a directory\n");

      // Count entries
      printf("Counting directory entries...\n");
      int count = 0;
      myfs_offset_t curr_offset = dir->data_block;
      myfs_offset_t dir_offset = ptr_to_offset(fsptr, dir);
      printf("Directory offset: %zu, First entry offset: %zu\n", dir_offset, curr_offset);
      
      while (curr_offset != 0) {
      printf("Processing entry at offset: %zu\n", curr_offset);
      myfs_file_t *entry = offset_to_ptr(fsptr, curr_offset);
      if (!entry) {
            printf("ERROR: Invalid entry pointer at offset %zu\n", curr_offset);
            break;
      }
      
      // Store the next offset before any other operations
      myfs_offset_t next_offset = entry->next;
      
      // Only count entries that belong to this directory
      if (entry->parent == dir_offset) {
            count++;
      }

      // Break if we detect a cycle - next points to current or previous entry
      if (next_offset == curr_offset) {
            printf("WARNING: Detected self-referential cycle at offset %zu\n", curr_offset);
            break;
      }
      
      curr_offset = next_offset;
      }
      printf("Found %d entries in directory\n", count);

      // No entries
      if (count == 0) {
            printf("Directory is empty (excluding . and ..)\n");
            return 0;
      }
      printf("Allocating array for %d entries\n", count);

      // Allocate array for names
      *namesptr = calloc(count, sizeof(char *));
      if (!*namesptr) {
            printf("ERROR: Failed to allocate memory for names array\n");
            *errnoptr = ENOMEM;
            return -1;
      }
      printf("Successfully allocated names array\n");

      // Fill array with names
      printf("Filling names array...\n");
      curr_offset = dir->data_block;
      int index = 0;
      
      while (curr_offset != 0 && index < count) {
            printf("Processing entry %d at offset %zu\n", index, curr_offset);
            myfs_file_t *entry = offset_to_ptr(fsptr, curr_offset);
            if (!entry) {
                  printf("ERROR: Invalid entry pointer during array fill\n");
                  break;
            }
            
            printf("Entry: name='%s', parent=%zu, dir_offset=%zu\n", 
                  entry->name, entry->parent, ptr_to_offset(fsptr, dir));
            
            if (entry->parent == ptr_to_offset(fsptr, dir)) {
                  printf("Adding entry '%s' to names array at index %d\n", entry->name, index);
                  (*namesptr)[index] = strdup(entry->name);
                  if (!(*namesptr)[index]) {
                  printf("ERROR: Failed to duplicate name string\n");
                  // Cleanup on error
                  for (int i = 0; i < index; i++) {
                        free((*namesptr)[i]);
                  }
                  free(*namesptr);
                  *errnoptr = ENOMEM;
                  return -1;
                  }
                  index++;
            } else {
                  printf("Skipping entry - belongs to different directory\n");
            }
            curr_offset = entry->next;
      }

      printf("=== READDIR END === (returning %d entries)\n", count);
      return count;
}

/* Implements an emulation of the mknod system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the creation of regular files.

   If a file gets created, it is of size zero and has default
   ownership and mode bits.

   The call creates the file indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mknod.

*/
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path) {
      printf("mknod called for path: %s\n", path);
      
      if (!fsptr || !path || !errnoptr) {
            if (errnoptr) *errnoptr = EFAULT;
            return -1;
      }

      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if (!header) return -1;

      // Get parent directory and filename
      char *filename = NULL;
      myfs_file_t *parent_dir = find_parent_dir(fsptr, path, &filename, errnoptr);
      if (!parent_dir) {
            printf("mknod: could not find parent directory\n");
            return -1;
      }

      // Check if file already exists in this directory
      myfs_file_t *existing = find_entry_in_dir(fsptr, parent_dir, filename);
      if (existing) {
            free(filename);
            *errnoptr = EEXIST;
            return -1;
      }

      // Allocate space for new file
      myfs_offset_t new_file_offset = allocate_block(fsptr, sizeof(myfs_file_t));
      if (new_file_offset == 0) {
            free(filename);
            *errnoptr = ENOSPC;
            return -1;
      }

      // Initialize new file
      myfs_file_t *new_file = offset_to_ptr(fsptr, new_file_offset);
      if (!new_file) {
            free(filename);
            *errnoptr = EFAULT;
            return -1;
      }

      memset(new_file, 0, sizeof(myfs_file_t));
      strncpy(new_file->name, filename, MYFS_MAX_FILENAME);
      new_file->type = MYFS_TYPE_FILE;
      new_file->size = 0;
      new_file->parent = ptr_to_offset(fsptr, parent_dir);

      // Add to parent directory
      new_file->next = parent_dir->data_block;
      parent_dir->data_block = new_file_offset;

      // Set timestamps
      struct timespec current_time;
      clock_gettime(CLOCK_REALTIME, &current_time);
      new_file->last_access_time = current_time;
      new_file->last_modified_time = current_time;

      free(filename);
      return 0;
}

/* Implements an emulation of the unlink system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the deletion of regular files.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 unlink.

*/
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
      //check params
      if(!fsptr || !path || !errnoptr){
            if (errnoptr){
                  //error code for bad address
                  *errnoptr = EFAULT;
            }
            return -1;
      }

      //initalized fs
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      //if failed
      if (!header){
            return -1;
      }

      //get the filename and parent dir
      char *filename;
      myfs_file_t *parent_dir = find_parent_dir(fsptr, path, &filename, errnoptr);
      if (parent_dir == NULL){
            return -1;
      }

      //get parent dir offset
      myfs_offset_t parent_offset = ptr_to_offset(fsptr, parent_dir);

      //search the dir for the file and ww going to use a 2 pointer way to traverse

      //keep track of previous entry for LL
      myfs_offset_t prev_offset = 0;
      //first entry in dir
      myfs_offset_t curr_offset = parent_dir -> data_block;
      //pointer to curr file entry bieng checked
      myfs_file_t* curr_file_ptr = NULL;

      //loop thoriugh dir entries
      while(curr_offset != 0){
            curr_file_ptr = offset_to_ptr(fsptr, curr_offset);

            //check if this is the file we want to unlink
            if (strcmp(curr_file_ptr->name, filename) == 0){
                  //make sure we are deleting a file not a dir
                  if(curr_file_ptr->type != MYFS_TYPE_FILE){
                        free(filename);
                        //error if trying to delete a directory
                        *errnoptr = EISDIR;
                        return -1;
                  }

                  if(curr_file_ptr->parent != parent_offset){
                        free(filename);
                        *errnoptr = EFAULT;
                        return -1;
                  }

                  //remove from the dir list so update the dir links to keep this file
                  //first entry in dir
                  if(prev_offset == 0){
                        parent_dir ->data_block = curr_file_ptr->next;
                  }
                  //the file is either in th emiddle or end of dir
                  else{
                        myfs_file_t* prev_file_ptr = offset_to_ptr(fsptr, prev_offset);
                        prev_file_ptr->next = curr_file_ptr->next;
                  }

                  //if file was not empty feee its data blocks
                  if(curr_file_ptr->data_block !=0){
                        free_block(fsptr, curr_file_ptr->data_block);
                  }
                  //free file entry
                  curr_file_ptr->parent = 0;
                  free_block(fsptr, curr_offset);

                  //we good
                  free(filename);
                  return 0;
            }

            //update pointers
            prev_offset = curr_offset;
            curr_offset = curr_file_ptr->next;
      }

      //if the file was not found
      free(filename);
      *errnoptr = ENOENT;
      return -1;
}

/* Implements an emulation of the rmdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call deletes the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The function call must fail when the directory indicated by path is
   not empty (if there are files or subdirectories other than . and ..).

   The error codes are documented in man 2 rmdir.

*/
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path) {
      printf("rmdir called for path: %s\n", path);
      
      if (!fsptr || !path || !errnoptr) {
            if (errnoptr) *errnoptr = EFAULT;
            return -1;
      }

      // Cannot remove root
      if (strcmp(path, "/") == 0) {
            *errnoptr = EBUSY;
            return -1;
      }

      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if (!header) return -1;

      // Get parent directory and dirname
      char *dirname;
      myfs_file_t *parent_dir = find_parent_dir(fsptr, path, &dirname, errnoptr);
      if (!parent_dir) {
            return -1;
      }

      // Find directory to remove in parent
      myfs_file_t *dir_to_remove = find_entry_in_dir(fsptr, parent_dir, dirname);
      free(dirname); // Free dirname as we don't need it anymore

      if (!dir_to_remove) {
            *errnoptr = ENOENT;
            return -1;
      }

      // Verify it's a directory
      if (dir_to_remove->type != MYFS_TYPE_DIR) {
            *errnoptr = ENOTDIR;
            return -1;
      }

      // Check directory is empty by scanning its entries
      myfs_offset_t curr_child = dir_to_remove->data_block;
      while (curr_child != 0) {
            myfs_file_t *child = offset_to_ptr(fsptr, curr_child);
            if (!child) {
                  *errnoptr = EFAULT;
                  return -1;
            }
            
            // Only count entries that belong to this directory
            if (child->parent == ptr_to_offset(fsptr, dir_to_remove)) {
                  *errnoptr = ENOTEMPTY;
                  return -1;
            }
            curr_child = child->next;
      }

      // Remove directory from parent's list
      myfs_offset_t prev_offset = 0;
      myfs_offset_t curr_offset = parent_dir->data_block;
      
      while (curr_offset != 0) {
            myfs_file_t *curr = offset_to_ptr(fsptr, curr_offset);
            if (!curr) {
                  *errnoptr = EFAULT;
                  return -1;
            }

            if (curr == dir_to_remove) {
                  // Update links
                  if (prev_offset == 0) {
                  parent_dir->data_block = curr->next;
                  } else {
                  myfs_file_t *prev = offset_to_ptr(fsptr, prev_offset);
                  if (!prev) {
                        *errnoptr = EFAULT;
                        return -1;
                  }
                  prev->next = curr->next;
                  }

                  // Clear parent reference and free the directory entry
                  curr->parent = 0;
                  free_block(fsptr, curr_offset);
                  
                  // Update parent timestamp
                  struct timespec current_time;
                  clock_gettime(CLOCK_REALTIME, &current_time);
                  parent_dir->last_modified_time = current_time;
                  parent_dir->last_access_time = current_time;
                  
                  return 0;
            }

            prev_offset = curr_offset;
            curr_offset = curr->next;
      }

      *errnoptr = ENOENT;
      return -1;
}
/* Implements an emulation of the mkdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.

*/
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path) {
      printf("mkdir called for path: %s\n", path);
      
      if (!fsptr || !path || !errnoptr) {
            if (errnoptr) *errnoptr = EFAULT;
            return -1;
      }

      // Cannot create root
      if (strcmp(path, "/") == 0) {
            *errnoptr = EEXIST;
            return -1;
      }

      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if (!header) return -1;

      // Get parent directory and dirname
      char *dirname;
      myfs_file_t *parent_dir = find_parent_dir(fsptr, path, &dirname, errnoptr);
      if (!parent_dir) return -1;

      printf("mkdir: checking if directory exists in parent '%s'\n", parent_dir->name);

      // Check if directory already exists
      myfs_file_t *existing = find_entry_in_dir(fsptr, parent_dir, dirname);
      if (existing) {
            printf("mkdir: directory already exists\n");
            free(dirname);
            *errnoptr = EEXIST;
            return -1;
      }

      // Allocate space for new directory
      myfs_offset_t new_dir_offset = allocate_block(fsptr, sizeof(myfs_file_t));
      if (new_dir_offset == 0) {
            printf("mkdir: failed to allocate space\n");
            free(dirname);
            *errnoptr = ENOSPC;
            return -1;
      }

      // Initialize new directory
      myfs_file_t *new_dir = offset_to_ptr(fsptr, new_dir_offset);
      if (!new_dir) {
            printf("mkdir: failed to get pointer to new directory\n");
            free(dirname);
            *errnoptr = EFAULT;
            return -1;
      }

      // Set up new directory
      memset(new_dir, 0, sizeof(myfs_file_t));
      strncpy(new_dir->name, dirname, MYFS_MAX_FILENAME);
      new_dir->type = MYFS_TYPE_DIR;
      new_dir->size = 0;
      new_dir->parent = ptr_to_offset(fsptr, parent_dir);
      new_dir->data_block = 0;  // No entries yet

      // Link into parent's directory structure
      new_dir->next = parent_dir->data_block;
      parent_dir->data_block = new_dir_offset;

      // Set timestamps
      struct timespec current_time;
      clock_gettime(CLOCK_REALTIME, &current_time);
      new_dir->last_access_time = current_time;
      new_dir->last_modified_time = current_time;

      printf("mkdir: directory created successfully\n");
      free(dirname);
      return 0;
}

/* Implements an emulation of the rename system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call moves the file or directory indicated by from to to.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   Caution: the function does more than what is hinted to by its name.
   In cases the from and to paths differ, the file is moved out of 
   the from path and added to the to path.

   The error codes are documented in man 2 rename.

*/
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr,
                         const char *from, const char *to) {
      
      // Check parameters
      if (!fsptr || !from || !to || !errnoptr) {
            if (errnoptr) {
                  *errnoptr = EFAULT;
            }
            return -1;
      }

      // If paths are the same, do nothing
      if (strcmp(from, to) == 0) {
            return 0;
      }
      
      // Get filesystem header
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if (!header) {
            *errnoptr = EFAULT;
            return -1;
      }

      // Get root directory for path traversal
      myfs_file_t *root_dir = offset_to_ptr(fsptr, header->root_dir);
      if (!root_dir) {
            *errnoptr = EFAULT;
            return -1;
      }

      // Find source parent directory and name
      char *from_name;
      myfs_file_t *from_parent = find_parent_dir(fsptr, from, &from_name, errnoptr);
      if (!from_parent) {
            return -1;
      }

      // Find source entry in its parent directory
      myfs_offset_t prev_offset = 0;
      myfs_offset_t curr_offset = from_parent->data_block;
      myfs_file_t *from_entry = NULL;

      // Loop through parent directory entries
      while (curr_offset != 0) {
            myfs_file_t *curr_ptr = offset_to_ptr(fsptr, curr_offset);
            if (!curr_ptr) {
                  free(from_name);
                  *errnoptr = EFAULT;
                  return -1;
            }
            
            if (strcmp(curr_ptr->name, from_name) == 0) {
                  from_entry = curr_ptr;
                  break;
            }
            prev_offset = curr_offset;
            curr_offset = curr_ptr->next;
      }

      if (!from_entry) {
            free(from_name);
            *errnoptr = ENOENT;
            return -1;
      }

      // Find destination parent directory and name
      char *to_name;
      myfs_file_t *to_parent = find_parent_dir(fsptr, to, &to_name, errnoptr);
      if (!to_parent) {
            free(from_name);
            return -1;
      }

      // Save the original next pointer before any modifications
      myfs_offset_t original_next = from_entry->next;

      // Check if destination exists
      myfs_file_t *existing_to = find_entry_in_dir(fsptr, to_parent, to_name);
      if (existing_to) {
            // Cannot overwrite directory with non-directory
            if (existing_to->type == MYFS_TYPE_DIR && from_entry->type != MYFS_TYPE_DIR) {
                  free(from_name);
                  free(to_name);
                  *errnoptr = EISDIR;
                  return -1;
            }
            
            // Cannot overwrite non-directory with directory
            if (existing_to->type != MYFS_TYPE_DIR && from_entry->type == MYFS_TYPE_DIR) {
                  free(from_name);
                  free(to_name);
                  *errnoptr = ENOTDIR;
                  return -1;
            }

            // Directory must be empty if it's being overwritten
            if (existing_to->type == MYFS_TYPE_DIR && existing_to->data_block != 0) {
                  free(from_name);
                  free(to_name);
                  *errnoptr = ENOTEMPTY;
                  return -1;
            }

            // Remove existing destination entry
            myfs_offset_t existing_prev = 0;
            myfs_offset_t existing_curr = to_parent->data_block;

            while (existing_curr != 0) {
                  myfs_file_t *curr = offset_to_ptr(fsptr, existing_curr);
                  if (strcmp(curr->name, to_name) == 0) {
                        if (existing_prev == 0) {
                              to_parent->data_block = curr->next;
                        } else {
                              myfs_file_t *prev = offset_to_ptr(fsptr, existing_prev);
                              prev->next = curr->next;
                        }
                        break;
                  }
                  existing_prev = existing_curr;
                  existing_curr = curr->next;
            }
      }

      // Update source directory links
      if (prev_offset == 0) {
            from_parent->data_block = original_next;
      } else {
            myfs_file_t *prev = offset_to_ptr(fsptr, prev_offset);
            if (prev) {
                  prev->next = original_next;
            }
      }

      // Update the entry itself
      strncpy(from_entry->name, to_name, MYFS_MAX_FILENAME);
      from_entry->parent = ptr_to_offset(fsptr, to_parent);
      
      // Update destination directory links
      from_entry->next = to_parent->data_block;
      to_parent->data_block = ptr_to_offset(fsptr, from_entry);

      // Update timestamps
      struct timespec current_time;
      clock_gettime(CLOCK_REALTIME, &current_time);
      from_parent->last_modified_time = current_time;
      to_parent->last_modified_time = current_time;

      // Cleanup
      free(from_name);
      free(to_name);
      return 0;
}

/* Implements an emulation of the truncate system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call changes the size of the file indicated by path to offset
   bytes.

   When the file becomes smaller due to the call, the extending bytes are
   removed. When it becomes larger, zeros are appended.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 truncate.

*/
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr,
                           const char *path, off_t offset) {
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entry for given path
      myfs_file_t *file = find_file(header, path);
      if (file == NULL){
            *errnoptr = ENOENT;
            return -1;
      }

      // Ensure it is a regular file
      if (file->type != MYFS_TYPE_FILE) {
            *errnoptr = EBADF; // Path is not a file
            return -1;
      }

      // if there is no size change
      if (file->size == (size_t)offset)
            return 0;

      // If the size will be shortened
      if (file->size > (size_t)offset) {
            // Truncate by freeing unused blocks
            size_t bytes_to_remove = file->size - offset;
            myfs_offset_t current_block = file->data_block;

            while (bytes_to_remove > 0 && current_block != 0) {
                  myfs_block_header_t *block = offset_to_ptr(fsptr, current_block);
                  size_t block_size = (block->size > bytes_to_remove) ? bytes_to_remove : block->size;

                  myfs_offset_t next_block = block->next; // Save next block
                  free_block(fsptr, current_block);       // Free current block
                  bytes_to_remove -= block_size;         // Reduce remaining bytes to remove
                  current_block = next_block;            // Move to next block
            }

            memset(file->data_block + offset, '\0', 1);

      } // If the size will be expanded
      else {
           // Extend by adding zeros
            size_t bytes_to_add = offset - file->size;
            char *file_data = offset_to_ptr(fsptr, file->data_block);

            if (file_data == NULL) {
                  *errnoptr = EFAULT; // Filesystem corruption
                  return -1;
            }

            // Find the new space for the data block
            myfs_offset_t new_block = allocate_block(fsptr, offset);
            if (new_block == 0) {
                  *errnoptr = ENOSPC;
                  return -1;
            }
            
            char *new_space = offset_to_ptr(fsptr, new_block);
            if (new_space == NULL) {
                  *errnoptr = EFAULT;
                  return -1;
            }

            // Copy the memory from old space to new space
            memcpy(new_space, file_data, file->size - 1);

            // Free old memory space
            free_block(fsptr, file->data_block);

            // Set the new memory space
            file->data_block = new_block;

            // Append zeros in the remaining space
            memset(new_space + file->size - 1, 0, bytes_to_add);
            memset(new_space + offset, '\0', 1);
      }

      // Update file size
      file->size = offset;

      return 0;
}

/* Implements an emulation of the open system call on the filesystem 
   of size fssize pointed to by fsptr, without actually performing the opening
   of the file (no file descriptor is returned).

   The call just checks if the file (or directory) indicated by path
   can be accessed, i.e. if the path can be followed to an existing
   object for which the access rights are granted.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The two only interesting error codes are 

   * EFAULT: the filesystem is in a bad state, we can't do anything

   * ENOENT: the file that we are supposed to open doesn't exist (or a
             subpath).

   It is possible to restrict ourselves to only these two error
   conditions. It is also possible to implement more detailed error
   condition answers.

   The error codes are documented in man 2 open.

*/
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path) {
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entry for given path
      myfs_file_t *file = find_file(header, path);
      if (file == NULL){
            *errnoptr = ENOENT;
            return -1;
      }

      // Ensure it is a regular file
      if (file->type != MYFS_TYPE_FILE) {
            *errnoptr = EBADF; // Path is not a file
            return -1;
      }

      return 0;
}

/* Implements an emulation of the read system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call copies up to size bytes from the file indicated by 
   path into the buffer, starting to read at offset. See the man page
   for read for the details when offset is beyond the end of the file etc.
   
   On success, the appropriate number of bytes read into the buffer is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 read.

*/
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path, char *buf, size_t size, off_t offset) {
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entry for given path
      myfs_file_t *file = find_file(header, path);
      if (file == NULL){
            *errnoptr = EBADF;
            return -1;
      }

      // Ensure it is a regular file
      if (file->type != MYFS_TYPE_FILE) {
            // *errnoptr = EBADF; // Path is not a file
            //CHANGE:
            *errnoptr = EISDIR;
            return -1;
      }

      // Check if offset is valid
      if(offset < 0){
            *errnoptr = EINVAL;
            return -1;
      }

      //if ofsset is beyone file size the EOF
      if ((size_t)offset > file->size){
            return 0;
      }

      //get how many buytes we can acutllau read
      size_t bytes_to_read = size;
      if((size_t)offset + size > file->size){
            bytes_to_read = file->size - offset;
      }
      //if theres nothing to read
      if (bytes_to_read == 0){
            return 0;
      }


      // Perform the read
      char *file_data = offset_to_ptr(fsptr, file->data_block);
      if (file_data == NULL) {
            *errnoptr = EFAULT; // Filesystem corruption
            return -1;
      }
      memcpy(buf, file_data + offset, bytes_to_read);

      //update access time
      struct timespec curr_time;
      clock_gettime(CLOCK_REALTIME, &curr_time);
      file->last_access_time = curr_time;

      // Return the number of bytes read
      return bytes_to_read;
}

/* Implements an emulation of the write system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call copies up to size bytes to the file indicated by 
   path into the buffer, starting to write at offset. See the man page
   for write for the details when offset is beyond the end of the file etc.
   
   On success, the appropriate number of bytes written into the file is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 write.

*/
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path, const char *buf, size_t size, off_t offset) {
      
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entry for given path
      myfs_file_t *file = find_file(header, path);
      if (file == NULL){
            *errnoptr = EBADF;
            return -1;
      }

      // Ensure it is a regular file
      if (file->type != MYFS_TYPE_FILE) {
            *errnoptr = EISDIR; // Path is not a file
            return -1;
      }

      // Check if offset is valid
      if (offset < 0 || (size_t)offset > file->size) {
            *errnoptr = EINVAL; // Invalid offset
            return -1;
      }

      // Calculate required size to accommodate the write
      size_t required_size = (size_t)offset + size;

      // Allocate more blocks if necessary
      if (required_size > file->size) {
            //round up to nearest blick
            size_t additional_size = ((required_size + MYFS_BLOCK_SIZE - 1) / MYFS_BLOCK_SIZE) * MYFS_BLOCK_SIZE;

            //allocated new vblock
            myfs_offset_t new_block = allocate_block(fsptr, additional_size);
            if (new_block == 0) {
                  *errnoptr = ENOSPC; // No space left on device
                  return -1;
            }

            char *new_data = offset_to_ptr(fsptr, new_block);
            if (new_data == NULL){
                  *errnoptr = EFAULT;
                  return -1;
            }

            //inatalized new space with zeros
            memset(new_data, 0, additional_size);

            //if there was existing data we need to copy it over
            if (file->data_block != 0){
                  char *old_data = offset_to_ptr(fsptr, file->data_block);
                  if(old_data != NULL){
                        memcpy(new_data, old_data, file->size);
                        free_block(fsptr, file->data_block);
                  }
            }

            file->data_block = new_block; // Link the new block to the file
      }

      // get pointer to file data
      char *file_data = offset_to_ptr(fsptr, file->data_block);
      if (file_data == NULL) {
            *errnoptr = EFAULT; // Filesystem corruption
            return -1;
      }

      //preform write
      memcpy(file_data + offset, buf, size);

      //update file size if needed
      if (required_size > file->size){
            file->size = required_size;
      }

      //update modification and access times
      struct timespec current_time;
      clock_gettime(CLOCK_REALTIME, &current_time);
      file->last_modified_time = current_time;
      file->last_access_time = current_time;

      // Return the number of bytes written
      return size;
}

/* Implements an emulation of the utimensat system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call changes the access and modification times of the file
   or directory indicated by path to the values in ts.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 utimensat.

*/
int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr,
                          const char *path, const struct timespec ts[2]) {
  
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entry for given path
      myfs_file_t *file = find_file(header, path);
      if (file == NULL){
            *errnoptr = ENOENT;
            return -1;
      }

      // Update access and modification times
      file->last_access_time = ts[0]; // Access time
      file->last_modified_time = ts[1]; // Modification time

      return 0;
}

/* Implements an emulation of the statfs system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call gets information of the filesystem usage and puts in 
   into stbuf.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 statfs.

   Essentially, only the following fields of struct statvfs need to be
   supported:

   f_bsize   fill with what you call a block (typically 1024 bytes)
   f_blocks  fill with the total number of blocks in the filesystem
   f_bfree   fill with the free number of blocks in the filesystem
   f_bavail  fill with same value as f_bfree
   f_namemax fill with your maximum file/directory name, if your
             filesystem has such a maximum

*/

/*
In case the struct for statvfs needs to be defined
typedef struct statvfs_struct statvfs;

struct statvfs_struct {
      __fsword_t f_bsize;   // Optimal transfer block size 
      fsblkcnt_t f_blocks;  // Total data blocks in filesystem 
      fsblkcnt_t f_bfree;   // Free blocks in filesystem 
      fsblkcnt_t f_bavail;  // Free blocks available to
                              unprivileged user 
      __fsword_t f_namemax; // Maximum length of filenames 
};
*/

int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr,
                         struct statvfs* stbuf) {

      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      // Populate the statvfs structure
      memset(stbuf, 0, sizeof(struct statvfs)); // Zero out the structure first

      stbuf->f_bsize = header->block_size;      // Block size
      stbuf->f_blocks = header->total_blocks;   // Total blocks in the filesystem
      stbuf->f_bfree = header->free_blocks;     // Free blocks in the filesystem
      stbuf->f_bavail = header->free_blocks;    // Blocks available to unprivileged users
      stbuf->f_namemax = MYFS_MAX_FILENAME;     // Maximum file name length

      // Success
      return 0;
}