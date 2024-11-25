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
static inline void offset_to_ptr(void *fsptr, myfs_offset_t offset) {
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
      //check if mem region is large enough for header plus root dir
      if (fssize < sizeof(myfs_header_t) + MYFS_BLOCK_SIZE) {
            return -1;
      }

      //initialize fs header
      myfs_header_t *header = (myfs_header_t *)fsptr;
      //set magic number
      header->magic = MAGIC_NUM;
      //set block size
      header->block_size = MYFS_BLOCK_SIZE;

      //calcluate the total blocks (subtract header size from total size and then divide by block sinxe to get the num of blocks)
      header->total_blocks = (fssize - sizeof(myfs_header_t)) / MYFS_BLOCK_SIZE;
      //set free blocks to total blocks and remove one for the root
      header->free_blocks = header->total_blocks - 1;

      //set root dir location
      header->root_dir = sizeof(myfs_header_t);

      //set first free block list which starts after the root dir
      header->free_list = header->root_dir + sizeof(myfs_file_t);

      //initalize first free block
      //get ptr to first free block using the offset
      myfs_block_header_t *first_free_block = offset_to_ptr(fsptr, header->free_list);
      //set next to zero since this is one big free splace block
      first_free_block->next = 0;
      first_free_block->size = (header->total_blocks - 1) * MYFS_BLOCK_SIZE;

      //set root dir
      //get ptr to root dir using offset
      myfs_file_t *root_dir = offset_to_ptr(fsptr, header->root_dir);
      //cleat all mem for root dir struct
      memset(root_dir, 0, sizeof(myfs_file_t));
      //set root dir struct attributes
      strcpy(root_dir->name, "/");
      root_dir->type = MYFS_TYPE_DIR;
      root_dir->next = 0;
      root_dir->parent = 0;
      root_dir->size = 0;
      root_dir->data_block = 0;
      //set time stanps
      root_dir->last_access_time.tv_sec = 0;
      root_dir->last_access_time.tv_nsec =0;
      root_dir->last_modified_time.tv_sec = 0;
      root_dir->last_modified_time.tv_nsec =0;
      return 0;
}

//function to check if the filestysem is already initalized
static int is_initialized(void *fsptr, size_t fssize) {
      //check pointer and size are good
      if (fsptr == NULL || fssize < sizeof(myfs_header_t)) {
            return 0;
      }
      //get header
      myfs_header_t *header = (myfs_header_t *)fsptr;
      //check if initialized
      return (header->magic == MAGIC_NUM);
}

//fucntion to intialize if needed and return header
static myfs_header_t *get_fs_header(void *fsptr, size_t fssize, int *errnoptr) {
      //check if initialized
      if (!is_initialized(fsptr, fssize)) {
            //initialize
            if (intalize_filesystem(fsptr, fssize) != 0) {
                  //error
                  *errnoptr = EFAULT;
                  return NULL;
            }
      }
      //get header
      return (myfs_header_t *)fsptr;
}

/*

FUNCTIONS FOR MEMORY ALLOCATION

*/

//function to free a block of mem
static void free_block(void *fsptr, myfs_offset_t offset) {
      if(offset == 0) {
            return;
      }

      //get fs header
      myfs_header_t *header = (myfs_header_t *)fsptr;

      //find the start of the block
      myfs_offset_t block_start = offset - sizeof(myfs_block_header_t);

      //get ptr to block header
      myfs_block_header_t *block_header = offset_to_ptr(fsptr, block_start);

      //add block to the beginning of the free list like adding to the start of a linked list
      //point to curr first block
      block_header->next = header->free_list;
      //set new first block to the block we just added
      header->free_list = block_start;
      //update data
      header->free_blocks++;
}

//function to allocate a block of mem given the fsptr and the size of mem wanted
static myfs_offset_t allocate_block(void *fsptr, size_t size) {
      //get fs header
      myfs_header_t *header = (myfs_header_t *)fsptr;

      //keep track of curr and prev blocks while traversing the free list
      myfs_offset_t curr_block_offset = header->free_list;
      myfs_offset_t prev_block_offset = 0;

      //get total size needed including the size of mem wanted and the block header
      size_t required_size = size + sizeof(myfs_block_header_t);

      //get the nearest block size
      required_size = ((required_size + MYFS_BLOCK_SIZE - 1) / MYFS_BLOCK_SIZE) * MYFS_BLOCK_SIZE;

      //traverse the free list until we find a blog big enough for spaced needed
      while (curr_block_offset != 0) {
            //get ptr to curr block
            myfs_block_header_t *curr_block_ptr = offset_to_ptr(fsptr, curr_block_offset);

            //check if block is big enough
            if (curr_block_ptr->size >= required_size) {
                  
                  //if it was first block then next becomes first
                  if(prev_block_offset == 0){
                        //set new first block
                        header->free_list = curr_block_ptr->next;
                  }
                  else{
                        //link prev to next
                        myfs_block_header_t *prev_block_ptr = offset_to_ptr(fsptr, prev_block_offset);
                        prev_block_ptr->next = curr_block_ptr->next;
                  }

                  //udate fs data
                  header->free_blocks--;
                  //mark the block as used
                  curr_block_ptr->next = 0;

                  //return offset to usable mem
                  return curr_block_offset + sizeof(myfs_block_header_t);
            }

            //update prev and curr
            prev_block_offset = curr_block_offset;
            curr_block_offset = curr_block_ptr->next;
      }

      //no block big enough found
      return 0;
}     

/*

FUNCTIONS FOR PATHS

*/

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
      //check if initialized
      myfs_header_t *header = get_fs_header(fsptr, fssize, errnoptr);
      if(header == NULL){
            *errnoptr = EFAULT;
            return -1;
      }

      //find the file/dir entru for given path
      myfs_file_t *entry = 
      if (entry == NULL){
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
            stbuf->st_mode = S_IFDIR;

            //ncount links start wirh 2 for "." and ".." entries
            stbuf -> st_nlink = 2;

            //count all subdir in this dir, each subsir adds a link because of its ..
            myfs_offset_t child_offset = entry->data_block
            while (child_offset != 0){
                  myfs_file_t *child_entry_file = offset_to_ptr(fsptr, child);
                  if (child_entry_file->type == MYFS_TYPE_DIR){
                        stbuf -> st_nlink++;
                  }
                  child_offset = child_entry -> next;
            }

            //dir dont have a size
            stbuf->st_size = 0;
      }
      //its a file
      else{

            stbuf -> st_mode = S_IFREG;

            //reg files have on line
            stbuf->st_nlink = 1;

            //set size
            stbuf->st_size = entry->size
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
  /* STUB */
  return -1;
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
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  /* STUB */
  return -1;
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
  /* STUB */
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
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  /* STUB */
  return -1;
}

/* Implements an emulation of the mkdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.

*/
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
  /* STUB */
  return -1;
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
int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr,
                         struct statvfs* stbuf) {
  /* STUB */
  return -1;
}
