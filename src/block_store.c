#include <stdio.h>
#include <stdint.h>
#include "bitmap.h"
#include "block_store.h"
#include <string.h>

// include more if you need

// You might find this handy.  I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)

#define INVALID_MACROS_MSG "\n\tERROR: invalid macros. insure the following:\n\t\tBITMAP_SIZE_BYTES > 0 and divisable by 32\n\t\tBLOCK_SIZE_BYTES  > 0 and divisable by 32\n\t\t0 <= BITMAP_START_BLOCK < BLOCK_STORE_NUM_BLOCKS\n\n" 

bool validMacros()
{
    if(BITMAP_SIZE_BYTES <= 0 || BITMAP_SIZE_BYTES % 32 != 0) return false;
    if(BITMAP_SIZE_BITS != (BITMAP_SIZE_BYTES * 8)) return false;
    if(BLOCK_STORE_NUM_BLOCKS <= 0 || BLOCK_STORE_NUM_BLOCKS % 32 != 0) return false;
    int bitmapSizeBlocks = BITMAP_SIZE_BYTES / BLOCK_SIZE_BYTES;
    if(BITMAP_SIZE_BYTES % BLOCK_SIZE_BYTES) bitmapSizeBlocks++;
    if(BLOCK_STORE_AVAIL_BLOCKS != BLOCK_STORE_NUM_BLOCKS - bitmapSizeBlocks) return false;
    if(BLOCK_SIZE_BYTES <= 0 || BLOCK_SIZE_BYTES % 32 != 0) return false;
    if(BLOCK_SIZE_BITS != BLOCK_SIZE_BYTES * 8) return false;
    if(BLOCK_STORE_NUM_BYTES != BLOCK_STORE_NUM_BLOCKS * BLOCK_SIZE_BYTES) return false;
    if(BITMAP_START_BLOCK < 0 || BITMAP_START_BLOCK >= BLOCK_STORE_NUM_BLOCKS) return false;
    return true;
}

block_store_t *block_store_create()
{
    if(!validMacros()){
        printf(INVALID_MACROS_MSG);
        return NULL;
    }

    int bitmap_blocks_count = BITMAP_SIZE_BYTES / BLOCK_SIZE_BYTES;
    if(BITMAP_SIZE_BYTES % BLOCK_SIZE_BYTES) bitmap_blocks_count++;
    printf("\tbitmap will occupy %d blocks\n", bitmap_blocks_count);

    if(BITMAP_START_BLOCK + bitmap_blocks_count < BLOCK_STORE_NUM_BLOCKS)
    {
        block_store_t *block_store = (block_store_t *) calloc(1, sizeof(block_store_t));
        printf("\tblock store allocated\n");

        block_store->bitmap = bitmap_overlay(BITMAP_SIZE_BITS, &block_store->blocks[BITMAP_START_BLOCK]);
        printf("\tbitmap created\n");

        while(bitmap_blocks_count--) 
        {
            int block_id =  BITMAP_START_BLOCK + bitmap_blocks_count;
            block_store_request(block_store, block_id);
            printf("\tblock %d reserved for bitmap\n", block_id);
        }
        return block_store;
    }
    else
    {
        printf("ERROR: bitmap doesn't fit. Decrese bitmap size or starting block\n");
        return NULL;
    }
}

void block_store_destroy(block_store_t *const bs)
{
    if(bs) //insure bitmap exists
    {
        bitmap_destroy(bs->bitmap); // free bitmap
        free(bs); // free block store
    }
}

size_t block_store_allocate(block_store_t *const bs)
{
    if(bs) //insure block store exists (not null ptr)
    {
        size_t empty = bitmap_ffz(bs->bitmap);
        if(empty < BLOCK_STORE_AVAIL_BLOCKS)
        {
            bitmap_set(bs->bitmap, empty);
            return empty;
        }
    }
    printf("\tERROR: cannot allocate in block store\n");
    return SIZE_MAX;
}

bool block_store_request(block_store_t *const bs, const size_t block_id)
{
    // error checking with bitmap_test, valid params, within range,
    if (bs == NULL || block_id >= BLOCK_STORE_AVAIL_BLOCKS) {
        printf("Error with requesting block store: invalid parameters\n");
        return false;
    }

    if (bitmap_test(bs->bitmap, block_id)) {
        printf("Error with requesting block store: block is taken\n");
        return false;
    }

    bitmap_set(bs->bitmap, block_id);

    return bitmap_test(bs->bitmap, block_id);
}

void block_store_release(block_store_t *const bs, const size_t block_id)
{
    // error checking
    if (bs == NULL || block_id >= BLOCK_STORE_AVAIL_BLOCKS) {
        printf("Error with releasing block store: invalid parameters\n");
        return;
    }

    bitmap_reset(bs->bitmap, block_id);
}

size_t block_store_get_used_blocks(const block_store_t *const bs)
{
    if(bs == NULL) return SIZE_MAX;
    return bitmap_total_set(bs->bitmap);
}

size_t block_store_get_free_blocks(const block_store_t *const bs)
{
    if(bs == NULL) return SIZE_MAX;
    return block_store_get_total_blocks() - block_store_get_used_blocks(bs);
}

size_t block_store_get_total_blocks()
{
    //number of blocks in store - 1 for bitmap
    return BLOCK_STORE_AVAIL_BLOCKS;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer)
{
    if(bs != NULL && block_id < BLOCK_STORE_NUM_BLOCKS && block_id != BITMAP_START_BLOCK && buffer != NULL)
    {
        memcpy(buffer, bs->blocks + block_id, BLOCK_SIZE_BYTES);
        return BLOCK_SIZE_BYTES;
    }
    printf("block_store_read ERROR: inalid perams\n");
    return 0;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer)
{
    if(bs != NULL && block_id < BLOCK_STORE_NUM_BLOCKS && block_id != BITMAP_START_BLOCK && buffer != NULL)
    {
        memcpy(bs->blocks + block_id, buffer, BLOCK_SIZE_BYTES);
        return BLOCK_SIZE_BYTES;
    }
    printf("block_store_write ERROR: inalid perams\n");
    return 0;
}

block_store_t *block_store_deserialize(const char *const filename)
{
    if(filename == NULL) return 0;
    FILE * input = fopen(filename, "r");
    block_store_t * bs = block_store_create(); 
    fread(bs, BLOCK_SIZE_BYTES, BLOCK_STORE_NUM_BLOCKS, input);
    return bs;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename)
{
    if(bs == NULL || filename == NULL) return 0;
    FILE * output = fopen(filename, "w");
    //fwrite returns number of blocks written. Multiply by bytes per block, and return.
    return BLOCK_SIZE_BYTES * fwrite(bs, BLOCK_SIZE_BYTES, BLOCK_STORE_NUM_BLOCKS, output);
}