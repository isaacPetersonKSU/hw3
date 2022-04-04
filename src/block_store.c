#include <stdio.h>
#include <stdint.h>
#include "bitmap.h"
#include "block_store.h"
#include <string.h>

// include more if you need

// You might find this handy.  I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)

block_store_t *block_store_create()
{
    block_store_t *block_store = (block_store_t *) calloc(1, sizeof(block_store_t));
    printf("\tblock store allocated\n");
    
    block_store->bitmap = bitmap_overlay(BITMAP_SIZE_BITS, &block_store->blocks[BITMAP_START_BLOCK]);
    printf("\tbitmap %08x created at block block %d\n", *bitmap_export(block_store->bitmap), BITMAP_START_BLOCK);

    return block_store;
}

void block_store_destroy(block_store_t *const bs)
{
    // error check
    if (bs == NULL) {
        printf("Error with destroying block store: block store is empty\n");
        return;
    }

    bitmap_destroy(bs->bitmap); // free bitmap
    free(bs); // free block store
}

size_t block_store_allocate(block_store_t *const bs)
{
    // error checking (null, make sure after ffz that the block is valid block within (BLOCK_STORE_NUM_BLOCKS))
    if (bs == NULL) {
        printf("ERROR: Unable to allocate blocks in NULL Block Store\n");
        return SIZE_MAX;
    }

    size_t empty = bitmap_ffz(bs->bitmap);
    if(empty < BLOCK_STORE_AVAIL_BLOCKS)
    {
        bitmap_set(bs->bitmap, empty);
        return empty;
    }
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
    return BLOCK_STORE_AVAIL_BLOCKS - bitmap_total_set(bs->bitmap);
}

size_t block_store_get_total_blocks()
{
    return BLOCK_STORE_AVAIL_BLOCKS;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer)
{
    if(bs != NULL && block_id < BLOCK_STORE_AVAIL_BLOCKS && buffer != NULL)
    {
        size_t block_index = block_id;
        if(block_index >= BITMAP_START_BLOCK) block_index++;

        memcpy(buffer, bs->blocks + block_index, BLOCK_SIZE_BYTES);
        return BLOCK_SIZE_BYTES;
    }
    printf("block_store_read ERROR: inalid perams\n");
    return 0;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer)
{
    if(bs != NULL && block_id < BLOCK_STORE_AVAIL_BLOCKS && buffer != NULL)
    {
        size_t block_index = block_id;
        if(block_index >= BITMAP_START_BLOCK) block_index++;

        memcpy(bs->blocks + block_index, buffer, BLOCK_SIZE_BYTES);
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
    return BLOCK_SIZE_BYTES * fwrite(bs, BLOCK_SIZE_BYTES, BLOCK_STORE_NUM_BLOCKS, output);
}