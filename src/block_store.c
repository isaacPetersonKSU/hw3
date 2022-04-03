#include <stdio.h>
#include <stdint.h>
#include "bitmap.h"
#include "block_store.h"
// include more if you need

// You might find this handy.  I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)

block_store_t *block_store_create()
{
    // calloc memory for the block store
    block_store_t *block_store = (block_store_t *) calloc(1, sizeof(block_store_t));
    // create and store the bitmap in block 127
    block_store->bitmap = bitmap_overlay(BITMAP_SIZE_BITS, &block_store->blocks[BITMAP_START_BLOCK]);

    // confirm that the block store was created successfully
    for (int i = BITMAP_START_BLOCK; i <= BITMAP_START_BLOCK + BLOCK_STORE_NUM_BLOCKS; i++) {
        if (block_store_request(block_store, i) == false) {
            printf("Error with requested block at location: %d", i);
            break;
        }
    }
    return block_store;
}

void block_store_destroy(block_store_t *const bs)
{
    // error check
    if (bs == NULL) {
        printf("Error with destroying block store: block store is empty");
        return;
    }

    bitmap_destroy(bs->bitmap); // free bitmap
    free(bs); // free block store
}

size_t block_store_allocate(block_store_t *const bs)
{
    // error checking (null, make sure after ffz that the block is valid block within (BLOCK_STORE_NUM_BLOCKS))
    if (bs == NULL) {
        printf("Error with allocating block store: block store is empty");
        return 0;
    }

    size_t empty = bitmap_ffz(bs->bitmap);

    // error check
    if (empty > BLOCK_STORE_NUM_BLOCKS) {
        printf("Error with allocating block store: bit is outside of range");
        return 0;
    }

    bitmap_set(bs->bitmap, empty);
    return empty;
}

bool block_store_request(block_store_t *const bs, const size_t block_id)
{
    // error checking with bitmap_test, valid params, within range,
    if (bs == NULL || block_id == 0) {
        printf("Error with requesting block store: invalid parameters");
        return false;
    }

    if (bitmap_test(bs->bitmap, block_id)) {
        printf("Error with requesting block store: block is taken");
        return false;
    }

    bitmap_set(bs->bitmap, block_id);

    if (bitmap_test(bs->bitmap, block_id)) return true;

    printf("Error with requesting block store: end of method");
    return false;
}

void block_store_release(block_store_t *const bs, const size_t block_id)
{
    // error checking
    if (bs == NULL || block_id == 0) {
        printf("Error with releasing block store: invalid parameters");
        return;
    }

    bitmap_reset(bs->bitmap, block_id);
}

size_t block_store_get_used_blocks(const block_store_t *const bs)
{
    UNUSED(bs);
    return 0;
}

size_t block_store_get_free_blocks(const block_store_t *const bs)
{
    UNUSED(bs);
    return 0;
}

size_t block_store_get_total_blocks()
{
    return 0;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer)
{
    UNUSED(bs);
    UNUSED(block_id);
    UNUSED(buffer);
    return 0;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer)
{
    UNUSED(bs);
    UNUSED(block_id);
    UNUSED(buffer);
    return 0;
}

block_store_t *block_store_deserialize(const char *const filename)
{
    UNUSED(filename);
    return NULL;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename)
{
    UNUSED(bs);
    UNUSED(filename);
    return 0;
}