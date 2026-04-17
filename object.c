// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Determine the type string for the header
    const char *type_str = "";
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1; // Unknown type

    // 2. Build the header: "<type> <size>\0"
    char header[128];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // 3. Allocate memory for the full object (Header + Data)
    size_t full_size = header_len + len;
    uint8_t *full_data = malloc(full_size);
    if (!full_data) return -1;

    // 4. Copy the header and data into our new buffer
    memcpy(full_data, header, header_len);
    if (len > 0 && data != NULL) {
        memcpy(full_data + header_len, data, len);
    }

    // 5. Compute SHA-256 hash of the FULL object
    compute_hash(full_data, full_size, id_out);

    // 6. Deduplication check: if it already exists, we're done!
    if (object_exists(id_out)) {
        free(full_data);
        return 0; 
    }

    // --- NEW CODE FOR COMMIT 3 STARTS HERE ---

    // 7. Create the shard directory (.pes/objects/XX/)
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path)); 

    char shard_dir[512];
    strncpy(shard_dir, final_path, sizeof(shard_dir));
    // Find the last slash to isolate the directory part
    char *last_slash = strrchr(shard_dir, '/');
    if (last_slash) *last_slash = '\0';

    // Create the directory. Ignore return value because it failing usually just means it already exists.
    mkdir(shard_dir, 0755); 

    // 8. Write to a temporary file in the same shard directory
    char temp_path[1024]; // Using 1024 to prevent the truncation warning!
    snprintf(temp_path, sizeof(temp_path), "%s/temp_write", shard_dir);
    
    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_data);
        return -1;
    }

    ssize_t written = write(fd, full_data, full_size);
    if (written < 0 || (size_t)written != full_size) {
        close(fd);
        unlink(temp_path); // Delete the broken temp file
        free(full_data);
        return -1;
    }

    // 9. fsync() the file, then atomically rename it, then fsync the directory
    fsync(fd);
    close(fd);

    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    // Open the directory and sync it to ensure the rename is saved to the physical disk
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full_data);
    return 0; // Success!
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the file path from the hash
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1; // File not found

    // Seek to the end to find the file size, then rewind to the start
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0) {
        fclose(f);
        return -1;
    }

    // Allocate a temporary buffer for the whole file (header + data)
    uint8_t *full_data = malloc(file_size);
    if (!full_data) {
        fclose(f);
        return -1;
    }

    // Read the file into our buffer
    if (fread(full_data, 1, file_size, f) != (size_t)file_size) {
        free(full_data);
        fclose(f);
        return -1;
    }
    fclose(f);

    // 3. Verify integrity: recompute the SHA-256 and compare
    ObjectID computed_id;
    compute_hash(full_data, file_size, &computed_id);
    if (memcmp(id->hash, computed_id.hash, HASH_SIZE) != 0) {
        free(full_data);
        return -1; // Hash mismatch! Data is corrupted or tampered with.
    }

    // Temporary placeholders to prevent compiler warnings
    (void)type_out;
    (void)data_out;
    (void)len_out;

    free(full_data); // Freeing temporarily
    return -1; // Still returning -1 because we haven't extracted the data yet
}
