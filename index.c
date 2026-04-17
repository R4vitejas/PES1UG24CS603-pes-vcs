// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// Example:
//   100644 a1b2c3d4e5f6...  1699900000 42 README.md
//   100644 f7e8d9c0b1a2...  1699900100 128 src/main.c
//
// This is intentionally a simple text format. No magic numbers, no
// binary parsing. The focus is on the staging area CONCEPT (tracking
// what will go into the next commit) and ATOMIC WRITES (temp+rename).
//
// PROVIDED functions: index_find, index_remove, index_status
// TODO functions:     index_load, index_save, index_add

#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

int object_write(ObjectType type, const void *data, size_t len, ObjectID *out_id);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
// Returns 0 on success, -1 if path not in index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

// Print the status of the working directory.
//
// Identifies files that are staged, unstaged (modified/deleted in working dir),
// and untracked (present in working dir but not in index).
// Returns 0.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    // Note: A true Git implementation deeply diffs against the HEAD tree here. 
    // For this lab, displaying indexed files represents the staging intent.
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            // Fast diff: check metadata instead of re-hashing file content
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            // Skip hidden directories, parent directories, and build artifacts
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue; // compiled executable
            if (strstr(ent->d_name, ".o") != NULL) continue; // object files

            // Check if file is tracked in the index
            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1; 
                    break;
                }
            }
            
            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) { // Only list regular files for simplicity
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

// Load the index from .pes/index.
//
// HINTS - Useful functions:
//   - fopen (with "r"), fscanf, fclose : reading the text file line by line
//   - hex_to_hash                      : converting the parsed string to ObjectID
//
// Returns 0 on success, -1 on error.
// Manually declaring object_write to satisfy the compiler
int index_load(Index *index) {
    index->count = 0; // Initialize an empty index

    // 1. Open the index file
    FILE *f = fopen(".pes/index", "r");
    if (!f) {
        // If the file doesn't exist, that's fine! It just means nothing is staged yet.
        return 0; 
    }

    // 2. Read the file line by line
    // Format: <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
    char hex_hash[HASH_HEX_SIZE];
    while (index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *entry = &index->entries[index->count];
        
        // fscanf reads space-separated values. %s reads until the next space.
        // We use %255[^\n] for the path to read everything else on the line, even if the filename has spaces.
        int matched = fscanf(f, "%o %64s %ld %u %255[^\n]", 
                             &entry->mode, hex_hash, &entry->mtime_sec, &entry->size, entry->path);
        
        if (matched != 5) {
            break; // End of file or malformed line
        }

        // Convert the string representation of the hash back into binary bytes
        hex_to_hash(hex_hash, &entry->hash);
        index->count++;
    }

    fclose(f);
    return 0;
}

// Save the index to .pes/index atomically.
//
// HINTS - Useful functions and syscalls:
//   - qsort                            : sorting the entries array by path
//   - fopen (with "w"), fprintf        : writing to the temporary file
//   - hash_to_hex                      : converting ObjectID for text output
//   - fflush, fileno, fsync, fclose    : flushing userspace buffers and syncing to disk
//   - rename                           : atomically moving the temp file over the old index
//
// Returns 0 on success, -1 on error.
// Helper for qsort to sort index entries by path
static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

int index_save(const Index *index) {
    // 1. Create a mutable copy and sort it (Git requirement)
    Index sorted_index = *index;
    qsort(sorted_index.entries, sorted_index.count, sizeof(IndexEntry), compare_index_entries);

    // 2. Open temporary file
    FILE *f = fopen(".pes/index.tmp", "w");
    if (!f) return -1;

    // 3. Write entries in text format
    for (int i = 0; i < sorted_index.count; i++) {
        IndexEntry *e = &sorted_index.entries[i];
        char hex[HASH_HEX_SIZE];
        hash_to_hex(&e->hash, hex);

        fprintf(f, "%o %s %ld %u %s\n", 
                e->mode, hex, e->mtime_sec, e->size, e->path);
    }

    // 4. Ensure data is physically on disk (The "Atomic" part)
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    // 5. Atomic swap: rename temp file to the real index file
    if (rename(".pes/index.tmp", ".pes/index") != 0) {
        unlink(".pes/index.tmp");
        return -1;
    }

    return 0;
}

// Stage a file for the next commit.
//
// HINTS - Useful functions and syscalls:
//   - fopen, fread, fclose             : reading the target file's contents
//   - object_write                     : saving the contents as OBJ_BLOB
//   - stat / lstat                     : getting file metadata (size, mtime, mode)
//   - index_find                       : checking if the file is already staged
//
// Returns 0 on success, -1 on error.
int index_add(Index *index, const char *path) {
    // 1. Get file metadata (mode, size, mtime)
    struct stat st;
    if (lstat(path, &st) != 0) {
        perror("stat");
        return -1;
    }

    // 2. Read file content
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    void *buf = malloc(st.st_size);
    if (!buf) { fclose(f); return -1; }
    
    if (fread(buf, 1, st.st_size, f) != (size_t)st.st_size) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    // 3. Write content to object store and get the hash (ObjectID)
    ObjectID hash;
    if (object_write(OBJ_BLOB, buf, st.st_size, &hash) != 0) {
        free(buf); return -1;
    }
    free(buf);

    // 4. Update existing entry OR add a new one
    IndexEntry *entry = index_find(index, path);
    if (!entry) {
        if (index->count >= MAX_INDEX_ENTRIES) return -1;
        entry = &index->entries[index->count++];
        strncpy(entry->path, path, sizeof(entry->path) - 1);
        entry->path[sizeof(entry->path) - 1] = '\0';
    }

    // 5. Cache the metadata (this is what lets index_status run fast!)
    entry->mode = st.st_mode;
    entry->hash = hash;
    entry->mtime_sec = (long)st.st_mtime;
    entry->size = (uint32_t)st.st_size;

    // 6. Save the index back to disk atomically
    return index_save(index);
}
