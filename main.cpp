#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <map>
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include "crc32.h"

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/********************************
* arcshark Structs/Definitions  *
*********************************/

enum ArcVersion
{
    ARC_100,
    ARC_110,
    ARC_200,
    ARC_300,
};

enum FileChunkType
{
    FileChunkType_OrigData,
    FileChunkType_SD,
};

struct FileChunk
{
    FileChunkType type;
    uint64_t offset;
    uint64_t size;
};

std::map<uint64_t, FileChunk> chunks;

/*******************************
* Offset4 Structs/Definitions  *
*******************************/

#define TREE_ALIGN_MASK           0x0fffe0
#define TREE_ALIGN_LSHIFT         (5)
#define TREE_FILESLICE_MASK       0x000003
#define TREE_FILESLICE_IDX        0x000000
#define TREE_FILESLICE_EXT_ADD1   0x000001
#define TREE_FILESLICE_EXT_ADD2   0x000002
#define TREE_REDIR                0x200000
#define TREE_UNK                  0x100000

#define FILESLICE_TREE_IDX_MASK     0x00FFFFFF
#define FILESLICE_REDIR             0x40000000
#define FILESLICE_UNK_BIT29         0x20000000
#define FILESLICE_UNK_BIT27         0x08000000
#define FILESLICE_UNK_BIT26         0x04000000

#define CURSED_FILESLICES (arc_version == ARC_100 || arc_version == ARC_110)

#define FILESLICE_100_COMPRESSION       0x07000000
#define FILESLICE_100_DECOMPRESSED      0x00000000
#define FILESLICE_100_UND               0x01000000
#define FILESLICE_100_COMPRESSED_LZ4    0x02000000
#define FILESLICE_100_COMPRESSED_ZSTD   0x03000000

#define FILESLICE_200_COMPRESSION       0x00000007
#define FILESLICE_200_DECOMPRESSED      0x00000000
#define FILESLICE_200_UND               0x00000001
#define FILESLICE_200_COMPRESSED_LZ4    0x00000002
#define FILESLICE_200_COMPRESSED_ZSTD   0x00000003

#define FILESLICE_COMPRESSION       (CURSED_FILESLICES ? FILESLICE_100_COMPRESSION : FILESLICE_200_COMPRESSION)
#define FILESLICE_DECOMPRESSED      (CURSED_FILESLICES ? FILESLICE_100_DECOMPRESSED : FILESLICE_200_DECOMPRESSED)
#define FILESLICE_UND               (CURSED_FILESLICES ? FILESLICE_100_UND : FILESLICE_200_UND)
#define FILESLICE_COMPRESSED_LZ4    (CURSED_FILESLICES ? FILESLICE_100_COMPRESSED_LZ4 : FILESLICE_200_COMPRESSED_LZ4)
#define FILESLICE_COMPRESSED_ZSTD   (CURSED_FILESLICES ? FILESLICE_100_COMPRESSED_ZSTD : FILESLICE_200_COMPRESSED_ZSTD)

//#define VERBOSE_PRINT

typedef struct offset4_header
{
    uint32_t total_size;
    uint32_t folder_tree_entries;
    uint32_t entries_folderchunks_1;
    uint32_t file_tree_entries;
    
    uint32_t fileslice_entries;
    uint32_t file_lookup_entries;
    uint32_t folder_hash_entries;
    uint32_t file_tree_entries_2;
    
    uint32_t entries_folderchunks_2;
    uint32_t post_fileslice_entries;
    uint32_t alloc_alignment;
    uint32_t unk10;
    
    uint8_t weird_hash_entries;
    uint8_t unk11;
    uint8_t unk12;
    uint8_t unk13;
} offset4_header;

typedef struct offset4_header_200
{
    uint32_t total_size;
    uint32_t file_lookup_entries;
    uint32_t unk08;
    uint32_t folder_tree_entries;
    
    uint32_t entries_folderchunks_1;
    uint32_t folder_hash_entries;
    uint32_t unk18;
    uint32_t unk1C;
    
    uint32_t fileslice_entries;
    uint32_t entries_folderchunks_2;
    uint32_t post_fileslice_entries;
    uint32_t unk2C;
    
    uint32_t alloc_alignment;
    uint32_t unk34;
    
    uint8_t size_3_entries;
    uint8_t unk39;
    uint8_t unk3A;
    uint8_t unk3B;
} offset4_header_200;

typedef struct offset4_headerext_300
{
    uint16_t unk0;
    uint16_t unk2;
    uint32_t unk4;
    uint32_t unk8;
    uint32_t unkC;
    uint32_t unk10;
    uint32_t unk14;
    uint32_t unk18;
} offset4_headerext_300;

typedef struct offset4_ext_header
{
    uint32_t bgm_unk_movie_entries;
    uint32_t entries;
    uint32_t entries_2;
    uint32_t num_files;
} offset4_ext_header;

typedef struct entry_triplet
{
    uint64_t hash : 40;
    uint64_t meta : 24;
    uint32_t meta2;
} __attribute__((packed)) entry_triplet;

typedef struct entry_pair
{
    uint64_t hash : 40;
    uint64_t meta : 24;
} __attribute__((packed)) entry_pair;

typedef struct file_pair
{
    uint64_t size;
    uint64_t offset;
} file_pair;

typedef struct folder_tree_entry
{
    entry_pair path;
    entry_pair folder;
    entry_pair parent;
    entry_pair hash4;
    union
    {
        uint32_t fileslice_start;
        uint32_t indexing_start;
    };
    uint32_t num_files;
    uint32_t subfolderlookup_start_idx;
    uint16_t num_folders;
    uint16_t tree_start;
    uint8_t unk6;
    uint8_t unk7;
    uint8_t unk8;
    uint8_t unk9;
} folder_tree_entry;

typedef struct folder_chunk_entry
{
    uint64_t offset;
    uint32_t memory_size;
    uint32_t file_size;
    uint32_t fileslice_index;
    uint32_t files;
    uint32_t unk3;
} __attribute__((packed)) folder_chunk_entry;

typedef struct file_slice
{
    uint32_t offset;
    uint32_t comp_size;
    uint32_t decomp_size;
    uint32_t flags;
} file_slice;

typedef struct file_tree_entry
{
    entry_pair path;
    entry_pair ext;
    entry_pair folder;
    entry_pair file;
    uint32_t fileslice_index;
    uint32_t flags;
} file_tree_entry;

typedef struct file_tree_entry_200
{
    entry_pair path;
    entry_pair ext;
    entry_pair folder;
    entry_pair file;
} file_tree_entry_200;

typedef struct hash_bucket
{
    uint32_t index;
    uint32_t num_entries;
} hash_bucket;

typedef struct indexing_helper_struct
{
    uint32_t file_tree_entry_idx;
    uint32_t folder_tree_entry_idx;
    uint32_t file_offset_helper_idx;
    uint32_t flags;
} indexing_helper_struct;

typedef struct file_offset_helper_struct
{
    uint32_t folderchunk_idx;
    uint32_t fileslice_idx;
    uint32_t flags;
} file_offset_helper_struct;

typedef struct folder_and_indexing
{
    uint32_t folder_idx;
    uint32_t indexing_idx;
} folder_and_indexing;

typedef struct offset4_structs
{
    void* off4_data;
    offset4_header* header;
    offset4_header_200* header_200;
    offset4_headerext_300* headerext_300;
    offset4_ext_header* ext_header;
    entry_triplet* bulkfile_category_info;
    entry_pair* bulkfile_hash_lookup;
    entry_triplet* bulk_files_by_name;
    uint32_t* bulkfile_lookup_to_fileidx;
    file_pair* file_pairs;
    entry_triplet* weird_hashes;
    folder_tree_entry* folder_tree_entries;
    folder_chunk_entry* folder_chunks;
    entry_pair* folder_hash_lookup;
    file_tree_entry* file_tree_entries;
    file_slice* fileslice_entries;
    entry_pair* folder_to_folder_tree;
    hash_bucket* file_lookup_buckets;
    entry_pair* file_lookup;
    entry_pair* numbers3;
    
    file_tree_entry_200* file_tree_entries_200;
    indexing_helper_struct* indexing_helper;
    file_offset_helper_struct* file_offset_helper;
    folder_and_indexing* folder_and_indexing_from_tree;
} offset4_structs;

/*******************
* Offset5 Structs  *
********************/

typedef struct offset5_header
{
    uint64_t total_size;
    uint32_t folder_entries;
    uint32_t file_entries;
    uint32_t hash_entries;
} offset5_header;

typedef struct mini_folder_tree_entry
{
    entry_pair path;
    entry_pair parent;
    entry_pair folder;
    uint32_t idx1;
    uint32_t idx2;
} mini_folder_tree_entry;

typedef struct mini_file_tree_entry
{
    entry_pair path;
    entry_pair folder;
    entry_pair file;
    entry_pair ext;
} mini_file_tree_entry;

typedef struct offset5_structs
{
    void* off5_data;
    offset5_header* header;
    entry_pair* folderhash_to_foldertree;
    mini_folder_tree_entry* folder_tree;
    entry_pair* entries_13;
    uint32_t* numbers;
    mini_file_tree_entry* file_tree_entries;
} offset5_structs;

/**********************
* ARC header structs  *
**********************/

typedef struct arc_header
{
    uint64_t magic;
    uint64_t offset_1;
    uint64_t offset_2;
    uint64_t offset_3;
    uint64_t offset_4;
    uint64_t offset_5;
    uint64_t offset_6;
} arc_header;

typedef struct arc_section
{
    uint32_t data_start;
    uint32_t decomp_size;
    uint32_t comp_size;
    uint32_t zstd_comp_size;
} arc_section;

/***********
* Globals  *
************/
FILE* arc_file;
arc_header arc_head;
offset4_structs off4_structs;
offset5_structs off5_structs;
ZSTD_DStream* dstream;
int arc_version = ARC_100;

/*********************
* Hash40/ZSTD utils  *
**********************/
std::map<uint32_t, std::string> unhash;

uint64_t hash40(const void* data, size_t len)
{
    return crc32(data, len) | (len & 0xFF) << 32;
}

int hash40_compar(const void* a, const void* b)
{
    uint64_t hash1 = *(uint64_t*)a & 0xFFFFFFFFFFLL;
    uint64_t hash2 = *(uint64_t*)b & 0xFFFFFFFFFFLL;

    if (hash1 < hash2) return -1;
    else if (hash1 == hash2) return 0;
    else return 1;
}

void hash40_store_init()
{
    std::ifstream strings("hashstrings.txt");
    std::string line;
    while (std::getline(strings, line))
    {
        uint64_t crc = hash40((const void*)line.c_str(), strlen(line.c_str()));
        unhash[crc] = line;
    }
}

void zstd_init()
{
    dstream = ZSTD_createDStream();
    size_t const initResult = ZSTD_initDStream(dstream);
}

void zstd_deinit()
{
    ZSTD_freeDStream(dstream);
}

bool zstd_decomp(void* comp, void* decomp, uint32_t comp_size, uint32_t decomp_size)
{
    ZSTD_resetDStream(dstream);

    ZSTD_inBuffer input = {comp, comp_size, 0};
    ZSTD_outBuffer output = {decomp, decomp_size, 0};

    size_t decompressed = ZSTD_decompressStream(dstream, &output, &input);
    if (ZSTD_isError(decompressed))
    {
        printf("err %s\n", ZSTD_getErrorName(decompressed));
        return false;
    }
    
    return true;
}

/**************************
* Struct print functions  *
**************************/

void print_entry_pair(entry_pair* pair)
{
    printf("%010llx %06llx (%s)\n", pair->hash, pair->meta, unhash[pair->hash].c_str());
}

void print_entry_triplet(entry_triplet* triplet)
{
    printf("%010llx %06llx %08x (%s)\n", triplet->hash, triplet->meta, triplet->meta2, unhash[triplet->hash].c_str());
}

void print_file_tree_entry(file_tree_entry* entry)
{
    printf("%06x: ", entry - off4_structs.file_tree_entries);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->ext);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
    printf("        fileslice index %08x flags %08x\n", entry->fileslice_index, entry->flags);
}

void print_file_tree_entry_200(file_tree_entry_200* entry)
{
    printf("%06x: ", entry - off4_structs.file_tree_entries_200);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->ext);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
}

void print_mini_folder_tree_entry(mini_folder_tree_entry* entry)
{
    printf("%06x: ", entry - off5_structs.folder_tree);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->parent);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        %08x %08x\n", entry->idx1, entry->idx2);
}

void print_mini_file_tree_entry(mini_file_tree_entry* entry)
{
    printf("%06x: ", entry - off5_structs.file_tree_entries);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
    printf("        ");
    print_entry_pair(&entry->ext);
}

void print_folder_tree_entry(folder_tree_entry* entry)
{
    printf("path %010llx %06llx, ", entry->path.hash, entry->path.meta);
    printf("folder %010llx %06llx, ", entry->folder.hash, entry->folder.meta);
    printf("parent %010llx %06llx, ", entry->parent.hash, entry->parent.meta);
    printf("hash4 %010llx %06llx, ", entry->hash4.hash, entry->hash4.meta);
    if (arc_version == ARC_100 || arc_version == ARC_110)
        printf("fileslice ");
    else
        printf("indexing idx ");
    printf("%08x files %08x subfolderlookup_start_idx %08x folders %04x tree_start %04x %02x %02x %02x %02x (path %s, folder %s, parent %s, %s)\n", entry->fileslice_start, entry->num_files, entry->subfolderlookup_start_idx, entry->num_folders, entry->tree_start, entry->unk6, entry->unk7, entry->unk8, entry->unk9, unhash[entry->path.hash].c_str(), unhash[entry->folder.hash].c_str(), unhash[entry->parent.hash].c_str(), unhash[entry->hash4.hash].c_str());
}

void print_folder_chunk(folder_chunk_entry* entry)
{
    //if (!entry->file_size || entry->unk3 != 0xffffff) return;

    printf("%016llx memory_size %08x file_size %08x fileslice_index %08x files %08x unk3 %08x\n", entry->offset, entry->memory_size, entry->file_size, entry->fileslice_index, entry->files, entry->unk3);
#if 0
    uint64_t calc_comp = 0;
    uint64_t calc_decomp = 0;

    file_slice* first = &off4_structs.fileslice_entries[entry->fileslice_index];    
    file_slice* last = &off4_structs.fileslice_entries[entry->fileslice_index+entry->files-1];
    calc_comp = last->offset * 4 + (last->comp_size + 0xf) & ~0xf;
    
    for (int i = 0; i < entry->files; i++)
    {
        int fileslice_index = entry->fileslice_index+i;
        file_slice* fileslice = &off4_structs.fileslice_entries[fileslice_index];
        
        if (fileslice->flags & FILESLICE_REDIR)
        {
            fileslice_index += (fileslice->flags & FILESLICE_TREE_IDX_MASK);
            fileslice = &off4_structs.fileslice_entries[fileslice_index];
        }
        
        uint64_t decomp = fileslice->decomp_size;
        uint64_t decomp_aligned_100 = (decomp + 0xff) & ~0xff;
        uint64_t decomp_aligned_8 = (decomp + 0x7) & ~0x7;

        printf("    %x: %llx %llx %x\n", fileslice_index, fileslice->offset * 4, decomp, fileslice->flags);
        
        if (i != entry->files-1)
        {
            calc_decomp += decomp + 0x80;
        }
        else
        {
            calc_decomp += decomp_aligned_8;
        }
    }
    
    calc_decomp = (calc_decomp + 0x7) & ~0x7;
    
    printf("%llx %llx\n", calc_comp, calc_decomp);
#endif
}

void print_fileslice(file_slice* entry)
{
    printf("%08x %08x %08x %08x\n", entry->offset, entry->comp_size, entry->decomp_size, entry->flags);
}

void print_100_110()
{
    printf("Category hash to bulkfile count and idx:\n");
    for (int i = 0; i < off4_structs.ext_header->bgm_unk_movie_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_triplet(&off4_structs.bulkfile_category_info[i]);
#endif
    }
    
    printf("Bulkfile hash to bulkfile lookup:\n");
    
    for (int i = 0; i < off4_structs.ext_header->entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.bulkfile_hash_lookup[i]);
#endif
    }
    
    printf("Bulkfile lookup:\n");
    for (int i = 0; i < off4_structs.ext_header->entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_triplet(&off4_structs.bulk_files_by_name[i]);
#endif
    }
    
    printf("Bulkfile lookup to bulkfile table index:\n");
    for (int i = 0; i < off4_structs.ext_header->entries_2; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x\n", i, off4_structs.bulkfile_lookup_to_fileidx[i]);
#endif
    }
    
    printf("Bulkfile Table:\n");
    for (int i = 0; i < off4_structs.ext_header->num_files; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: size %016llx offs %016llx\n", i, off4_structs.file_pairs[i].size, off4_structs.file_pairs[i].offset);
#endif
    }
    
    printf("Weird hash table:\n");
    for (int i = 0; i < off4_structs.header->weird_hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_triplet(&off4_structs.weird_hashes[i]);
#endif
    }
    
    printf("Folder Tree Entries:\n");
    for (int i = 0; i < off4_structs.header->folder_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_folder_tree_entry(&off4_structs.folder_tree_entries[i]);
#endif
    }

    printf("Folder chunk entries:\n");
#ifdef VERBOSE_PRINT
    for (int i = 0; i < off4_structs.header->entries_folderchunks_1 + off4_structs.header->entries_folderchunks_2; i++)
    {
        printf("%06x: ", i);
        print_folder_chunk(&off4_structs.folder_chunks[i]);
    }
#endif
    
    printf("Folder Hash table:\n");
    for (int i = 0; i < off4_structs.header->folder_hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_hash_lookup[i]);
#endif
    }
    
    printf("File Tree Entries:\n");
    for (int i = 0; i < off4_structs.header->file_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        print_file_tree_entry(&off4_structs.file_tree_entries[i]);
#endif
    }
    
    printf("Fileslice table:\n");
    for (int i = 0; i < off4_structs.header->fileslice_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_fileslice(&off4_structs.fileslice_entries[i]);
#endif
    }
    
    printf("Folder to folder tree lookup:\n");
    for (int i = 0; i < off4_structs.header->folder_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_to_folder_tree[i]);
#endif
    }

    printf("File->fileslice index lookup buckets: total hashes %08x buckets %08x\n", off4_structs.file_lookup_buckets->index, off4_structs.file_lookup_buckets->num_entries);
    // off4_structs.numbers[hash % table_size].first is lookup start index
    // off4_structs.numbers[hash % table_size].second is lookup search length
    for (int i = 1; i < off4_structs.file_lookup_buckets->num_entries+1; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x\n", i, off4_structs.file_lookup_buckets[i].index, off4_structs.file_lookup_buckets[i].num_entries);
#endif
    }
    
    printf("File->fileslice index lookup table:\n");
    for (int i = 0; i < off4_structs.header->file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.file_lookup[i]);
#endif
    }
    
    printf("Numbers 3:\n");
    for (int i = 0; i < off4_structs.header->file_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.numbers3[i]);
#endif
    }
}

void print_200()
{
#if 0
    printf("Category hash to bulkfile count and idx:\n");
    for (int i = 0; i < off4_structs.ext_header->bgm_unk_movie_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_triplet(&off4_structs.bulkfile_category_info[i]);
#endif
    }
    
    printf("Bulkfile hash to bulkfile lookup:\n");
    
    for (int i = 0; i < off4_structs.ext_header->entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.bulkfile_hash_lookup[i]);
#endif
    }
    
    printf("Bulkfile lookup:\n");
    for (int i = 0; i < off4_structs.ext_header->entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_triplet(&off4_structs.bulk_files_by_name[i]);
#endif
    }
    
    printf("Bulkfile lookup to bulkfile table index:\n");
    for (int i = 0; i < off4_structs.ext_header->entries_2; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x\n", i, off4_structs.bulkfile_lookup_to_fileidx[i]);
#endif
    }
    
    printf("Bulkfile Table:\n");
    for (int i = 0; i < off4_structs.ext_header->num_files; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: size %016llx offs %016llx\n", i, off4_structs.file_pairs[i].size, off4_structs.file_pairs[i].offset);
#endif
    }
#endif
    printf("Folder Tree Entries:\n");
    for (int i = 0; i < off4_structs.header_200->folder_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_folder_tree_entry(&off4_structs.folder_tree_entries[i]);
#endif
    }

    printf("Folder chunk entries:\n");
#ifdef VERBOSE_PRINT
    for (int i = 0; i < off4_structs.header_200->entries_folderchunks_1 + off4_structs.header_200->entries_folderchunks_2; i++)
    {
        printf("%06x: ", i);
        print_folder_chunk(&off4_structs.folder_chunks[i]);
    }
#endif
    
    printf("Folder Hash table:\n");
    for (int i = 0; i < off4_structs.header_200->folder_hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_hash_lookup[i]);
#endif
    }
    
    printf("File Tree Entries:\n");
    for (int i = 0; i < off4_structs.header_200->file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        print_file_tree_entry_200(&off4_structs.file_tree_entries_200[i]);
#endif
    }
    
    printf("Folder to folder tree lookup:\n");
    for (int i = 0; i < off4_structs.header_200->folder_tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_to_folder_tree[i]);
#endif
    }

    printf("File->fileslice index lookup buckets: total hashes %08x buckets %08x\n", off4_structs.file_lookup_buckets->index, off4_structs.file_lookup_buckets->num_entries);
    // off4_structs.numbers[hash % table_size].first is lookup start index
    // off4_structs.numbers[hash % table_size].second is lookup search length
    for (int i = 1; i < off4_structs.file_lookup_buckets->num_entries+1; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x\n", i, off4_structs.file_lookup_buckets[i].index, off4_structs.file_lookup_buckets[i].num_entries);
#endif
    }
    
    printf("File->fileslice index lookup table:\n");
    for (int i = 0; i < off4_structs.header_200->file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.file_lookup[i]);
#endif
    }
    
    printf("Tree path meta to folder and indexing helper:\n");
    for (int i = 0; i < off4_structs.header_200->unk08; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("folder idx: %08x indexing idx: %08x\n", off4_structs.folder_and_indexing_from_tree[i].folder_idx, off4_structs.folder_and_indexing_from_tree[i].indexing_idx);
#endif
    }
    
    printf("Indexing helper:\n");
    for (int i = 0; i < off4_structs.header_200->unk18 + off4_structs.header_200->post_fileslice_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("file_tree_entry_idx %08x folder_tree_entry_idx %08x file_offset_helper_idx %08x flags %08x\n", off4_structs.indexing_helper[i].file_tree_entry_idx, off4_structs.indexing_helper[i].folder_tree_entry_idx, off4_structs.indexing_helper[i].file_offset_helper_idx, off4_structs.indexing_helper[i].flags);
#endif
    }
    
    printf("File offset helper:\n");
    for (int i = 0; i < off4_structs.header_200->unk1C + off4_structs.header_200->post_fileslice_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("folderchunk_idx %08x fileslice_idx %08x flags %08x\n", off4_structs.file_offset_helper[i].folderchunk_idx, off4_structs.file_offset_helper[i].fileslice_idx, off4_structs.file_offset_helper[i].flags);
#endif
    }

    printf("Fileslice table:\n");
    for (int i = 0; i < off4_structs.header_200->fileslice_entries + off4_structs.header_200->post_fileslice_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_fileslice(&off4_structs.fileslice_entries[i]);
#endif
    }
}

/********************
* Lookup functions  *
********************/

file_tree_entry* hash_lookup(uint64_t hash)
{
    hash_bucket bucket = off4_structs.file_lookup_buckets[(hash % off4_structs.file_lookup_buckets->num_entries) + 1];
    entry_pair* found = (entry_pair*)bsearch(&hash, &off4_structs.file_lookup[bucket.index], bucket.num_entries, sizeof(entry_pair), hash40_compar);
    
    return &off4_structs.file_tree_entries[found->meta];
}

file_tree_entry* file_lookup(const char* path)
{
    uint64_t hash = hash40(path, strlen(path));
    return hash_lookup(hash);
}

file_tree_entry_200* hash_lookup_200(uint64_t hash)
{
    hash_bucket bucket = off4_structs.file_lookup_buckets[(hash % off4_structs.file_lookup_buckets->num_entries) + 1];
    entry_pair* found = (entry_pair*)bsearch(&hash, &off4_structs.file_lookup[bucket.index], bucket.num_entries, sizeof(entry_pair), hash40_compar);
    
    return &off4_structs.file_tree_entries_200[found->meta];
}

file_tree_entry_200* file_lookup_200(const char* path)
{
    uint64_t hash = hash40(path, strlen(path));
    return hash_lookup_200(hash);
}

void dump_file(folder_chunk_entry* folderchunk, file_slice* fileslice, std::string outpath)
{    
    if ((fileslice->flags & FILESLICE_COMPRESSION) == FILESLICE_DECOMPRESSED)
    {
        FILE* part = fopen(outpath.c_str(), "wb");
        if (!part)
        {
            printf("Failed to open %s\n", outpath.c_str());
            return;
        }

        void* data = malloc(fileslice->decomp_size);

        printf("decomp seek %llx\n", arc_head.offset_2 + folderchunk->offset + (fileslice->offset * sizeof(uint32_t)));
        fseek(arc_file, arc_head.offset_2 + folderchunk->offset + (fileslice->offset * sizeof(uint32_t)), SEEK_SET);
        fread(data, fileslice->comp_size, 1, arc_file);

        fwrite(data, fileslice->decomp_size, 1, part);
        fclose(part);
        free(data);

        return;
    }

    if ((fileslice->flags & FILESLICE_COMPRESSION) != FILESLICE_COMPRESSED_ZSTD)
    {
        printf("Failed to extract %s, unknown compression (%08x)\n", outpath.c_str(), fileslice->flags & FILESLICE_COMPRESSION);
        return;
    }

    void* data = malloc(fileslice->decomp_size);
    void* data_comp = malloc(fileslice->comp_size);

    printf("comp seek %llx\n", arc_head.offset_2 + folderchunk->offset + (fileslice->offset * sizeof(uint32_t)));
    fseek(arc_file, arc_head.offset_2 + folderchunk->offset + (fileslice->offset * sizeof(uint32_t)), SEEK_SET);
    fread(data_comp, fileslice->comp_size, 1, arc_file);

    if (!zstd_decomp(data_comp, data, fileslice->comp_size, fileslice->decomp_size))
    {
        printf("Failed to decompress...\n");
        free(data);
        free(data_comp);
        return;
    }

    FILE* part = fopen(outpath.c_str(), "wb");
    if (part)
    {
        fwrite(data, fileslice->decomp_size, 1, part);
        fclose(part);
    }
    else
    {
        printf("Failed to open %s\n", outpath.c_str());
    }

    free(data);
    free(data_comp);
}

void dump_file_tree_entry(file_tree_entry* entry, std::string outpath)
{
    if (entry->flags & TREE_REDIR)
    {
        uint32_t redir_idx = off4_structs.fileslice_entries[entry->fileslice_index].flags & FILESLICE_TREE_IDX_MASK;
        
        print_file_tree_entry(entry);
        entry = &off4_structs.file_tree_entries[redir_idx];
        print_file_tree_entry(entry);
    }

    folder_tree_entry* bighash = &off4_structs.folder_tree_entries[entry->path.meta];
    folder_chunk_entry* folderchunk = &off4_structs.folder_chunks[bighash->path.meta];
    print_folder_tree_entry(bighash);
    print_folder_chunk(folderchunk);
    
    uint32_t fileslice_index = 0;
    if ((entry->flags & TREE_FILESLICE_MASK) == TREE_FILESLICE_IDX)
    {
        fileslice_index = entry->fileslice_index;
    }
    else
    {
        fileslice_index = entry->ext.meta;
        if (off4_structs.fileslice_entries[fileslice_index].flags & FILESLICE_REDIR)
            fileslice_index += (off4_structs.fileslice_entries[fileslice_index].flags & FILESLICE_TREE_IDX_MASK);
    }

    dump_file(folderchunk, &off4_structs.fileslice_entries[fileslice_index], outpath);
}

void dump_file_tree_entry_200(file_tree_entry_200* entry, std::string outpath)
{
    folder_and_indexing* pair = &off4_structs.folder_and_indexing_from_tree[entry->path.meta];
    indexing_helper_struct* indexing = &off4_structs.indexing_helper[pair->indexing_idx];
    file_offset_helper_struct* offset = &off4_structs.file_offset_helper[indexing->file_offset_helper_idx];
    
    printf("%x\n", offset->flags);
    
    folder_tree_entry* bighash = &off4_structs.folder_tree_entries[pair->folder_idx];
    folder_chunk_entry* folderchunk = &off4_structs.folder_chunks[bighash->path.meta];
    print_folder_tree_entry(bighash);
    print_folder_chunk(folderchunk);
    
    uint32_t fileslice_index = offset->fileslice_idx;
    print_fileslice(&off4_structs.fileslice_entries[fileslice_index]);
    //if ((entry->flags & TREE_FILESLICE_MASK) == TREE_FILESLICE_IDX)
    {
        //fileslice_index = entry->fileslice_index;
    }
    /*else
    {
        fileslice_index = entry->ext.meta;
        if (off4_structs.fileslice_entries[fileslice_index].flags & FILESLICE_REDIR)
            fileslice_index += (off4_structs.fileslice_entries[fileslice_index].flags & FILESLICE_TREE_IDX_MASK);
    }*/

    printf("Dumping to %s\n", outpath.c_str());
    dump_file(folderchunk, &off4_structs.fileslice_entries[fileslice_index], outpath);
}

void dump_file(std::string filepath)
{
    if (arc_version == ARC_100 || arc_version == ARC_110)
    {
        file_tree_entry* entry = file_lookup(filepath.c_str());
        print_file_tree_entry(entry);
        dump_file_tree_entry(entry, unhash[entry->file.hash]);
    }
    else
    {
        file_tree_entry_200* entry = file_lookup_200(filepath.c_str());
        print_file_tree_entry_200(entry);
        
        dump_file_tree_entry_200(entry, unhash[entry->file.hash]);
    }
}

void dump_hash(uint64_t hash)
{
    file_tree_entry* entry = hash_lookup(hash);
    print_file_tree_entry(entry);
    dump_file_tree_entry(entry, "hash2.bin");
}

/****************************************
* Struct offset calculations/expansion  *
****************************************/

void calc_offset4_structs(offset4_structs* off4, uint32_t buckets = 0)
{
    off4->bulkfile_category_info = (entry_triplet*)&off4->ext_header[1];
    off4->bulkfile_hash_lookup = (entry_pair*)&off4->bulkfile_category_info[off4->ext_header->bgm_unk_movie_entries];
    off4->bulk_files_by_name = (entry_triplet*)&off4->bulkfile_hash_lookup[off4->ext_header->entries];
    off4->bulkfile_lookup_to_fileidx = (uint32_t*)&off4->bulk_files_by_name[off4->ext_header->entries];
    off4->file_pairs = (file_pair*)&off4->bulkfile_lookup_to_fileidx[off4->ext_header->entries_2];
    off4->weird_hashes = (entry_triplet*)&off4->file_pairs[off4->ext_header->num_files];
    off4->folder_tree_entries = (folder_tree_entry*)&off4->weird_hashes[off4->header->weird_hash_entries];
    off4->folder_chunks = (folder_chunk_entry*)&off4->folder_tree_entries[off4->header->folder_tree_entries];
    off4->folder_hash_lookup = (entry_pair*)&off4->folder_chunks[off4->header->entries_folderchunks_1 + off4->header->entries_folderchunks_2];

    off4->file_tree_entries = (file_tree_entry*)&off4->folder_hash_lookup[off4->header->folder_hash_entries];
    off4->fileslice_entries = (file_slice*)&off4->file_tree_entries[off4->header->file_tree_entries];
    off4->folder_to_folder_tree = (entry_pair*)&off4->fileslice_entries[off4->header->fileslice_entries + off4->header->post_fileslice_entries];
    off4->file_lookup_buckets = (hash_bucket*)&off4->folder_to_folder_tree[off4->header->folder_tree_entries];
    
    if (buckets == 0)
        buckets = off4->file_lookup_buckets->num_entries;
    
    off4->file_lookup = (entry_pair*)&off4->file_lookup_buckets[buckets+1];
    off4->numbers3 = (entry_pair*)&off4->file_lookup[off4->header->file_lookup_entries];
}

void calc_offset4_structs_200(offset4_structs* off4, uint32_t buckets = 0)
{
    off4->bulkfile_category_info = (entry_triplet*)&off4->ext_header[1];
    off4->bulkfile_hash_lookup = (entry_pair*)&off4->bulkfile_category_info[off4->ext_header->bgm_unk_movie_entries];
    off4->bulk_files_by_name = (entry_triplet*)&off4->bulkfile_hash_lookup[off4->ext_header->entries];
    off4->bulkfile_lookup_to_fileidx = (uint32_t*)&off4->bulk_files_by_name[off4->ext_header->entries];
    off4->file_pairs = (file_pair*)&off4->bulkfile_lookup_to_fileidx[off4->ext_header->entries_2];
    off4->file_lookup_buckets = (hash_bucket*)&off4->file_pairs[off4->ext_header->num_files];
    
    if (buckets == 0)
        buckets = off4->file_lookup_buckets->num_entries;
    
    off4->file_lookup = (entry_pair*)&off4->file_lookup_buckets[buckets+1];

    off4->file_tree_entries = 0;
    off4->file_tree_entries_200 = (file_tree_entry_200*)&off4->file_lookup[off4->header_200->file_lookup_entries];
    off4->folder_and_indexing_from_tree = (folder_and_indexing*)&off4->file_tree_entries_200[off4->header_200->file_lookup_entries];

    off4->folder_to_folder_tree = (entry_pair*)&off4->folder_and_indexing_from_tree[off4->header_200->unk08];
    off4->folder_tree_entries = (folder_tree_entry*)&off4->folder_to_folder_tree[off4->header_200->folder_tree_entries];

    off4->folder_chunks = (folder_chunk_entry*)&off4->folder_tree_entries[off4->header_200->folder_tree_entries];
    off4->folder_hash_lookup = (entry_pair*)&off4->folder_chunks[off4->header_200->entries_folderchunks_1 + off4->header_200->entries_folderchunks_2];
    off4->indexing_helper = (indexing_helper_struct*)&off4->folder_hash_lookup[off4->header_200->folder_hash_entries];
    off4->file_offset_helper = (file_offset_helper_struct*)&off4->indexing_helper[off4->header_200->unk18 + off4->header_200->post_fileslice_entries];
    off4->fileslice_entries = (file_slice*)&off4->file_offset_helper[off4->header_200->unk1C + off4->header_200->post_fileslice_entries];
}

void calc_offset5_structs(offset5_structs* off5)
{
    off5->folderhash_to_foldertree = (entry_pair*)&off5->header[1];
    off5->folder_tree = (mini_folder_tree_entry*)&off5->folderhash_to_foldertree[off5->header->folder_entries];
    off5->entries_13 = (entry_pair*)&off5->folder_tree[off5->header->folder_entries];
    off5->numbers = (uint32_t*)&off5->entries_13[off5->header->hash_entries];
    off5->file_tree_entries = (mini_file_tree_entry*)&off5->numbers[off5->header->file_entries];
}

void expand_fileslices_foldertree_folderchunk()
{
    offset4_structs newvals = off4_structs;
    
    uint32_t old_big, old_folderchunks_2, old_post;
    old_big = newvals.header->folder_tree_entries;
    old_folderchunks_2 = newvals.header->entries_folderchunks_2;
    old_post = newvals.header->post_fileslice_entries;
    
    newvals.header->folder_tree_entries += 1;
    newvals.header->entries_folderchunks_2 += 1;
    newvals.header->post_fileslice_entries += 100;
    
    calc_offset4_structs(&newvals, off4_structs.file_lookup_buckets->num_entries);
    
    memmove(newvals.numbers3, off4_structs.numbers3, off4_structs.header->file_tree_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup, off4_structs.file_lookup, off4_structs.header->file_lookup_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup_buckets, off4_structs.file_lookup_buckets, (off4_structs.file_lookup_buckets->num_entries+1) * sizeof(hash_bucket));
    memmove(newvals.folder_to_folder_tree, off4_structs.folder_to_folder_tree, off4_structs.header->folder_tree_entries * sizeof(entry_pair));
    memmove(newvals.fileslice_entries, off4_structs.fileslice_entries, (off4_structs.header->fileslice_entries + off4_structs.header->post_fileslice_entries) * sizeof(file_slice));
    memmove(newvals.file_tree_entries, off4_structs.file_tree_entries, off4_structs.header->file_tree_entries * sizeof(file_tree_entry));
    memmove(newvals.folder_hash_lookup, off4_structs.folder_hash_lookup, off4_structs.header->folder_hash_entries * sizeof(entry_pair));
    memmove(newvals.folder_chunks, off4_structs.folder_chunks, (off4_structs.header->entries_folderchunks_1 + off4_structs.header->entries_folderchunks_2) * sizeof(folder_chunk_entry));
    memmove(newvals.folder_tree_entries, off4_structs.folder_tree_entries, off4_structs.header->folder_tree_entries * sizeof(folder_tree_entry));
    memmove(newvals.weird_hashes, off4_structs.weird_hashes, off4_structs.header->weird_hash_entries * sizeof(entry_triplet));
    memmove(newvals.file_pairs, off4_structs.file_pairs, off4_structs.ext_header->entries_2 * sizeof(file_pair));
    memmove(newvals.bulkfile_lookup_to_fileidx, off4_structs.bulkfile_lookup_to_fileidx, off4_structs.ext_header->entries_2 * sizeof(uint32_t));
    memmove(newvals.bulk_files_by_name, off4_structs.bulk_files_by_name, off4_structs.ext_header->entries * sizeof(entry_triplet));
    memmove(newvals.bulkfile_hash_lookup, off4_structs.bulkfile_hash_lookup, off4_structs.ext_header->entries * sizeof(entry_pair));
    memmove(newvals.bulkfile_category_info, off4_structs.bulkfile_category_info, off4_structs.ext_header->bgm_unk_movie_entries * sizeof(entry_triplet));
    
    off4_structs = newvals;
    
    file_tree_entry* wolf = file_lookup("prebuilt:/nro/release/lua2cpp_wolf.nro");
    
    
    folder_tree_entry* bighash = &off4_structs.folder_tree_entries[wolf->path.meta];
    folder_chunk_entry* folderchunk = &off4_structs.folder_chunks[bighash->path.meta];
    
    uint32_t new_fileslice_idx = off4_structs.header->fileslice_entries + old_post;
    folder_tree_entry* bighash_new = &off4_structs.folder_tree_entries[old_big];
    folder_chunk_entry* folderchunk_new = &off4_structs.folder_chunks[off4_structs.header->entries_folderchunks_1 + old_folderchunks_2];
    file_slice* fileslice_new = &off4_structs.fileslice_entries[new_fileslice_idx];
    
   *bighash_new = *bighash;
   *folderchunk_new = *folderchunk;
    
    wolf->path.meta = old_big;
    bighash_new->path.meta = off4_structs.header->entries_folderchunks_1 + old_folderchunks_2;
    bighash_new->fileslice_start = new_fileslice_idx;

    folderchunk_new->fileslice_index = new_fileslice_idx;

    for (int i = 0; i < folderchunk_new->files; i++)
    {
        off4_structs.fileslice_entries[new_fileslice_idx+i] = off4_structs.fileslice_entries[folderchunk->fileslice_index+i];
    }
    
    wolf->fileslice_index = (wolf->fileslice_index-bighash->fileslice_start)+new_fileslice_idx;

    // weird stuff
    
    folderchunk_new->offset = (0xffff00000000 / 4);
    printf("%llx %llx\n", folderchunk_new->memory_size, folderchunk_new->file_size);
    folderchunk_new->memory_size = 0;
    folderchunk_new->file_size = 0;
    
    file_slice* fileslice_wolf = &off4_structs.fileslice_entries[wolf->fileslice_index];
    /*fileslice_wolf->flags &= ~FILESLICE_COMPRESSION;
    fileslice_wolf->flags |= FILESLICE_DECOMPRESSED;
    fileslice_wolf->comp_size = fileslice_new->decomp_size;*/
    
    for (int i = 0; i < folderchunk_new->files; i++)
    {
        int fileslice_index = new_fileslice_idx+i;
        file_slice* fileslice = &off4_structs.fileslice_entries[fileslice_index];
        
        if (fileslice->flags & FILESLICE_REDIR)
        {
            fileslice_index += (fileslice->flags & FILESLICE_TREE_IDX_MASK);
            fileslice = &off4_structs.fileslice_entries[fileslice_index];
        }
        
        uint64_t comp = fileslice->comp_size;
        uint64_t decomp = fileslice->decomp_size;
        uint64_t comp_aligned = (comp + 0x7) & ~0x7;
        uint64_t decomp_aligned = (decomp + 0x7f) & ~0x7f;

        printf("    %x: %llx %llx %llx %x %llx\n", fileslice_index, fileslice->offset * 4, decomp, comp, fileslice->flags, comp_aligned);
        
        if (fileslice->flags & FILESLICE_COMPRESSION)
        {
            folderchunk_new->memory_size += decomp_aligned;
            folderchunk_new->file_size += comp_aligned;
        }
        else
        {
            folderchunk_new->memory_size += comp_aligned;
            folderchunk_new->file_size += comp_aligned;
        }
    }
    
    printf("%llx %llx\n", folderchunk_new->memory_size, folderchunk_new->file_size);
    
    print_file_tree_entry(wolf);
    print_fileslice(fileslice_new);
    print_folder_tree_entry(bighash_new);
    print_folder_chunk(folderchunk_new);
    print_entry_pair(&off4_structs.folder_hash_lookup[bighash_new->subfolderlookup_start_idx + 1]);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("%s <data.arc>\n", argv[0]);
        return -1;
    }

    hash40_store_init();
    zstd_init();
    
    char* fname = argv[1];
    arc_file = fopen(argv[1], "rb");
    if (!arc_file)
    {
        printf("Failed to to open file `%x'! Exiting...\n", argv[1]);
        return -1;
    }
    
    fread(&arc_head, sizeof(arc_header), 1, arc_file);
    
    printf("Magic: %016llx\n", arc_head.magic);
    printf("Offset 1: %016llx\n", arc_head.offset_1);
    printf("Offset 2: %016llx\n", arc_head.offset_2);
    printf("Offset 3: %016llx\n", arc_head.offset_3);
    printf("Offset 4: %016llx\n", arc_head.offset_4);
    printf("Offset 5: %016llx\n", arc_head.offset_5);
    printf("Offset 6: %016llx\n\n", arc_head.offset_6);
    
    arc_version = ARC_100;
    
    // Offset 4
    arc_section section;
    fseek(arc_file, arc_head.offset_4, SEEK_SET);
    fread(&section, sizeof(section), 1, arc_file);
    
    if (section.data_start < 0x100)
    {
        arc_version = ARC_110;

        off4_structs.off4_data = malloc(section.decomp_size);
        off4_structs.header = (offset4_header*)off4_structs.off4_data;
        off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header));

        void* comp_tmp = malloc(section.comp_size);
        
        fseek(arc_file, arc_head.offset_4 + section.data_start, SEEK_SET);
        fread(comp_tmp, section.comp_size, 1, arc_file);
        
        zstd_decomp(comp_tmp, off4_structs.off4_data, section.zstd_comp_size, section.decomp_size);
        
        free(comp_tmp);
        
        // 2.0.0
        if (off4_structs.ext_header->bgm_unk_movie_entries != 3)
        {
            arc_version = ARC_200;
            off4_structs.header_200 = (offset4_header_200*)off4_structs.off4_data;
            off4_structs.header = nullptr;
            off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header_200) + off4_structs.header_200->size_3_entries * sizeof(entry_triplet));
            
            off4_structs.headerext_300 = (offset4_headerext_300*)(off4_structs.off4_data + sizeof(offset4_header_200));
            
            // 3.0.0
            if (off4_structs.headerext_300->unk0 != 1)
            {
                off4_structs.headerext_300 = nullptr;
            }
            else
            {
                arc_version = ARC_300;
                
                off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header_200)  + sizeof(offset4_headerext_300) + off4_structs.header_200->size_3_entries * sizeof(entry_triplet));
            }
        }
        
        FILE* dump = fopen("dump.bin", "wb");
        fwrite(off4_structs.off4_data, 1, section.decomp_size, dump);
        fclose(dump);
    }
    else
    {
        off4_structs.off4_data = malloc(section.data_start + 0x200000); // total_size
        off4_structs.header = (offset4_header*)off4_structs.off4_data;
        off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header));
        
        fseek(arc_file, arc_head.offset_4, SEEK_SET);
        fread(off4_structs.header, 0x34, 1, arc_file);
        fread(off4_structs.ext_header, 0x10, 1, arc_file);

        fread(off4_structs.off4_data + sizeof(offset4_header) + sizeof(offset4_ext_header), off4_structs.header->total_size - (sizeof(offset4_header) + sizeof(offset4_ext_header)), 1, arc_file);
    }
    
    if (arc_version == ARC_100 || arc_version == ARC_110)
    {
        printf("Offset 4 Header:\n");
        printf("Total size: %08x\n", off4_structs.header->total_size);
        printf("Folder tree entries: %08x\n", off4_structs.header->folder_tree_entries);
        printf("Folder chunks 1: %08x\n", off4_structs.header->entries_folderchunks_1);
        printf("File Tree Entries: %08x\n", off4_structs.header->file_tree_entries);
        
        printf("Fileslice entries: %08x\n", off4_structs.header->fileslice_entries);
        printf("File lookup entries: %08x\n", off4_structs.header->file_lookup_entries);
        printf("Folder hash entries: %08x\n", off4_structs.header->folder_hash_entries);
        printf("File Tree Entries 2: %08x\n", off4_structs.header->file_tree_entries_2);
        printf("Folder chunks 2: %08x\n", off4_structs.header->entries_folderchunks_2);
        printf("Post-fileslice entries: %08x\n", off4_structs.header->post_fileslice_entries);
        printf("Default alloc alignment: %08x\n", off4_structs.header->alloc_alignment);
        printf("Unk 10: %08x\n", off4_structs.header->unk10);
        printf("Unk 11: %08x\n\n", off4_structs.header->unk11);
        
        calc_offset4_structs(&off4_structs);
    }
    else
    {
        printf("Offset 4 Header (2.0.0+):\n");
        printf("Total size: %08x\n", off4_structs.header_200->total_size);
        printf("File lookup entries: %08x\n", off4_structs.header_200->file_lookup_entries);
        printf("Unk08: %08x\n", off4_structs.header_200->unk08);
        printf("Folder tree entries: %08x\n", off4_structs.header_200->folder_tree_entries);
        
        printf("Folder chunks 1: %08x\n", off4_structs.header_200->entries_folderchunks_1);
        printf("Folder hash entries: %08x\n", off4_structs.header_200->folder_hash_entries);
        printf("Unk18: %08x\n", off4_structs.header_200->unk18);
        printf("Unk1C: %08x\n", off4_structs.header_200->unk1C);
        
        printf("Fileslice entries: %08x\n", off4_structs.header_200->fileslice_entries);
        printf("Folder chunks 2: %08x\n", off4_structs.header_200->entries_folderchunks_2);
        printf("Post-fileslice entries: %08x\n", off4_structs.header_200->post_fileslice_entries);
        printf("Unk2C: %08x\n", off4_structs.header_200->unk2C);
        
        printf("Default alloc alignment: %08x\n", off4_structs.header_200->alloc_alignment);
        printf("Unk34: %08x\n", off4_structs.header_200->unk34);
        
        printf("size_3_entries: %02x\n", off4_structs.header_200->size_3_entries);
        printf("Unk39: %02x\n", off4_structs.header_200->unk39);
        printf("Unk3A: %02x\n", off4_structs.header_200->unk3A);
        printf("Unk3B: %02x\n\n", off4_structs.header_200->unk3B);
        
        if (arc_version == ARC_300)
        {
            printf("Offset 4 Headerext (3.0.0):\n");
            printf("Unk0: %04x\n", off4_structs.headerext_300->unk0);
            printf("Unk2: %04x\n", off4_structs.headerext_300->unk2);
            printf("Unk4: %08x\n", off4_structs.headerext_300->unk4);
            printf("Unk8: %08x\n", off4_structs.headerext_300->unk8);
            printf("UnkC: %08x\n", off4_structs.headerext_300->unkC);
            printf("Unk10: %08x\n", off4_structs.headerext_300->unk10);
            printf("Unk14: %08x\n", off4_structs.headerext_300->unk14);
            printf("Unk18: %08x\n\n", off4_structs.headerext_300->unk18);
        }
        
        calc_offset4_structs_200(&off4_structs);
    }

    printf("Offset 4 Extended Header:\n");
    printf("Hash table 1 entries: %08x\n", off4_structs.ext_header->bgm_unk_movie_entries);
    printf("Hash table 2/3 entries: %08x\n", off4_structs.ext_header->entries);
    printf("Number table entries: %08x\n", off4_structs.ext_header->entries_2);
    printf("Num files: %08x\n\n", off4_structs.ext_header->num_files);
    
    //expand_fileslices_foldertree_folderchunk();
    
    // Sample lookup
    dump_file("prebuilt:/nro/release/lua2cpp_wolf.nro");
    //dump_hash(0x2b122ee688);
    //dump_file("stage/punchoutsb/normal/model/stc_lightboard_chance_set/pusb_lightboard_chance_col.nutexb");
    //dump_file("fighter/pitb/motion/body/c01/h03heavywalk.nuanmb");
    //dump_file("sound/bank/stage/se_stage_fzero_mutecity3ds.nus3bank");
    /*dump_file("prebuilt:/nro/release/lua2cpp_common.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_bayonetta.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_captain.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_chrom.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_cloud.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_daisy.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_dedede.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_diddy.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_donkey.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_duckhunt.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_falco.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_fox.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_gamewatch.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ganon.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_gaogaen.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_gekkouga.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ike.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_inkling.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_kamui.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ken.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_kirby.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_koopa.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_koopag.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_koopajr.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_krool.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_link.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_littlemac.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_lucario.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_lucas.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_lucina.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_luigi.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_mario.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_mariod.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_marth.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_metaknight.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_mewtwo.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miienemyf.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miienemyg.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miienemys.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miifighter.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miigunner.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_miiswordsman.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_murabito.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_nana.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ness.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pacman.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_palutena.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_peach.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pfushigisou.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pichu.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pikachu.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pikmin.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pit.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pitb.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_plizardon.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_popo.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_purin.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_pzenigame.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_reflet.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_richter.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ridley.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_robot.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_rockman.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_rosetta.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_roy.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ryu.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_samus.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_samusd.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_sheik.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_shizue.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_shulk.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_simon.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_snake.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_sonic.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_szerosuit.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_toonlink.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_wario.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_wiifit.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_wolf.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_yoshi.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_younglink.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_zelda.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_ptrainer.nro");
    dump_file("prebuilt:/nro/release/lua2cpp_item.nro");*/
    
    if (arc_version == ARC_100 || arc_version == ARC_110)
    {
        print_100_110();
    }
    else
    {
        print_200();
    }
    
    //TODO: 2.0.0+
    if (arc_version == ARC_100 || arc_version == ARC_110)
    {
        // Offset 5
        fseek(arc_file, arc_head.offset_5, SEEK_SET);
        fread(&section, sizeof(section), 1, arc_file);
        
        if (section.data_start < 0x100)
        {
            off5_structs.off5_data = malloc(section.decomp_size);
            off5_structs.header = (offset5_header*)off5_structs.off5_data;

            void* comp_tmp = malloc(section.comp_size);
            
            fseek(arc_file, arc_head.offset_5 + section.data_start, SEEK_SET);
            fread(comp_tmp, section.comp_size, 1, arc_file);
            
            zstd_decomp(comp_tmp, off5_structs.off5_data, section.zstd_comp_size, section.decomp_size);
            
            free(comp_tmp);
        }
        else
        {
            off5_structs.off5_data = malloc(section.data_start); // total_size
            off5_structs.header = (offset5_header*)off5_structs.off5_data;
            
            fseek(arc_file, arc_head.offset_5, SEEK_SET);
            fread(off5_structs.header, 0x14, 1, arc_file);

            fread(off5_structs.off5_data + sizeof(offset5_header), off5_structs.header->total_size - sizeof(offset5_header), 1, arc_file);
        }

        printf("\nOffset 5 Header:\n");
        printf("Total size %016llx\n", off5_structs.header->total_size);
        printf("Folder Entries: %08x\n", off5_structs.header->folder_entries);
        printf("File Entries: %08x\n", off5_structs.header->file_entries);
        printf("Something 2: %08x\n", off5_structs.header->hash_entries);
        
        calc_offset5_structs(&off5_structs);

        printf("Folder hash to folder tree entry:\n");
        for (int i = 0; i < off5_structs.header->folder_entries; i++)
        {
    #ifdef VERBOSE_PRINT
            printf("%06x: ", i);
            print_entry_pair(&off5_structs.folderhash_to_foldertree[i]);
    #endif
        }
        
        printf("Folder tree:\n");
        for (int i = 0; i < off5_structs.header->folder_entries; i++)
        {
    #ifdef VERBOSE_PRINT
            printf("%06x: ", i);
            print_mini_folder_tree_entry(&off5_structs.folder_tree[i]);
    #endif
        }
        
        printf("File hash to file tree entry:\n");
        for (int i = 0; i < off5_structs.header->hash_entries; i++)
        {
    #ifdef VERBOSE_PRINT
            print_entry_pair(&off5_structs.entries_13[i]);
    #endif
        }
        
        printf("Numbers:\n");
        for (int i = 0; i < off5_structs.header->file_entries; i++)
        {
    #ifdef VERBOSE_PRINT
            printf("%06x: %08x\n", i, off5_structs.numbers[i]);
    #endif
        }
        
        printf("File tree:\n");
        for (int i = 0; i < off5_structs.header->file_entries; i++)
        {
    #ifdef VERBOSE_PRINT
            print_mini_file_tree_entry(&off5_structs.file_tree_entries[i]);
    #endif
        }

        free(off5_structs.off5_data);
    }
    free(off4_structs.off4_data);
    
    zstd_deinit();
    fclose(arc_file);
}
