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

typedef struct offset5_header
{
    uint64_t total_size;
    uint32_t folder_entries;
    uint32_t file_entries;
    uint32_t hash_entries;
} offset5_header;

typedef struct offset4_header
{
    uint32_t total_size;
    uint32_t entries_big;
    uint32_t entries_bigfiles_1;
    uint32_t tree_entries;
    
    uint32_t suboffset_entries;
    uint32_t file_lookup_entries;
    uint32_t folder_hash_entries;
    uint32_t tree_entries_2;
    
    uint32_t entries_bigfiles_2;
    uint32_t post_suboffset_entries;
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
    uint32_t entries_big;
    
    uint32_t entries_bigfiles_1;
    uint32_t folder_hash_entries;
    uint32_t unk18;
    uint32_t unk1C;
    
    uint32_t suboffset_entries;
    uint32_t entries_bigfiles_2;
    uint32_t post_suboffset_entries;
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

typedef struct big_hash_entry
{
    entry_pair path;
    entry_pair folder;
    entry_pair parent;
    entry_pair hash4;
    union
    {
        uint32_t suboffset_start;
        uint32_t indexing_start;
    };
    uint32_t num_files;
    uint32_t folderlookup_start;
    uint16_t num_folders;
    uint16_t tree_start;
    uint8_t unk6;
    uint8_t unk7;
    uint8_t unk8;
    uint8_t unk9;
} big_hash_entry;

typedef struct big_file_entry
{
    uint64_t offset;
    uint32_t decomp_size;
    uint32_t comp_size;
    uint32_t suboffset_index;
    uint32_t files;
    uint32_t unk3;
} __attribute__((packed)) big_file_entry;

typedef struct file_entry
{
    uint32_t offset;
    uint32_t comp_size;
    uint32_t decomp_size;
    uint32_t flags;
} file_entry;

typedef struct tree_entry
{
    entry_pair path;
    entry_pair ext;
    entry_pair folder;
    entry_pair file;
    uint32_t suboffset_index;
    uint32_t flags;
} tree_entry;

typedef struct tree_entry_200
{
    entry_pair path;
    entry_pair ext;
    entry_pair folder;
    entry_pair file;
} tree_entry_200;

typedef struct folder_tree_entry
{
    entry_pair path;
    entry_pair parent;
    entry_pair folder;
    uint32_t idx1;
    uint32_t idx2;
} folder_tree_entry;

typedef struct mini_tree_entry
{
    entry_pair path;
    entry_pair folder;
    entry_pair file;
    entry_pair ext;
} mini_tree_entry;

typedef struct hash_bucket
{
    uint32_t index;
    uint32_t num_entries;
} hash_bucket;

typedef struct indexing_helper_struct
{
    uint32_t tree_entry_idx;
    uint32_t big_folder_idx;
    uint32_t file_offset_helper_idx;
    uint32_t flags;
} indexing_helper_struct;

typedef struct file_offset_helper_struct
{
    uint32_t bigfile_idx;
    uint32_t suboffset_idx;
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
    big_hash_entry* big_hashes;
    big_file_entry* big_files;
    entry_pair* folder_hash_lookup;
    tree_entry* tree_entries;
    file_entry* suboffset_entries;
    entry_pair* folder_to_big_hash;
    hash_bucket* file_lookup_buckets;
    entry_pair* file_lookup;
    entry_pair* numbers3;
    
    tree_entry_200* tree_entries_200;
    indexing_helper_struct* indexing_helper;
    file_offset_helper_struct* file_offset_helper;
    folder_and_indexing* folder_and_indexing_from_tree;
} offset4_structs;

typedef struct offset5_structs
{
    void* off5_data;
    offset5_header* header;
    entry_pair* folderhash_to_foldertree;
    folder_tree_entry* folder_tree;
    entry_pair* entries_13;
    uint32_t* numbers;
    mini_tree_entry* tree_entries;
} offset5_structs;

typedef struct arc_section
{
    uint32_t data_start;
    uint32_t decomp_size;
    uint32_t comp_size;
    uint32_t zstd_comp_size;
} arc_section;

#define TREE_ALIGN_MASK           0x0fffe0
#define TREE_ALIGN_LSHIFT         (5)
#define TREE_SUBOFFSET_MASK       0x000003
#define TREE_SUBOFFSET_IDX        0x000000
#define TREE_SUBOFFSET_EXT_ADD1   0x000001
#define TREE_SUBOFFSET_EXT_ADD2   0x000002
#define TREE_REDIR                0x200000
#define TREE_UNK                  0x100000

#define SUBOFFSET_TREE_IDX_MASK     0x00FFFFFF
#define SUBOFFSET_REDIR             0x40000000
#define SUBOFFSET_UNK_BIT29         0x20000000
#define SUBOFFSET_UNK_BIT27         0x08000000
#define SUBOFFSET_UNK_BIT26         0x04000000

#define CURSED_SUBOFFSETS (arc_version == ARC_100 || arc_version == ARC_110)

#define SUBOFFSET_100_COMPRESSION       0x07000000
#define SUBOFFSET_100_DECOMPRESSED      0x00000000
#define SUBOFFSET_100_UND               0x01000000
#define SUBOFFSET_100_COMPRESSED_LZ4    0x02000000
#define SUBOFFSET_100_COMPRESSED_ZSTD   0x03000000

#define SUBOFFSET_200_COMPRESSION       0x00000007
#define SUBOFFSET_200_DECOMPRESSED      0x00000000
#define SUBOFFSET_200_UND               0x00000001
#define SUBOFFSET_200_COMPRESSED_LZ4    0x00000002
#define SUBOFFSET_200_COMPRESSED_ZSTD   0x00000003

#define SUBOFFSET_COMPRESSION       (CURSED_SUBOFFSETS ? SUBOFFSET_100_COMPRESSION : SUBOFFSET_200_COMPRESSION)
#define SUBOFFSET_DECOMPRESSED      (CURSED_SUBOFFSETS ? SUBOFFSET_100_DECOMPRESSED : SUBOFFSET_200_DECOMPRESSED)
#define SUBOFFSET_UND               (CURSED_SUBOFFSETS ? SUBOFFSET_100_UND : SUBOFFSET_200_UND)
#define SUBOFFSET_COMPRESSED_LZ4    (CURSED_SUBOFFSETS ? SUBOFFSET_100_COMPRESSED_LZ4 : SUBOFFSET_200_COMPRESSED_LZ4)
#define SUBOFFSET_COMPRESSED_ZSTD   (CURSED_SUBOFFSETS ? SUBOFFSET_100_COMPRESSED_ZSTD : SUBOFFSET_200_COMPRESSED_ZSTD)

//#define VERBOSE_PRINT

FILE* arc_file;
arc_header arc_head;
offset4_structs off4_structs;
offset5_structs off5_structs;
ZSTD_DStream* dstream;
int arc_version = ARC_100;

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

void print_entry_pair(entry_pair* pair)
{
    printf("%010llx %06llx (%s)\n", pair->hash, pair->meta, unhash[pair->hash].c_str());
}

void print_entry_triplet(entry_triplet* triplet)
{
    printf("%010llx %06llx %08x (%s)\n", triplet->hash, triplet->meta, triplet->meta2, unhash[triplet->hash].c_str());
}

void print_tree_entry(tree_entry* entry)
{
    printf("%06x: ", entry - off4_structs.tree_entries);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->ext);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
    printf("        suboffset index %08x flags %08x\n", entry->suboffset_index, entry->flags);
}

void print_tree_entry_200(tree_entry_200* entry)
{
    printf("%06x: ", entry - off4_structs.tree_entries_200);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->ext);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
}

void print_folder_tree_entry(folder_tree_entry* entry)
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

void print_mini_tree_entry(mini_tree_entry* entry)
{
    printf("%06x: ", entry - off5_structs.tree_entries);
    print_entry_pair(&entry->path);
    printf("        ");
    print_entry_pair(&entry->folder);
    printf("        ");
    print_entry_pair(&entry->file);
    printf("        ");
    print_entry_pair(&entry->ext);
}

void print_big_hash(big_hash_entry* entry)
{
    printf("path %010llx %06llx, ", entry->path.hash, entry->path.meta);
    printf("folder %010llx %06llx, ", entry->folder.hash, entry->folder.meta);
    printf("parent %010llx %06llx, ", entry->parent.hash, entry->parent.meta);
    printf("hash4 %010llx %06llx, ", entry->hash4.hash, entry->hash4.meta);
    if (arc_version == ARC_100 || arc_version == ARC_110)
        printf("suboffset ");
    else
        printf("indexing idx ");
    printf("%08x files %08x folderlookup_start %08x folders %04x tree_start %04x %02x %02x %02x %02x (path %s, folder %s, parent %s, %s)\n", entry->suboffset_start, entry->num_files, entry->folderlookup_start, entry->num_folders, entry->tree_start, entry->unk6, entry->unk7, entry->unk8, entry->unk9, unhash[entry->path.hash].c_str(), unhash[entry->folder.hash].c_str(), unhash[entry->parent.hash].c_str(), unhash[entry->hash4.hash].c_str());
}

void print_big_file(big_file_entry* entry)
{
    if (!entry->comp_size || entry->unk3 != 0xffffff) return;

    printf("%016llx decomp %08x comp %08x suboffset_index %08x files %08x unk3 %08x\n", entry->offset, entry->decomp_size, entry->comp_size, entry->suboffset_index, entry->files, entry->unk3);
#if 0
    uint64_t calc_comp = 0;
    uint64_t calc_decomp = 0;
    for (int i = 0; i < entry->files; i++)
    {
        int suboffset_index = entry->suboffset_index+i;
        file_entry* suboffset = &off4_structs.suboffset_entries[suboffset_index];
        
        if (suboffset->flags & SUBOFFSET_REDIR)
        {
            suboffset_index += (suboffset->flags & SUBOFFSET_TREE_IDX_MASK);
            suboffset = &off4_structs.suboffset_entries[suboffset_index];
        }
        
        uint64_t comp = suboffset->comp_size;
        uint64_t decomp = suboffset->decomp_size;
        uint64_t comp_aligned = (comp + 0xf) & ~0xf;
        uint64_t decomp_aligned = ((decomp + 0x80) + 0xf) & ~0xf;

        printf("    %x: %llx %llx %llx %x %llx\n", suboffset_index, suboffset->offset * 4, decomp, comp, suboffset->flags, comp_aligned);
        
        if (suboffset->flags & SUBOFFSET_COMPRESSION)
        {
            calc_decomp += decomp_aligned;
            calc_comp += comp_aligned;
        }
        else
        {
            calc_decomp += decomp_aligned;
            calc_comp += comp_aligned;
        }
    }
    
    printf("%llx %llx\n", calc_comp, calc_decomp);
#endif
}

void print_suboffset(file_entry* entry)
{
    printf("%08x %08x %08x %08x\n", entry->offset, entry->comp_size, entry->decomp_size, entry->flags);
}

tree_entry* hash_lookup(uint64_t hash)
{
    hash_bucket bucket = off4_structs.file_lookup_buckets[(hash % off4_structs.file_lookup_buckets->num_entries) + 1];
    entry_pair* found = (entry_pair*)bsearch(&hash, &off4_structs.file_lookup[bucket.index], bucket.num_entries, sizeof(entry_pair), hash40_compar);
    
    return &off4_structs.tree_entries[found->meta];
}

tree_entry* file_lookup(const char* path)
{
    uint64_t hash = hash40(path, strlen(path));
    return hash_lookup(hash);
}


tree_entry_200* hash_lookup_200(uint64_t hash)
{
    hash_bucket bucket = off4_structs.file_lookup_buckets[(hash % off4_structs.file_lookup_buckets->num_entries) + 1];
    entry_pair* found = (entry_pair*)bsearch(&hash, &off4_structs.file_lookup[bucket.index], bucket.num_entries, sizeof(entry_pair), hash40_compar);
    
    return &off4_structs.tree_entries_200[found->meta];
}

tree_entry_200* file_lookup_200(const char* path)
{
    uint64_t hash = hash40(path, strlen(path));
    return hash_lookup_200(hash);
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

void dump_file(big_file_entry* bigfile, file_entry* suboffset, std::string outpath)
{    
    if ((suboffset->flags & SUBOFFSET_COMPRESSION) == SUBOFFSET_DECOMPRESSED)
    {
        FILE* part = fopen(outpath.c_str(), "wb");
        if (!part)
        {
            printf("Failed to open %s\n", outpath.c_str());
            return;
        }

        void* data = malloc(suboffset->decomp_size);

        printf("decomp seek %llx\n", arc_head.offset_2 + bigfile->offset + (suboffset->offset * sizeof(uint32_t)));
        fseek(arc_file, arc_head.offset_2 + bigfile->offset + (suboffset->offset * sizeof(uint32_t)), SEEK_SET);
        fread(data, suboffset->comp_size, 1, arc_file);

        fwrite(data, suboffset->decomp_size, 1, part);
        fclose(part);
        free(data);

        return;
    }

    if ((suboffset->flags & SUBOFFSET_COMPRESSION) != SUBOFFSET_COMPRESSED_ZSTD)
    {
        printf("Failed to extract %s, unknown compression (%08x)\n", outpath.c_str(), suboffset->flags & SUBOFFSET_COMPRESSION);
        return;
    }

    void* data = malloc(suboffset->decomp_size);
    void* data_comp = malloc(suboffset->comp_size);

    printf("comp seek %llx\n", arc_head.offset_2 + bigfile->offset + (suboffset->offset * sizeof(uint32_t)));
    fseek(arc_file, arc_head.offset_2 + bigfile->offset + (suboffset->offset * sizeof(uint32_t)), SEEK_SET);
    fread(data_comp, suboffset->comp_size, 1, arc_file);

    if (!zstd_decomp(data_comp, data, suboffset->comp_size, suboffset->decomp_size))
    {
        printf("Failed to decompress...\n");
        free(data);
        free(data_comp);
        return;
    }

    FILE* part = fopen(outpath.c_str(), "wb");
    if (part)
    {
        fwrite(data, suboffset->decomp_size, 1, part);
        fclose(part);
    }
    else
    {
        printf("Failed to open %s\n", outpath.c_str());
    }

    free(data);
    free(data_comp);
}

void dump_tree_entry(tree_entry* entry, std::string outpath)
{
    if (entry->flags & TREE_REDIR)
    {
        uint32_t redir_idx = off4_structs.suboffset_entries[entry->suboffset_index].flags & SUBOFFSET_TREE_IDX_MASK;
        
        print_tree_entry(entry);
        entry = &off4_structs.tree_entries[redir_idx];
        print_tree_entry(entry);
    }

    big_hash_entry* bighash = &off4_structs.big_hashes[entry->path.meta];
    big_file_entry* bigfile = &off4_structs.big_files[bighash->path.meta];
    print_big_hash(bighash);
    print_big_file(bigfile);
    
    uint32_t suboffset_index = 0;
    if ((entry->flags & TREE_SUBOFFSET_MASK) == TREE_SUBOFFSET_IDX)
    {
        suboffset_index = entry->suboffset_index;
    }
    else
    {
        suboffset_index = entry->ext.meta;
        if (off4_structs.suboffset_entries[suboffset_index].flags & SUBOFFSET_REDIR)
            suboffset_index += (off4_structs.suboffset_entries[suboffset_index].flags & SUBOFFSET_TREE_IDX_MASK);
    }

    dump_file(bigfile, &off4_structs.suboffset_entries[suboffset_index], outpath);
}

void dump_tree_entry_200(tree_entry_200* entry, std::string outpath)
{
    folder_and_indexing* pair = &off4_structs.folder_and_indexing_from_tree[entry->path.meta];
    indexing_helper_struct* indexing = &off4_structs.indexing_helper[pair->indexing_idx];
    file_offset_helper_struct* offset = &off4_structs.file_offset_helper[indexing->file_offset_helper_idx];
    big_hash_entry* bighash = &off4_structs.big_hashes[pair->folder_idx];
    big_file_entry* bigfile = &off4_structs.big_files[bighash->path.meta];
    print_big_hash(bighash);
    print_big_file(bigfile);
    
    uint32_t suboffset_index = offset->suboffset_idx;
    print_suboffset(&off4_structs.suboffset_entries[suboffset_index]);
    //if ((entry->flags & TREE_SUBOFFSET_MASK) == TREE_SUBOFFSET_IDX)
    {
        //suboffset_index = entry->suboffset_index;
    }
    /*else
    {
        suboffset_index = entry->ext.meta;
        if (off4_structs.suboffset_entries[suboffset_index].flags & SUBOFFSET_REDIR)
            suboffset_index += (off4_structs.suboffset_entries[suboffset_index].flags & SUBOFFSET_TREE_IDX_MASK);
    }*/

    printf("Dumping to %s\n", outpath.c_str());
    dump_file(bigfile, &off4_structs.suboffset_entries[suboffset_index], outpath);
}

void calc_offset4_structs(offset4_structs* off4, uint32_t buckets = 0)
{
    off4->bulkfile_category_info = (entry_triplet*)&off4->ext_header[1];
    off4->bulkfile_hash_lookup = (entry_pair*)&off4->bulkfile_category_info[off4->ext_header->bgm_unk_movie_entries];
    off4->bulk_files_by_name = (entry_triplet*)&off4->bulkfile_hash_lookup[off4->ext_header->entries];
    off4->bulkfile_lookup_to_fileidx = (uint32_t*)&off4->bulk_files_by_name[off4->ext_header->entries];
    off4->file_pairs = (file_pair*)&off4->bulkfile_lookup_to_fileidx[off4->ext_header->entries_2];
    off4->weird_hashes = (entry_triplet*)&off4->file_pairs[off4->ext_header->num_files];
    off4->big_hashes = (big_hash_entry*)&off4->weird_hashes[off4->header->weird_hash_entries];
    off4->big_files = (big_file_entry*)&off4->big_hashes[off4->header->entries_big];
    off4->folder_hash_lookup = (entry_pair*)&off4->big_files[off4->header->entries_bigfiles_1 + off4->header->entries_bigfiles_2];

    off4->tree_entries = (tree_entry*)&off4->folder_hash_lookup[off4->header->folder_hash_entries];
    off4->suboffset_entries = (file_entry*)&off4->tree_entries[off4->header->tree_entries];
    off4->folder_to_big_hash = (entry_pair*)&off4->suboffset_entries[off4->header->suboffset_entries + off4->header->post_suboffset_entries];
    off4->file_lookup_buckets = (hash_bucket*)&off4->folder_to_big_hash[off4->header->entries_big];
    
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

    off4->tree_entries = 0;
    off4->tree_entries_200 = (tree_entry_200*)&off4->file_lookup[off4->header_200->file_lookup_entries];
    off4->folder_and_indexing_from_tree = (folder_and_indexing*)&off4->tree_entries_200[off4->header_200->file_lookup_entries];

    off4->folder_to_big_hash = (entry_pair*)&off4->folder_and_indexing_from_tree[off4->header_200->unk08];
    off4->big_hashes = (big_hash_entry*)&off4->folder_to_big_hash[off4->header_200->entries_big];

    off4->big_files = (big_file_entry*)&off4->big_hashes[off4->header_200->entries_big];
    off4->folder_hash_lookup = (entry_pair*)&off4->big_files[off4->header_200->entries_bigfiles_1 + off4->header_200->entries_bigfiles_2];
    off4->indexing_helper = (indexing_helper_struct*)&off4->folder_hash_lookup[off4->header_200->folder_hash_entries];
    off4->file_offset_helper = (file_offset_helper_struct*)&off4->indexing_helper[off4->header_200->unk18 + off4->header_200->post_suboffset_entries];
    off4->suboffset_entries = (file_entry*)&off4->file_offset_helper[off4->header_200->unk1C + off4->header_200->post_suboffset_entries];
    
    //printf("%x %x %x %x\n", *(uint32_t*)(indexing_helper + 0x001d97*0x10 + 0), *(uint32_t*)(indexing_helper + 0x001d97*0x10 + 4), *(uint32_t*)(indexing_helper + 0x001d97*0x10 + 8), *(uint32_t*)(indexing_helper + 0x001d97*0x10 + 0xC));

    //off4->weird_hashes = (entry_triplet*)
    //off4->numbers3 = (entry_pair*)&off4->file_lookup[off4->header->file_lookup_entries];
}

void calc_offset5_structs(offset5_structs* off5)
{
    off5->folderhash_to_foldertree = (entry_pair*)&off5->header[1];
    off5->folder_tree = (folder_tree_entry*)&off5->folderhash_to_foldertree[off5->header->folder_entries];
    off5->entries_13 = (entry_pair*)&off5->folder_tree[off5->header->folder_entries];
    off5->numbers = (uint32_t*)&off5->entries_13[off5->header->hash_entries];
    off5->tree_entries = (mini_tree_entry*)&off5->numbers[off5->header->file_entries];
}

void expand_subfiles_bighash_bigfile()
{
    offset4_structs newvals = off4_structs;
    
    uint32_t old_big, old_bigfiles_2, old_post;
    old_big = newvals.header->entries_big;
    old_bigfiles_2 = newvals.header->entries_bigfiles_2;
    old_post = newvals.header->post_suboffset_entries;
    
    newvals.header->entries_big += 1;
    newvals.header->entries_bigfiles_2 += 1;
    newvals.header->post_suboffset_entries += 100;
    
    calc_offset4_structs(&newvals, off4_structs.file_lookup_buckets->num_entries);
    
    memmove(newvals.numbers3, off4_structs.numbers3, off4_structs.header->tree_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup, off4_structs.file_lookup, off4_structs.header->file_lookup_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup_buckets, off4_structs.file_lookup_buckets, (off4_structs.file_lookup_buckets->num_entries+1) * sizeof(hash_bucket));
    memmove(newvals.folder_to_big_hash, off4_structs.folder_to_big_hash, off4_structs.header->entries_big * sizeof(entry_pair));
    memmove(newvals.suboffset_entries, off4_structs.suboffset_entries, (off4_structs.header->suboffset_entries + off4_structs.header->post_suboffset_entries) * sizeof(file_entry));
    memmove(newvals.tree_entries, off4_structs.tree_entries, off4_structs.header->tree_entries * sizeof(tree_entry));
    memmove(newvals.folder_hash_lookup, off4_structs.folder_hash_lookup, off4_structs.header->folder_hash_entries * sizeof(entry_pair));
    memmove(newvals.big_files, off4_structs.big_files, (off4_structs.header->entries_bigfiles_1 + off4_structs.header->entries_bigfiles_2) * sizeof(big_file_entry));
    memmove(newvals.big_hashes, off4_structs.big_hashes, off4_structs.header->entries_big * sizeof(big_hash_entry));
    memmove(newvals.weird_hashes, off4_structs.weird_hashes, off4_structs.header->weird_hash_entries * sizeof(entry_triplet));
    memmove(newvals.file_pairs, off4_structs.file_pairs, off4_structs.ext_header->entries_2 * sizeof(file_pair));
    memmove(newvals.bulkfile_lookup_to_fileidx, off4_structs.bulkfile_lookup_to_fileidx, off4_structs.ext_header->entries_2 * sizeof(uint32_t));
    memmove(newvals.bulk_files_by_name, off4_structs.bulk_files_by_name, off4_structs.ext_header->entries * sizeof(entry_triplet));
    memmove(newvals.bulkfile_hash_lookup, off4_structs.bulkfile_hash_lookup, off4_structs.ext_header->entries * sizeof(entry_pair));
    memmove(newvals.bulkfile_category_info, off4_structs.bulkfile_category_info, off4_structs.ext_header->bgm_unk_movie_entries * sizeof(entry_triplet));
    
    off4_structs = newvals;
    
    tree_entry* wolf = file_lookup("prebuilt:/nro/release/lua2cpp_wolf.nro");
    
    
    big_hash_entry* bighash = &off4_structs.big_hashes[wolf->path.meta];
    big_file_entry* bigfile = &off4_structs.big_files[bighash->path.meta];
    
    uint32_t new_suboffset_idx = off4_structs.header->suboffset_entries + old_post;
    big_hash_entry* bighash_new = &off4_structs.big_hashes[old_big];
    big_file_entry* bigfile_new = &off4_structs.big_files[off4_structs.header->entries_bigfiles_1 + old_bigfiles_2];
    file_entry* suboffset_new = &off4_structs.suboffset_entries[new_suboffset_idx];
    
   *bighash_new = *bighash;
   *bigfile_new = *bigfile;
    
    wolf->path.meta = old_big;
    bighash_new->path.meta = off4_structs.header->entries_bigfiles_1 + old_bigfiles_2;
    bighash_new->suboffset_start = new_suboffset_idx;

    bigfile_new->suboffset_index = new_suboffset_idx;

    for (int i = 0; i < bigfile_new->files; i++)
    {
        off4_structs.suboffset_entries[new_suboffset_idx+i] = off4_structs.suboffset_entries[bigfile->suboffset_index+i];
    }
    
    wolf->suboffset_index = (wolf->suboffset_index-bighash->suboffset_start)+new_suboffset_idx;

    // weird stuff
    
    bigfile_new->offset = (0xffff00000000 / 4);
    printf("%llx %llx\n", bigfile_new->decomp_size, bigfile_new->comp_size);
    bigfile_new->decomp_size = 0;
    bigfile_new->comp_size = 0;
    
    file_entry* suboffset_wolf = &off4_structs.suboffset_entries[wolf->suboffset_index];
    /*suboffset_wolf->flags &= ~SUBOFFSET_COMPRESSION;
    suboffset_wolf->flags |= SUBOFFSET_DECOMPRESSED;
    suboffset_wolf->comp_size = suboffset_new->decomp_size;*/
    
    for (int i = 0; i < bigfile_new->files; i++)
    {
        int suboffset_index = new_suboffset_idx+i;
        file_entry* suboffset = &off4_structs.suboffset_entries[suboffset_index];
        
        if (suboffset->flags & SUBOFFSET_REDIR)
        {
            suboffset_index += (suboffset->flags & SUBOFFSET_TREE_IDX_MASK);
            suboffset = &off4_structs.suboffset_entries[suboffset_index];
        }
        
        uint64_t comp = suboffset->comp_size;
        uint64_t decomp = suboffset->decomp_size;
        uint64_t comp_aligned = (comp + 0x7) & ~0x7;
        uint64_t decomp_aligned = (decomp + 0x7f) & ~0x7f;

        printf("    %x: %llx %llx %llx %x %llx\n", suboffset_index, suboffset->offset * 4, decomp, comp, suboffset->flags, comp_aligned);
        
        if (suboffset->flags & SUBOFFSET_COMPRESSION)
        {
            bigfile_new->decomp_size += decomp_aligned;
            bigfile_new->comp_size += comp_aligned;
        }
        else
        {
            bigfile_new->decomp_size += comp_aligned;
            bigfile_new->comp_size += comp_aligned;
        }
    }
    
    printf("%llx %llx\n", bigfile_new->decomp_size, bigfile_new->comp_size);
    
    print_tree_entry(wolf);
    print_suboffset(suboffset_new);
    print_big_hash(bighash_new);
    print_big_file(bigfile_new);
    print_entry_pair(&off4_structs.folder_hash_lookup[bighash_new->folderlookup_start + 1]);
}

void dump_file(std::string filepath)
{
    if (arc_version == ARC_100 || arc_version == ARC_110)
    {
        tree_entry* entry = file_lookup(filepath.c_str());
        print_tree_entry(entry);
        dump_tree_entry(entry, unhash[entry->file.hash]);
    }
    else
    {
        tree_entry_200* entry = file_lookup_200(filepath.c_str());
        print_tree_entry_200(entry);
        
        dump_tree_entry_200(entry, unhash[entry->file.hash]);
    }
}

void dump_hash(uint64_t hash)
{
    tree_entry* entry = hash_lookup(hash);
    print_tree_entry(entry);
    dump_tree_entry(entry, "hash2.bin");
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
    
    printf("Big hash table:\n");
    for (int i = 0; i < off4_structs.header->entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_big_hash(&off4_structs.big_hashes[i]);
#endif
    }

    printf("Big file entries:\n");
#ifdef VERBOSE_PRINT
    for (int i = 0; i < off4_structs.header->entries_bigfiles_1 + off4_structs.header->entries_bigfiles_2; i++)
    {
        printf("%06x: ", i);
        print_big_file(&off4_structs.big_files[i]);
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
    
    printf("File Entries:\n");
    for (int i = 0; i < off4_structs.header->tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        print_tree_entry(&off4_structs.tree_entries[i]);
#endif
    }
    
    printf("Suboffset table:\n");
    for (int i = 0; i < off4_structs.header->suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_suboffset(&off4_structs.suboffset_entries[i]);
#endif
    }
    
    printf("Folder to big hash lookup:\n");
    for (int i = 0; i < off4_structs.header->entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_to_big_hash[i]);
#endif
    }

    printf("File->suboffset index lookup buckets: total hashes %08x buckets %08x\n", off4_structs.file_lookup_buckets->index, off4_structs.file_lookup_buckets->num_entries);
    // off4_structs.numbers[hash % table_size].first is lookup start index
    // off4_structs.numbers[hash % table_size].second is lookup search length
    for (int i = 1; i < off4_structs.file_lookup_buckets->num_entries+1; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x\n", i, off4_structs.file_lookup_buckets[i].index, off4_structs.file_lookup_buckets[i].num_entries);
#endif
    }
    
    printf("File->suboffset index lookup table:\n");
    for (int i = 0; i < off4_structs.header->file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.file_lookup[i]);
#endif
    }
    
    printf("Numbers 3:\n");
    for (int i = 0; i < off4_structs.header->tree_entries; i++)
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
    printf("Big hash table:\n");
    for (int i = 0; i < off4_structs.header_200->entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_big_hash(&off4_structs.big_hashes[i]);
#endif
    }

    printf("Big file entries:\n");
#ifdef VERBOSE_PRINT
    for (int i = 0; i < off4_structs.header_200->entries_bigfiles_1 + off4_structs.header_200->entries_bigfiles_2; i++)
    {
        printf("%06x: ", i);
        print_big_file(&off4_structs.big_files[i]);
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
    
    printf("File Entries:\n");
    for (int i = 0; i < off4_structs.header_200->file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        print_tree_entry_200(&off4_structs.tree_entries_200[i]);
#endif
    }
    
    printf("Folder to big hash lookup:\n");
    for (int i = 0; i < off4_structs.header_200->entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_entry_pair(&off4_structs.folder_to_big_hash[i]);
#endif
    }

    printf("File->suboffset index lookup buckets: total hashes %08x buckets %08x\n", off4_structs.file_lookup_buckets->index, off4_structs.file_lookup_buckets->num_entries);
    // off4_structs.numbers[hash % table_size].first is lookup start index
    // off4_structs.numbers[hash % table_size].second is lookup search length
    for (int i = 1; i < off4_structs.file_lookup_buckets->num_entries+1; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x\n", i, off4_structs.file_lookup_buckets[i].index, off4_structs.file_lookup_buckets[i].num_entries);
#endif
    }
    
    printf("File->suboffset index lookup table:\n");
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
    for (int i = 0; i < off4_structs.header_200->unk18 + off4_structs.header_200->post_suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("tree_entry_idx %08x big_folder_idx %08x file_offset_helper_idx %08x flags %08x\n", off4_structs.indexing_helper[i].tree_entry_idx, off4_structs.indexing_helper[i].big_folder_idx, off4_structs.indexing_helper[i].file_offset_helper_idx, off4_structs.indexing_helper[i].flags);
#endif
    }
    
    printf("File offset helper:\n");
    for (int i = 0; i < off4_structs.header_200->unk1C + off4_structs.header_200->post_suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("bigfile_idx %08x suboffset_idx %08x flags %08x\n", off4_structs.file_offset_helper[i].bigfile_idx, off4_structs.file_offset_helper[i].suboffset_idx, off4_structs.file_offset_helper[i].flags);
#endif
    }

    printf("Suboffset table:\n");
    for (int i = 0; i < off4_structs.header_200->suboffset_entries + off4_structs.header_200->post_suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        print_suboffset(&off4_structs.suboffset_entries[i]);
#endif
    }
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("%s <data.arc>\n", argv[0]);
        return -1;
    }
    
    std::ifstream strings("hashstrings.txt");
    
    std::string line;
    while (std::getline(strings, line))
    {
        uint64_t crc = hash40((const void*)line.c_str(), strlen(line.c_str()));
        unhash[crc] = line;
    }
    
    dstream = ZSTD_createDStream();
    size_t const initResult = ZSTD_initDStream(dstream);
    
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
        printf("Big hash entries: %08x\n", off4_structs.header->entries_big);
        printf("Big files 1: %08x\n", off4_structs.header->entries_bigfiles_1);
        printf("File Tree Entries: %08x\n", off4_structs.header->tree_entries);
        
        printf("Suboffset entries: %08x\n", off4_structs.header->suboffset_entries);
        printf("File lookup entries: %08x\n", off4_structs.header->file_lookup_entries);
        printf("Folder hash entries: %08x\n", off4_structs.header->folder_hash_entries);
        printf("File Tree Entries 2: %08x\n", off4_structs.header->tree_entries_2);
        printf("Big files 2: %08x\n", off4_structs.header->entries_bigfiles_2);
        printf("Post-suboffset entries: %08x\n", off4_structs.header->post_suboffset_entries);
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
        printf("Big hash entries: %08x\n", off4_structs.header_200->entries_big);
        
        printf("Big files 1: %08x\n", off4_structs.header_200->entries_bigfiles_1);
        printf("Folder hash entries: %08x\n", off4_structs.header_200->folder_hash_entries);
        printf("Unk18: %08x\n", off4_structs.header_200->unk18);
        printf("Unk1C: %08x\n", off4_structs.header_200->unk1C);
        
        printf("Suboffset entries: %08x\n", off4_structs.header_200->suboffset_entries);
        printf("Big files 2: %08x\n", off4_structs.header_200->entries_bigfiles_2);
        printf("Post-suboffset entries: %08x\n", off4_structs.header_200->post_suboffset_entries);
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
    
    //expand_subfiles_bighash_bigfile();
    
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
            print_folder_tree_entry(&off5_structs.folder_tree[i]);
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
            print_mini_tree_entry(&off5_structs.tree_entries[i]);
    #endif
        }

        free(off5_structs.off5_data);
    }
    free(off4_structs.off4_data);
    
    ZSTD_freeDStream(dstream);
    fclose(arc_file);
}
