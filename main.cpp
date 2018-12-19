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
    uint32_t unk;
    uint32_t unk2;
    uint32_t unk3;
    uint16_t unk4;
    uint16_t unk5;
    uint32_t unk6;
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

typedef struct offset4_structs
{
    void* off4_data;
    offset4_header* header;
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
    file_entry* post_suboffset_entries;
    entry_pair* folder_to_big_hash;
    hash_bucket* file_lookup_buckets;
    entry_pair* file_lookup;
    entry_pair* numbers3;
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

#define TREE_ALIGN_MASK           0xfffe0
#define TREE_ALIGN_LSHIFT         (5)
#define TREE_UNK

#define SUBOFFSET_TREE_IDX_MASK     0x00FFFFFF
#define SUBOFFSET_REDIR             0x40000000
#define SUBOFFSET_UNK_BIT29         0x20000000
#define SUBOFFSET_UNK_BIT27         0x08000000
#define SUBOFFSET_UNK_BIT26         0x04000000

#define SUBOFFSET_COMPRESSION       0x07000000
#define SUBOFFSET_DECOMPRESSED      0x00000000
#define SUBOFFSET_UND               0x01000000
#define SUBOFFSET_COMPRESSED_LZ4    0x02000000
#define SUBOFFSET_COMPRESSED_ZSTD   0x03000000
#define VERBOSE_PRINT

FILE* arc_file;
arc_header arc_head;
offset4_structs off4_structs;
offset5_structs off5_structs;
ZSTD_DStream* dstream;

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
    printf("%08x %08x %08x %04x %04x %08x (path %s, folder %s, parent %s, %s)\n", entry->unk, entry->unk2, entry->unk3, entry->unk4, entry->unk5, entry->unk6, unhash[entry->path.hash].c_str(), unhash[entry->folder.hash].c_str(), unhash[entry->parent.hash].c_str(), unhash[entry->hash4.hash].c_str());
}

void print_big_file(big_file_entry* entry)
{
    printf("%016llx decomp %08x comp %08x suboffset_index %08x files %08x unk3 %08x\n", entry->offset, entry->decomp_size, entry->comp_size, entry->suboffset_index, entry->files, entry->unk3);
}

tree_entry* file_lookup(const char* path)
{
    uint64_t hash = hash40(path, strlen(path));
    hash_bucket bucket = off4_structs.file_lookup_buckets[(hash % off4_structs.file_lookup_buckets->num_entries) + 1];
    entry_pair* found = (entry_pair*)bsearch(&hash, &off4_structs.file_lookup[bucket.index], bucket.num_entries, sizeof(entry_pair), hash40_compar);
    
    return &off4_structs.tree_entries[found->meta];
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

    fseek(arc_file, arc_head.offset_2 + bigfile->offset + (suboffset->offset * sizeof(uint32_t)), SEEK_SET);
    fread(data_comp, suboffset->comp_size, 1, arc_file);

    if (!zstd_decomp(data_comp, data, suboffset->comp_size, suboffset->decomp_size))
    {
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
    big_hash_entry* bighash = &off4_structs.big_hashes[entry->path.meta];
    big_file_entry* bigfile = &off4_structs.big_files[bighash->path.meta];
    print_big_hash(bighash);
    print_big_file(bigfile);

    dump_file(bigfile, &off4_structs.suboffset_entries[entry->suboffset_index], outpath);
}

void calc_offset4_structs(offset4_structs* off4)
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
    off4->post_suboffset_entries = (file_entry*)&off4->suboffset_entries[off4->header->suboffset_entries];
    off4->folder_to_big_hash = (entry_pair*)&off4->post_suboffset_entries[off4->header->post_suboffset_entries];
    off4->file_lookup_buckets = (hash_bucket*)&off4->folder_to_big_hash[off4->header->entries_big];
    off4->file_lookup = (entry_pair*)&off4->file_lookup_buckets[off4->file_lookup_buckets->num_entries+1];
    off4->numbers3 = (entry_pair*)&off4->file_lookup[off4->header->file_lookup_entries];
}

void expand_subfiles_bighash_bigfile()
{
    offset4_structs newvals = off4_structs;
    
    newvals.header->entries_big += 1;
    newvals.header->post_suboffset_entries += 5;
    
    calc_offset4_structs(&newvals);
    
    memmove(newvals.numbers3, off4_structs.numbers3, off4_structs.header->tree_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup, off4_structs.file_lookup, off4_structs.header->file_lookup_entries * sizeof(entry_pair));
    memmove(newvals.file_lookup_buckets, off4_structs.file_lookup_buckets, (off4_structs.file_lookup_buckets->num_entries+1) * sizeof(hash_bucket));
    memmove(newvals.folder_to_big_hash, off4_structs.folder_to_big_hash, off4_structs.header->entries_big * sizeof(entry_pair));
    memmove(newvals.post_suboffset_entries, off4_structs.post_suboffset_entries, off4_structs.header->post_suboffset_entries * sizeof(file_entry));
    memmove(newvals.suboffset_entries, off4_structs.suboffset_entries, off4_structs.header->suboffset_entries * sizeof(file_entry));
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
}

void dump_file(std::string filepath)
{
    tree_entry* entry = file_lookup(filepath.c_str());
    print_tree_entry(entry);
    dump_tree_entry(entry, unhash[entry->file.hash]);
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
    
    fread(&arc_head, sizeof(arc_header), 1, arc_file);
    
    printf("Magic: %016llx\n", arc_head.magic);
    printf("Offset 1: %016llx\n", arc_head.offset_1);
    printf("Offset 2: %016llx\n", arc_head.offset_2);
    printf("Offset 3: %016llx\n", arc_head.offset_3);
    printf("Offset 4: %016llx\n", arc_head.offset_4);
    printf("Offset 5: %016llx\n", arc_head.offset_5);
    printf("Offset 6: %016llx\n\n", arc_head.offset_6);
    
    // Offset 4
    arc_section section;
    fseek(arc_file, arc_head.offset_4, SEEK_SET);
    fread(&section, sizeof(section), 1, arc_file);
    
    if (section.data_start < 0x100)
    {
        off4_structs.off4_data = malloc(section.decomp_size);
        off4_structs.header = (offset4_header*)off4_structs.off4_data;
        off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header));

        void* comp_tmp = malloc(section.comp_size);
        
        fseek(arc_file, arc_head.offset_4 + section.data_start, SEEK_SET);
        fread(comp_tmp, section.comp_size, 1, arc_file);
        printf("%lx %x\n", section.data_start, *(uint32_t*)comp_tmp);
        
        zstd_decomp(comp_tmp, off4_structs.off4_data, section.zstd_comp_size, section.decomp_size);
        
        free(comp_tmp);
    }
    else
    {
        off4_structs.off4_data = malloc(section.data_start); // total_size
        off4_structs.header = (offset4_header*)off4_structs.off4_data;
        off4_structs.ext_header = (offset4_ext_header*)(off4_structs.off4_data + sizeof(offset4_header));
        
        fseek(arc_file, arc_head.offset_4, SEEK_SET);
        fread(off4_structs.header, 0x34, 1, arc_file);
        fread(off4_structs.ext_header, 0x10, 1, arc_file);

        fread(off4_structs.off4_data + sizeof(offset4_header) + sizeof(offset4_ext_header), off4_structs.header->total_size - (sizeof(offset4_header) + sizeof(offset4_ext_header)), 1, arc_file);
    }
    
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
    
    printf("Offset 4 Extended Header:\n");
    printf("Hash table 1 entries: %08x\n", off4_structs.ext_header->bgm_unk_movie_entries);
    printf("Hash table 2/3 entries: %08x\n", off4_structs.ext_header->entries);
    printf("Number table entries: %08x\n", off4_structs.ext_header->entries_2);
    printf("Num files: %08x\n\n", off4_structs.ext_header->num_files);
    
    calc_offset4_structs(&off4_structs);
    
    //expand_subfiles_bighash_bigfile();
    
    // Sample lookup
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
        printf("%06x: ");
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
        printf("%06x: %08x %08x %08x %08x\n", i, off4_structs.suboffset_entries[i].offset, off4_structs.suboffset_entries[i].comp_size, off4_structs.suboffset_entries[i].decomp_size, off4_structs.suboffset_entries[i].flags);
#endif
    }
    
    printf("post-suboffset table:\n");
    for (int i = 0; i < off4_structs.header->post_suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x %08x %08x\n", i, off4_structs.post_suboffset_entries[i].offset, off4_structs.post_suboffset_entries[i].comp_size, off4_structs.post_suboffset_entries[i].decomp_size, off4_structs.post_suboffset_entries[i].flags);
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
    
    off5_structs.folderhash_to_foldertree = (entry_pair*)&off5_structs.header[1];
    off5_structs.folder_tree = (folder_tree_entry*)&off5_structs.folderhash_to_foldertree[off5_structs.header->folder_entries];
    off5_structs.entries_13 = (entry_pair*)&off5_structs.folder_tree[off5_structs.header->folder_entries];
    off5_structs.numbers = (uint32_t*)&off5_structs.entries_13[off5_structs.header->hash_entries];
    off5_structs.tree_entries = (mini_tree_entry*)&off5_structs.numbers[off5_structs.header->file_entries];
    
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
    free(off4_structs.off4_data);
    
    ZSTD_freeDStream(dstream);
    fclose(arc_file);
}
