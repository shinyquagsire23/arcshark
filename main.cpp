#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <map>
#include <iostream>
#include <fstream>
#include <zlib.h>
#include <cstring>

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
    uint32_t a;
    uint8_t b;
    uint8_t c[3];
    uint32_t d;
} entry_triplet;

typedef struct entry_pair
{
    uint32_t a;
    uint8_t b;
    uint8_t c[3];
} entry_pair;

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
    entry_pair file;
    entry_pair folder;
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
//#define VERBOSE_PRINT

std::map<uint32_t, std::string> unhash;

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
        uint32_t crc = crc32(0, (const Bytef*)line.c_str(), strlen(line.c_str()));
        unhash[crc] = line;
    }
    
    char* fname = argv[1];
    
    FILE* f = fopen(argv[1], "rb");
    arc_header header;
    
    fread(&header, sizeof(arc_header), 1, f);
    
    printf("Magic: %016llx\n", header.magic);
    printf("Offset 1: %016llx\n", header.offset_1);
    printf("Offset 2: %016llx\n", header.offset_2);
    printf("Offset 3: %016llx\n", header.offset_3);
    printf("Offset 4: %016llx\n", header.offset_4);
    printf("Offset 5: %016llx\n", header.offset_5);
    printf("Offset 6: %016llx\n\n", header.offset_6);
    
    // Offset 4
    offset4_header off4_header;
    offset4_ext_header off4_ext_header;
    fseek(f, header.offset_4, SEEK_SET);
    fread(&off4_header, 0x34, 1, f);
    fread(&off4_ext_header, 0x10, 1, f);

    void* off4_data = malloc(off4_header.total_size - 0x44);
    fread(off4_data, off4_header.total_size - 0x44, 1, f);
    
    printf("Offset 4 Header:\n");
    printf("Total size: %08x\n", off4_header.total_size);
    printf("Big hash entries: %08x\n", off4_header.entries_big);
    printf("Big files 1: %08x\n", off4_header.entries_bigfiles_1);
    printf("File Tree Entries: %08x\n", off4_header.tree_entries);
    
    printf("Suboffset entries: %08x\n", off4_header.suboffset_entries);
    printf("File lookup entries: %08x\n", off4_header.file_lookup_entries);
    printf("Folder hash entries: %08x\n", off4_header.folder_hash_entries);
    printf("File Tree Entries 2: %08x\n", off4_header.tree_entries_2);
    printf("Big files 2: %08x\n", off4_header.entries_bigfiles_2);
    printf("Post-suboffset entries: %08x\n", off4_header.post_suboffset_entries);
    printf("Default alloc alignment: %08x\n", off4_header.alloc_alignment);
    printf("Unk 10: %08x\n", off4_header.unk10);
    printf("Unk 11: %08x\n\n", off4_header.unk11);
    
    printf("Offset 4 Extended Header:\n");
    printf("Hash table 1 entries: %08x\n", off4_ext_header.bgm_unk_movie_entries);
    printf("Hash table 2/3 entries: %08x\n", off4_ext_header.entries);
    printf("Number table entries: %08x\n", off4_ext_header.entries_2);
    printf("Num files: %08x\n\n", off4_ext_header.num_files);
    
    entry_triplet* off4_bulkfile_category_info = (entry_triplet*)off4_data;
    entry_pair* off4_bulkfile_hash_lookup = (entry_pair*)&off4_bulkfile_category_info[off4_ext_header.bgm_unk_movie_entries];
    entry_triplet* off4_bulk_files_by_name = (entry_triplet*)&off4_bulkfile_hash_lookup[off4_ext_header.entries];
    uint32_t* off4_bulkfile_lookup_to_fileidx = (uint32_t*)&off4_bulk_files_by_name[off4_ext_header.entries];
    file_pair* off4_file_pairs = (file_pair*)&off4_bulkfile_lookup_to_fileidx[off4_ext_header.entries_2];
    entry_triplet* off4_weird_hashes = (entry_triplet*)&off4_file_pairs[off4_ext_header.num_files];
    big_hash_entry* off4_big_hashes = (big_hash_entry*)&off4_weird_hashes[off4_header.weird_hash_entries];
    big_file_entry* off4_big_files = (big_file_entry*)&off4_big_hashes[off4_header.entries_big];
    entry_pair* off4_folder_hash_lookup = (entry_pair*)&off4_big_files[off4_header.entries_bigfiles_1 + off4_header.entries_bigfiles_2];
    tree_entry* off4_tree_entries = (tree_entry*)&off4_folder_hash_lookup[off4_header.folder_hash_entries];
    file_entry* off4_suboffset_entries = (file_entry*)&off4_tree_entries[off4_header.tree_entries];
    file_entry* off4_post_suboffset_entries = (file_entry*)&off4_suboffset_entries[off4_header.suboffset_entries];
    entry_pair* off4_folder_to_big_hash = (entry_pair*)&off4_post_suboffset_entries[off4_header.post_suboffset_entries];
    uint32_t* off4_numbers2_header = (uint32_t*)&off4_folder_to_big_hash[off4_header.entries_big];
    uint32_t* off4_numbers2 = (uint32_t*)&off4_numbers2_header[2];
    entry_pair* off4_file_lookup = (entry_pair*)&off4_numbers2[off4_numbers2_header[1]*2];
    entry_pair* off4_numbers3 = (entry_pair* )&off4_file_lookup[off4_header.file_lookup_entries];
    
    printf("Category hash to bulkfile count and idx:\n");
    for (int i = 0; i < off4_ext_header.bgm_unk_movie_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_bulkfile_category_info[i].a, off4_bulkfile_category_info[i].b, off4_bulkfile_category_info[i].c[2], off4_bulkfile_category_info[i].c[1], off4_bulkfile_category_info[i].c[0], off4_bulkfile_category_info[i].d, unhash[off4_bulkfile_category_info[i].a].c_str());
#endif
    }
    
    printf("Bulkfile hash to bulkfile lookup:\n");
    
    for (int i = 0; i < off4_ext_header.entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_bulkfile_hash_lookup[i].a, off4_bulkfile_hash_lookup[i].b, off4_bulkfile_hash_lookup[i].c[2], off4_bulkfile_hash_lookup[i].c[1], off4_bulkfile_hash_lookup[i].c[0], unhash[off4_bulkfile_hash_lookup[i].a].c_str());
#endif
    }
    
    printf("Bulkfile lookup:\n");
    for (int i = 0; i < off4_ext_header.entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_bulk_files_by_name[i].a, off4_bulk_files_by_name[i].b, off4_bulk_files_by_name[i].c[2], off4_bulk_files_by_name[i].c[1], off4_bulk_files_by_name[i].c[0], off4_bulk_files_by_name[i].d, unhash[off4_bulk_files_by_name[i].a].c_str());
#endif
    }
    
    printf("Bulkfile lookup to bulkfile table index:\n");
    for (int i = 0; i < off4_ext_header.entries_2; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x\n", i, off4_bulkfile_lookup_to_fileidx[i]);
#endif
    }
    
    printf("Bulkfile Table:\n");
    for (int i = 0; i < off4_ext_header.num_files; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: size %016llx offs %016llx\n", i, off4_file_pairs[i].size, off4_file_pairs[i].offset);
#endif
    }
    
    printf("Weird hash table:\n");
    for (int i = 0; i < off4_header.weird_hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_weird_hashes[i].a, off4_weird_hashes[i].b, off4_weird_hashes[i].c[2], off4_weird_hashes[i].c[1], off4_weird_hashes[i].c[0], off4_weird_hashes[i].d, unhash[off4_weird_hashes[i].a].c_str());
#endif
    }
    
    printf("Big hash table:\n");
    for (int i = 0; i < off4_header.entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: ", i);
        printf("path %08x %02x %02x%02x%02x, ", off4_big_hashes[i].path.a, off4_big_hashes[i].path.b, off4_big_hashes[i].path.c[2], off4_big_hashes[i].path.c[1], off4_big_hashes[i].path.c[0]);
        printf("folder %08x %02x %02x%02x%02x, ", off4_big_hashes[i].folder.a, off4_big_hashes[i].folder.b, off4_big_hashes[i].folder.c[2], off4_big_hashes[i].folder.c[1], off4_big_hashes[i].folder.c[0]);
        printf("parent %08x %02x %02x%02x%02x, ", off4_big_hashes[i].parent.a, off4_big_hashes[i].parent.b, off4_big_hashes[i].parent.c[2], off4_big_hashes[i].parent.c[1], off4_big_hashes[i].parent.c[0]);
        printf("hash4 %08x %02x %02x%02x%02x, ", off4_big_hashes[i].hash4.a, off4_big_hashes[i].hash4.b, off4_big_hashes[i].hash4.c[2], off4_big_hashes[i].hash4.c[1], off4_big_hashes[i].hash4.c[0]);
        printf("%08x %08x %08x %04x %04x %08x (path %s, folder %s, parent %s, %s)\n", off4_big_hashes[i].unk, off4_big_hashes[i].unk2, off4_big_hashes[i].unk3, off4_big_hashes[i].unk4, off4_big_hashes[i].unk5, off4_big_hashes[i].unk6, unhash[off4_big_hashes[i].path.a].c_str(), unhash[off4_big_hashes[i].folder.a].c_str(), unhash[off4_big_hashes[i].parent.a].c_str(), unhash[off4_big_hashes[i].hash4.a].c_str());
#endif
    }

    printf("Big file entries:\n");
#ifdef VERBOSE_PRINT
    ZSTD_DStream* const dstream = ZSTD_createDStream();
    size_t const initResult = ZSTD_initDStream(dstream);
    for (int i = 0; i < off4_header.entries_bigfiles_1 + off4_header.entries_bigfiles_2; i++)
    {
        printf("%06x: %016llx decomp %08x comp %08x suboffset_index %08x files %08x unk3 %08x\n", i, off4_big_files[i].offset, off4_big_files[i].decomp_size, off4_big_files[i].comp_size, off4_big_files[i].suboffset_index, off4_big_files[i].files, off4_big_files[i].unk3);
        
        if (!off4_big_files[i].comp_size) continue;
        if (off4_big_files[i].unk3 != 0xFFFFFF) continue;
#if 0
        char tmp[0x100];
        snprintf(tmp, 0x100, "%s_extract_raw/%u.comp", argv[1], i);
        FILE* part = fopen(tmp, "wb");
        if (!part) continue;

        void* data = malloc(off4_big_files[i].comp_size);

        fseek(f, header.offset_2 + off4_big_files[i].offset, SEEK_SET);
        fread(data, off4_big_files[i].comp_size, 1, f);

        fwrite(data, off4_big_files[i].comp_size, 1, part);
        fclose(part);
        free(data);
        continue;
#endif
#ifdef DUMP_FILES
        for (int j = 0; j < off4_big_files[i].files; j++)
        {
            file_entry* suboffset = &off4_suboffset_entries[off4_big_files[i].suboffset_index + j];
            printf("    %u_%u: offset %llx, comp %x, decomp %x, flags %x\n", i, j, header.offset_2 + off4_big_files[i].offset + (suboffset->offset * sizeof(uint32_t)), suboffset->comp_size, suboffset->decomp_size, suboffset->flags);
            
            if (!((suboffset->flags & SUBOFFSET_COMPRESSION) == SUBOFFSET_COMPRESSED))
            {
                char tmp[0x100];
                snprintf(tmp, 0x100, "%s_extract_raw/%u_%u", argv[1], i, j);
                FILE* part = fopen(tmp, "wb");
                if (!part) continue;
                
                void* data = malloc(suboffset->decomp_size);
                
                fseek(f, header.offset_2 + off4_big_files[i].offset + (suboffset->offset * sizeof(uint32_t)), SEEK_SET);
                fread(data, suboffset->comp_size, 1, f);
                
                fwrite(data, suboffset->decomp_size, 1, part);
                fclose(part);
                free(data);
                
                continue;
            }
            
            void* data = malloc(suboffset->decomp_size);
            void* data_comp = malloc(suboffset->comp_size);
        
            fseek(f, header.offset_2 + off4_big_files[i].offset + (suboffset->offset * sizeof(uint32_t)), SEEK_SET);
            fread(data_comp, suboffset->comp_size, 1, f);

            ZSTD_resetDStream(dstream);

            ZSTD_inBuffer input = {data_comp, suboffset->comp_size, 0};
            ZSTD_outBuffer output = {data, suboffset->decomp_size, 0};

        
            size_t decompressed = ZSTD_decompressStream(dstream, &output, &input);
            if (ZSTD_isError(decompressed))
            {
                printf("err %s, continuing\n", ZSTD_getErrorName(decompressed));
                free(data);
                free(data_comp);
                continue;
            }

            //printf("decompressed hint %zx output.pos %zx input.pos %zx\n", decompressed, output.pos, input.pos);
            
            char tmp[0x100];
            snprintf(tmp, 0x100, "%s_extract_raw/%u_%u", argv[1], i, j);
            FILE* part = fopen(tmp, "wb");
            if (!part) continue;
            
            fwrite(output.dst, output.pos, 1, part);
            fclose(part);
        
            free(data);
            free(data_comp);
        }
#endif
        
        
        
    }
    ZSTD_freeDStream(dstream);
#endif
    
    printf("Folder Hash table:\n");
    for (int i = 0; i < off4_header.folder_hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_folder_hash_lookup[i].a, off4_folder_hash_lookup[i].b, off4_folder_hash_lookup[i].c[2], off4_folder_hash_lookup[i].c[1], off4_folder_hash_lookup[i].c[0], unhash[off4_folder_hash_lookup[i].a].c_str());
#endif
    }
    
    printf("File Entries:\n");
    for (int i = 0; i < off4_header.tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_tree_entries[i].path.a, off4_tree_entries[i].path.b, off4_tree_entries[i].path.c[2], off4_tree_entries[i].path.c[1], off4_tree_entries[i].path.c[0], unhash[off4_tree_entries[i].path.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off4_tree_entries[i].ext.a, off4_tree_entries[i].ext.b, off4_tree_entries[i].ext.c[2], off4_tree_entries[i].ext.c[1], off4_tree_entries[i].ext.c[0], unhash[off4_tree_entries[i].ext.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off4_tree_entries[i].file.a, off4_tree_entries[i].file.b, off4_tree_entries[i].file.c[2], off4_tree_entries[i].file.c[1], off4_tree_entries[i].file.c[0], unhash[off4_tree_entries[i].file.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off4_tree_entries[i].folder.a, off4_tree_entries[i].folder.b, off4_tree_entries[i].folder.c[2], off4_tree_entries[i].folder.c[1], off4_tree_entries[i].folder.c[0], unhash[off4_tree_entries[i].folder.a].c_str());
        printf("        suboffset index %08x flags %08x\n", off4_tree_entries[i].suboffset_index, off4_tree_entries[i].flags);
#endif
    }
    
    printf("Suboffset table:\n");
    for (int i = 0; i < off4_header.suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x %08x %08x\n", i, off4_suboffset_entries[i].offset, off4_suboffset_entries[i].comp_size, off4_suboffset_entries[i].decomp_size, off4_suboffset_entries[i].flags);
#endif
    }
    
    printf("post-suboffset table:\n");
    for (int i = 0; i < off4_header.post_suboffset_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x %08x %08x\n", i, off4_post_suboffset_entries[i].offset, off4_post_suboffset_entries[i].comp_size, off4_post_suboffset_entries[i].decomp_size, off4_post_suboffset_entries[i].flags);
#endif
    }
    
    printf("Folder to big hash lookup:\n");
    for (int i = 0; i < off4_header.entries_big; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_folder_to_big_hash[i].a, off4_folder_to_big_hash[i].b, off4_folder_to_big_hash[i].c[2], off4_folder_to_big_hash[i].c[1], off4_folder_to_big_hash[i].c[0], unhash[off4_folder_to_big_hash[i].a].c_str());
#endif
    }

    printf("File->suboffset index lookup buckets: total hashes %08x buckets %08x\n", off4_numbers2_header[0], off4_numbers2_header[1]);
    // off4_numbers[hash % table_size].first is lookup start index
    // off4_numbers[hash % table_size].second is lookup search length
    for (int i = 0; i < off4_numbers2_header[1]+1; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %08x\n", i, off4_numbers2[i*2], off4_numbers2[(i*2)+1]);
#endif
    }
    
    printf("File->suboffset index lookup table:\n");
    for (int i = 0; i < off4_header.file_lookup_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_file_lookup[i].a, off4_file_lookup[i].b, off4_file_lookup[i].c[2], off4_file_lookup[i].c[1], off4_file_lookup[i].c[0], unhash[off4_file_lookup[i].a].c_str());
#endif
    }
    
    printf("Numbers 3:\n");
    for (int i = 0; i < off4_header.tree_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off4_numbers3[i].a, off4_numbers3[i].b, off4_numbers3[i].c[2], off4_numbers3[i].c[1], off4_numbers3[i].c[0], unhash[off4_numbers3[i].a].c_str());
#endif
    }
    
    
    
    
    
    
    // Offset 5
    offset5_header off5_header;
    fseek(f, header.offset_5, SEEK_SET);
    fread(&off5_header, 0x14, 1, f);
    
    void* off5_data = malloc(off5_header.total_size - 0x14);
    fread(off5_data, off5_header.total_size - 0x14, 1, f);

    printf("\nOffset 5 Header:\n");
    printf("Total size %016llx\n", off5_header.total_size);
    printf("Folder Entries: %08x\n", off5_header.folder_entries);
    printf("File Entries: %08x\n", off5_header.file_entries);
    printf("Something 2: %08x\n", off5_header.hash_entries);
    
    printf("Folder hash to folder tree entry:\n");
    entry_pair* off5_folderhash_to_foldertree = (entry_pair*)off5_data;
    for (int i = 0; i < off5_header.folder_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off5_folderhash_to_foldertree[i].a, off5_folderhash_to_foldertree[i].b, off5_folderhash_to_foldertree[i].c[2], off5_folderhash_to_foldertree[i].c[1], off5_folderhash_to_foldertree[i].c[0], unhash[off5_folderhash_to_foldertree[i].a].c_str());
#endif
    }
    
    printf("Folder tree:\n");
    folder_tree_entry* off5_folder_tree = (folder_tree_entry*)&off5_folderhash_to_foldertree[off5_header.folder_entries];
    for (int i = 0; i < off5_header.folder_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off5_folder_tree[i].path.a, off5_folder_tree[i].path.b, off5_folder_tree[i].path.c[2], off5_folder_tree[i].path.c[1], off5_folder_tree[i].path.c[0], unhash[off5_folder_tree[i].path.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off5_folder_tree[i].parent.a, off5_folder_tree[i].parent.b, off5_folder_tree[i].parent.c[2], off5_folder_tree[i].parent.c[1], off5_folder_tree[i].parent.c[0], unhash[off5_folder_tree[i].parent.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off5_folder_tree[i].folder.a, off5_folder_tree[i].folder.b, off5_folder_tree[i].folder.c[2], off5_folder_tree[i].folder.c[1], off5_folder_tree[i].folder.c[0], unhash[off5_folder_tree[i].folder.a].c_str());
        printf("        %08x %08x\n", off5_folder_tree[i].idx1, off5_folder_tree[i].idx2);
#endif
    }
    
    printf("File hash to file tree entry:\n");
    entry_pair* entries_13 = (entry_pair*)&off5_folder_tree[off5_header.folder_entries];
    for (int i = 0; i < off5_header.hash_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, entries_13[i].a, entries_13[i].b,  entries_13[i].c[2], entries_13[i].c[1], entries_13[i].c[0], unhash[entries_13[i].a].c_str());
#endif
    }
    
    printf("Numbers:\n");
    uint32_t* off5_numbers = (uint32_t*)&entries_13[off5_header.hash_entries];
    for (int i = 0; i < off5_header.file_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x\n", i, off5_numbers[i]);
#endif
    }
    
    printf("File tree:\n");
    mini_tree_entry* off5_tree_entries = (mini_tree_entry*)&off5_numbers[off5_header.file_entries];
    for (int i = 0; i < off5_header.file_entries; i++)
    {
#ifdef VERBOSE_PRINT
        printf("%06x: %08x %02x %02x%02x%02x (%s)\n", i, off5_tree_entries[i].path.a, off5_tree_entries[i].path.b, off5_tree_entries[i].path.c[2], off5_tree_entries[i].path.c[1], off5_tree_entries[i].path.c[0], unhash[off5_tree_entries[i].path.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off5_tree_entries[i].ext.a, off5_tree_entries[i].ext.b, off5_tree_entries[i].ext.c[2], off5_tree_entries[i].ext.c[1], off5_tree_entries[i].ext.c[0], unhash[off5_tree_entries[i].ext.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off5_tree_entries[i].file.a, off5_tree_entries[i].file.b, off5_tree_entries[i].file.c[2], off5_tree_entries[i].file.c[1], off5_tree_entries[i].file.c[0], unhash[off5_tree_entries[i].file.a].c_str());
        printf("        %08x %02x %02x%02x%02x (%s)\n", off5_tree_entries[i].folder.a, off5_tree_entries[i].folder.b, off5_tree_entries[i].folder.c[2], off5_tree_entries[i].folder.c[1], off5_tree_entries[i].folder.c[0], unhash[off5_tree_entries[i].folder.a].c_str());
#endif
    }

    free(off5_data);
    
    fclose(f);
}
