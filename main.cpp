#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <map>
#include <iostream>
#include <fstream>
#include <zlib.h>
#include <cstring>

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
    uint32_t entries;
    uint32_t entries_2;
    uint32_t something2;
} offset5_header;

typedef struct offset4_header
{
    uint32_t total_size;
    uint32_t entries_big;
    uint32_t entries_bigfiles_1;
    uint32_t entries;
    
    uint32_t entries_2;
    uint32_t entries_3;
    uint32_t unk6;
    uint32_t entries_4;
    
    uint32_t entries_bigfiles_2;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    
    uint32_t unk11;
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
    entry_pair hash1;
    entry_pair hash2;
    entry_pair hash3;
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
    uint32_t unk;
    uint32_t unk2;
    uint32_t unk3;
} __attribute__((packed)) big_file_entry;

typedef struct quad_entry
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} quad_entry;

std::map<uint32_t, std::string> unhash;

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("%s <data.arc>\n", argv[0]);
    }
    
    std::ifstream strings("strings.txt");
    
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
    printf("Entries: %08x\n", off4_header.entries);
    
    printf("Entries 2: %08x\n", off4_header.entries_2);
    printf("Entries 3: %08x\n", off4_header.entries_3);
    printf("Unk 6: %08x\n", off4_header.unk6);
    printf("Entries 4: %08x\n", off4_header.entries_4);
    printf("Big files 2: %08x\n", off4_header.entries_bigfiles_2);
    printf("Unk 8: %08x\n", off4_header.unk8);
    printf("Unk 9: %08x\n", off4_header.unk9);
    printf("Unk 10: %08x\n", off4_header.unk10);
    printf("Unk 11: %08x\n\n", off4_header.unk11);
    
    printf("Offset 4 Extended Header:\n");
    printf("Hash table 1 entries: %08x\n", off4_ext_header.bgm_unk_movie_entries);
    printf("Hash table 2/3 entries: %08x\n", off4_ext_header.entries);
    printf("Number table entries: %08x\n", off4_ext_header.entries_2);
    printf("Num files: %08x\n\n", off4_ext_header.num_files);


    printf("Hash table 1:\n");
    entry_triplet* off4_entries = (entry_triplet*)off4_data;
    for (int i = 0; i < off4_ext_header.bgm_unk_movie_entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_entries[i].a, off4_entries[i].b, off4_entries[i].c[2], off4_entries[i].c[1], off4_entries[i].c[0], off4_entries[i].d, unhash[off4_entries[i].a].c_str());
    }
    
    printf("Hash table 2:\n");
    entry_pair* off4_entries_2 = (entry_pair*)&off4_entries[3];
    for (int i = 0; i < off4_ext_header.entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, off4_entries_2[i].a, off4_entries_2[i].b, off4_entries_2[i].c[2], off4_entries_2[i].c[1], off4_entries_2[i].c[0], unhash[off4_entries_2[i].a].c_str());
    }
    
    printf("Hash table 3:\n");
    entry_triplet* off4_entries_3 = (entry_triplet*)&off4_entries_2[off4_ext_header.entries];
    for (int i = 0; i < off4_ext_header.entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_entries_3[i].a, off4_entries_3[i].b, off4_entries_3[i].c[2], off4_entries_3[i].c[1], off4_entries_3[i].c[0], off4_entries_3[i].d, unhash[off4_entries_3[i].a].c_str());
    }
    
    printf("Number table:\n");
    uint32_t* off4_nums = (uint32_t*)&off4_entries_3[off4_ext_header.entries];
    for (int i = 0; i < off4_ext_header.entries_2; i++)
    {
        //printf("%x: %08x\n", i, off4_nums[i]);
    }
    
    printf("File Table:\n");
    file_pair* file_pairs = (file_pair*)&off4_nums[off4_ext_header.entries_2];
    for (int i = 0; i < off4_ext_header.num_files; i++)
    {
        //printf("%x: size %016llx offs %016llx\n", i, file_pairs[i].size, file_pairs[i].offset);
    }
    
    printf("Weird hash table:\n");
    entry_triplet* weird_hashes = (entry_triplet*)&file_pairs[off4_ext_header.num_files];
    for (int i = 0; i < 0xE; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x %08x (%s)\n", i, weird_hashes[i].a, weird_hashes[i].b, weird_hashes[i].c[2], weird_hashes[i].c[1], weird_hashes[i].c[0], weird_hashes[i].d, unhash[weird_hashes[i].a].c_str());
    }
    
    printf("Big hash table:\n");
    big_hash_entry* big_hashes = (big_hash_entry*)&weird_hashes[0xE];
    for (int i = 0; i < off4_header.entries_big; i++)
    {
        /*printf("%06x: ", i);
        printf("hash1 %08x %02x %02x%02x%02x, ", big_hashes[i].hash1.a, big_hashes[i].hash1.b, big_hashes[i].hash1.c[2], big_hashes[i].hash1.c[1], big_hashes[i].hash1.c[0]);
        printf("hash2 %08x %02x %02x%02x%02x, ", big_hashes[i].hash2.a, big_hashes[i].hash2.b, big_hashes[i].hash2.c[2], big_hashes[i].hash2.c[1], big_hashes[i].hash2.c[0]);
        printf("hash3 %08x %02x %02x%02x%02x, ", big_hashes[i].hash3.a, big_hashes[i].hash3.b, big_hashes[i].hash3.c[2], big_hashes[i].hash3.c[1], big_hashes[i].hash3.c[0]);
        printf("hash4 %08x %02x %02x%02x%02x, ", big_hashes[i].hash4.a, big_hashes[i].hash4.b, big_hashes[i].hash4.c[2], big_hashes[i].hash4.c[1], big_hashes[i].hash4.c[0]);
        printf("%08x %08x %08x %04x %04x %08x (%s, %s, %s, %s)\n", big_hashes[i].unk, big_hashes[i].unk2, big_hashes[i].unk3, big_hashes[i].unk4, big_hashes[i].unk5, big_hashes[i].unk6, unhash[big_hashes[i].hash1.a].c_str(), unhash[big_hashes[i].hash2.a].c_str(), unhash[big_hashes[i].hash3.a].c_str(), unhash[big_hashes[i].hash4.a].c_str());*/
    }
    
    printf("Big file entries:\n");
    big_file_entry* big_files = (big_file_entry*)&big_hashes[off4_header.entries_big];
    for (int i = 0; i < off4_header.entries_bigfiles_1 + off4_header.entries_bigfiles_2; i++)
    {
        //printf("%06x: %016llx decomp %08x comp %08x unks %08x %08x %08x\n", i, big_files[i].offset, big_files[i].decomp_size, big_files[i].comp_size, big_files[i].unk, big_files[i].unk2, big_files[i].unk3);
    }
    
    printf("Hash table 4:\n");
    entry_pair* off4_entries_4 = (entry_pair*)&big_files[off4_header.entries_bigfiles_1 + off4_header.entries_bigfiles_2];
    for (int i = 0; i < 0x248f73; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, off4_entries_4[i].a, off4_entries_4[i].b, off4_entries_4[i].c[2], off4_entries_4[i].c[1], off4_entries_4[i].c[0], unhash[off4_entries_4[i].a].c_str());
    }
    
    printf("Quad table:\n");
    quad_entry* quad_entries = (quad_entry*)&off4_entries_4[0x248f73];
    for (int i = 0; i < 0x89b11; i++)
    {
        //printf("%x: %08x %08x %08x %08x\n", i, quad_entries[i].a, quad_entries[i].b, quad_entries[i].c, quad_entries[i].d);
    }
    
    printf("Hash table 5:\n");
    entry_pair* off4_entries_5 = (entry_pair*)&quad_entries[0x89b11];
    for (int i = 0; i < off4_header.entries_big; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, off4_entries_5[i].a, off4_entries_5[i].b, off4_entries_5[i].c[2], off4_entries_5[i].c[1], off4_entries_5[i].c[0], unhash[off4_entries_5[i].a].c_str());
    }
    
    printf("Numbers:\n");
    uint32_t* off4_numbers = (uint32_t*)&off4_entries_5[off4_header.entries_big];
    
    //TODO not hashes
    printf("Hash table 6:\n");
    entry_pair* off4_entries_6 = (entry_pair*)&off4_numbers[0x802];
    for (int i = 0; i < off4_header.entries_3; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, off4_entries_6[i].a, off4_entries_6[i].b, off4_entries_6[i].c[2], off4_entries_6[i].c[1], off4_entries_6[i].c[0], unhash[off4_entries_6[i].a].c_str());
    }
    
    printf("numbers 2:\n");
    //TODO
    
    
    
    
    
    
    // Offset 5
    offset5_header off5_header;
    fseek(f, header.offset_5, SEEK_SET);
    fread(&off5_header, 0x14, 1, f);
    
    void* off5_data = malloc(off5_header.total_size - 0x14);
    fread(off5_data, off5_header.total_size - 0x14, 1, f);

    printf("Offset 5 Header:\n");
    printf("Total size %016llx\n", off5_header.total_size);
    printf("Entries: %08x\n", off5_header.entries);
    printf("Entries 2: %08x\n", off5_header.entries_2);
    
    printf("Hash table 1\n");
    entry_pair* entries = (entry_pair*)off5_data;
    for (int i = 0; i < off5_header.entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries[i].a, entries[i].b, entries[i].c[2], entries[i].c[1], entries[i].c[0], unhash[entries[i].a].c_str());
    }
    
    printf("Hash table 1.2\n");
    entry_pair* entries_2 = (entry_pair*)&entries[off5_header.entries];
    for (int i = 0; i < 0x247a1; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_2[i].a, entries_2[i].b, entries_2[i].c[2], entries_2[i].c[1], entries_2[i].c[0], unhash[entries_2[i].a].c_str());
    }
    
    printf("Hash table 2\n");
    entry_pair* entries_3 = (entry_pair*)&entries_2[0x247a1];
    for (int i = 0; i < off5_header.entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_3[i].a, entries_3[i].b,  entries_3[i].c[2], entries_3[i].c[1], entries_3[i].c[0], unhash[entries_3[i].a].c_str());
    }
    
    printf("Hash table 2.2\n");
    entry_pair* entries_4 = (entry_pair*)&entries_3[off5_header.entries];
    for (int i = 0; i < 0x71a94; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_4[i].a, entries_4[i].b, entries_4[i].c[2], entries_4[i].c[1], entries_4[i].c[0], unhash[entries_4[i].a].c_str());
    }
    
    uint32_t* entries_5 = (uint32_t*)&entries_4[0x71a94];
    /*for (int i = 0; i < off5_header.entries_2; i++)
    {
        printf("%016llx\n", entries_5[i]);
    }*/
    
    printf("Hash table 3\n");
    entry_pair* entries_6 = (entry_pair*)&entries_5[off5_header.entries_2];
    for (int i = 0; i < off5_header.entries_2 * 4; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_6[i].a, entries_6[i].b, entries_6[i].c[2], entries_6[i].c[1], entries_6[i].c[0], unhash[entries_6[i].a].c_str());
    }
    
    free(off5_data);
    
    fclose(f);
}
