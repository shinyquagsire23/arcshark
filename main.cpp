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
    uint32_t unk2;
    uint32_t unk3;
    uint32_t entries;
    
    uint32_t entries_2;
    uint32_t entries_3;
    uint32_t unk6;
    uint32_t entries_4;
    uint32_t unk7;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
    uint32_t unk12;
    uint32_t unk13;
    uint32_t unk14;
    uint32_t unk15;
} offset4_header;

typedef struct offset4_entry
{
    uint32_t a;
    uint8_t b;
    uint8_t c[3];
    uint32_t d;
} offset4_entry;

typedef struct offset5_entry_1
{
    uint32_t a;
    uint8_t b;
    uint8_t c[3];
} offset5_entry_1;

typedef struct offset5_entry_2
{
    uint32_t a;
    uint8_t b;
    uint8_t c[3];
} offset5_entry_2;

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
    
    offset4_header off4_header;
    fseek(f, header.offset_4, SEEK_SET);
    fread(&off4_header, 0x44, 1, f);
    
    printf("Offset 4 Header:\n");
    
    void* off4_data = malloc(off4_header.total_size - 0x44);
    fread(off4_data, off4_header.total_size - 0x44, 1, f);
    
    
    offset4_entry* off4_entries = (offset4_entry*)off4_data;
    for (int i = 0; i < 0x10; i++)
    {
        printf("%x: %08x %02x %02x%02x%02x %08x (%s)\n", i, off4_entries[i].a, off4_entries[i].b, off4_entries[i].c[2], off4_entries[i].c[1], off4_entries[i].c[0], off4_entries[i].d, unhash[off4_entries[i].a].c_str());
    }
    
    
    
    
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
    offset5_entry_1* entries = (offset5_entry_1*)off5_data;
    for (int i = 0; i < 0x40; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries[i].a, entries[i].b, entries[i].c[2], entries[i].c[1], entries[i].c[0], unhash[entries[i].a].c_str());
    }
    
    printf("Hash table 1.2\n");
    offset5_entry_2* entries_2 = (offset5_entry_2*)&entries[off5_header.entries];
    for (int i = 0; i < 0x247a1; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_2[i].a, entries_2[i].b, entries_2[i].c[2], entries_2[i].c[1], entries_2[i].c[0], unhash[entries_2[i].a].c_str());
    }
    
    printf("Hash table 2\n");
    offset5_entry_1* entries_3 = (offset5_entry_1*)&entries_2[0x247a1];
    for (int i = 0; i < off5_header.entries; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_3[i].a, entries_3[i].b,  entries_3[i].c[2], entries_3[i].c[1], entries_3[i].c[0], unhash[entries_3[i].a].c_str());
    }
    
    printf("Hash table 2.2\n");
    offset5_entry_2* entries_4 = (offset5_entry_2*)&entries_3[off5_header.entries];
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
    offset5_entry_2* entries_6 = (offset5_entry_2*)&entries_5[off5_header.entries_2];
    for (int i = 0; i < off5_header.entries_2 * 4; i++)
    {
        //printf("%x: %08x %02x %02x%02x%02x (%s)\n", i, entries_6[i].a, entries_6[i].b, entries_6[i].c[2], entries_6[i].c[1], entries_6[i].c[0], unhash[entries_6[i].a].c_str());
    }
    
    free(off5_data);
    
    fclose(f);
}
