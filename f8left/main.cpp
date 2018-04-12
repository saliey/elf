#include <iostream>
#include "ElfReader.h"
#include "ElfRebuilder.h"
#include "FDebug.h"
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>

const char* short_options = "hdm:s:o:";
const struct option long_options[] = {
        {"help", 0, NULL, 'h'},
        {"debug", 0, NULL, 'd'},
        {"memso", 1, NULL, 'm'},
        {"source", 1, NULL, 's'},
        {"output", 1, NULL, 'o'},
        {nullptr, 0, nullptr, 0}
};
void useage();

int main(int argc, char* argv[]) {
    int c;

    ElfReader elf_reader;

    std::string source, output;
    bool isValidArg = true;
    while((c = getopt_long(argc, argv, short_options, long_options, nullptr)) != -1) {
        switch (c) {
            case 'd':
                FDebug = true;
                printf("Use debug mode\n");
                break;
            case 's':
                source = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            case 'm': {
                auto is16Bit = [](const char* c) {
                    auto len = strlen(c);
                    if(len > 2) {
                        if(c[0] == '0' & c[1] == 'x') return true;
                    }
                    bool is10bit = true;
                    for(auto i = 0; i < len; i++) {
                        if((c[i] > 'a' && c[i] < 'f') ||
                                c[i] > 'A' && c[i] < 'F') {
                            is10bit = false;
                        }
                    }
                    return !is10bit;
                };
#ifndef __LP64__
                auto base = strtoul(optarg, 0, is16Bit(optarg) ? 16: 10);
#else
                auto base = strtoull(optarg, 0, is16Bit(optarg) ? 16: 10);
#endif
                elf_reader.setDumpSoFile(true);
                elf_reader.setDumpSoBaseAddr(base);
            }
                break;
            default:
                isValidArg = false;
                break;
        }
    }
    if(!isValidArg) {
        useage();
        return -1;
    }

    auto file = fopen(source.c_str(), "rb");
    if(nullptr == file) {
        printf("source so file cannot found!!!\n");
        return -1;
    }
    auto fd = fileno(file);
	
	

    printf("start to rebuild elf file\n");
    elf_reader.setSource(source.c_str(), fd);

    if(!elf_reader.Load()) {
        printf("source so file is invalid\n");
        return -1;
    }

    ElfRebuilder elf_rebuilder(&elf_reader);
	
	struct stat statbuf;
	stat(source.c_str(), &statbuf);
	int size = statbuf.st_size;
	FILE *rdfile = fopen(source.c_str(), "rb");
	void* mmadd = mmap(0, size, 3, 2, fd, 0);
	elf_rebuilder.setFileSize(size, mmadd);
	
	printf("mmap : %x \n", mmadd);
	printf("total filesize : %x , fileaddr : %x , refile : %x , fxx : %x , buff : %x \n", size, file, rdfile, *file, statbuf);
	
    if(!elf_rebuilder.Rebuild()) {
        printf("error occured in rebuilding elf file\n");
        return -1;
    }
    fclose(file);

    file = fopen(output.c_str(), "wb+");

    if(nullptr == file) {
        printf("output so file cannot write !!!\n");
        return -1;
    }
	printf("rebuild_size :  %x \n", elf_rebuilder.getRebuildSize());
    fwrite(elf_rebuilder.getRebuildData(), elf_rebuilder.getRebuildSize(), 1, file);
	printf("rebuild_cpy :  %x , sor : %x , size : %x \n", file, rdfile, size);
	//memcpy(file, rdfile, size);
    fclose(file);

    printf("Done!!!\n");
    return 0;
}

void useage() {
    printf("SoFixer v0.2 author F8LEFT(currwin)\n");
    printf("Useage: SoFixer <option(s)> -s sourcefile -o generatefile\n");
    printf(" try rebuild shdr with phdr\n");
    printf(" Options are:\n");

    printf("  -d --debug                                 Show debug info\n");
    printf("  -m --memso memBaseAddr(16bit format)       Source file is dump from memory from address x\n");
    printf("  -s --source sourceFilePath                 Source file path\n");
    printf("  -o --output generateFilePath               Generate file path\n");
    printf("  -h --help                                  Display this information\n");

}
