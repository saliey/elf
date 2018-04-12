//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include "ElfRebuilder.h"
#include "elf.h"
#include "FDebug.h"


ElfRebuilder::ElfRebuilder(ElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}



bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=======================RebuildPhdr=========================\n");
    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for(auto i = 0; i < elf_reader_->phdr_count(); i++) {
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        // p_paddr and p_align is not used in load, just ignore it.
        // fix file offset.
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
        phdr++;
    }
    FLOGD("=====================RebuildPhdr End======================\n");
    return true;
}

bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr======ss===================\n");
    // rebuilding shdr, link information
    auto base = si.load_bias;
    shstrtab.push_back('\0');
	FLOGD("ensure step start \n");
    // empty shdr
    if(true) {
		FLOGD("step 1 \n");
        Elf_Shdr shdr = {0};
        shdrs.push_back(shdr);
    }
	
	bool tohash = false;

    // gen .dynsym
    if(si.symtab != nullptr) {
		FLOGD("step 2 \n");
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.symtab - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // calc sh_size later(pad to next shdr)
        shdr.sh_link = 0;   // link to dynstr later
//        shdr.sh_info = 1;
        shdr.sh_info = 2;		// 修复
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;

        shdrs.push_back(shdr);
    }

    // gen .dynstr
    if(si.strtab != nullptr) {
		FLOGD("step 3 \n");
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynstr");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.strtab - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.strtabsize;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
		tohash = true;
    }

    // gen .hash
    if(si.hash != 0) {
		FLOGD("step 4 \n");
        sHASH = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO 32bit, 64bit?
        shdr.sh_size = (si.nbucket + si.nchain) * 4 + 2 * 4;	//sizeof(Elf_Addr)
        shdr.sh_link = sDYNSYM;	//sDYNSYM
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x4;

        shdrs.push_back(shdr);
    }

    // gen .rel.dyn
    if(si.rel != nullptr) {
		FLOGD("step 5 \n");
        sRELDYN = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.rel - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.rel_count * sizeof(Elf_Rela);
        shdr.sh_link = sDYNSYM;	// sDYNSYM
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }

    // gen .rel.plt
    if(si.plt_rel != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rela.plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (Elf_Addr)si.plt_rel - base;
        shdr.sh_offset = shdr.sh_addr;		
		FLOGD("step 6 si.plt_rel_count : %x , size: %x \n", si.plt_rel_count, sizeof(Elf_Rela));
        shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rela);	// v + 8
        shdr.sh_link = sDYNSYM;	// sDYNSYM
        shdr.sh_info = 8;		// 修复
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;

        shdrs.push_back(shdr);
    }

    // gen .plt with .rel.plt
    if(si.plt_rel != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = shdrs[sRELPLT].sh_addr + shdrs[sRELPLT].sh_size + 8;		// 16字节对齐？
		FLOGD("step 7 sh_addr : %x , size: %x \n", shdr.sh_addr, sizeof(Elf_Rela));
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
		FLOGD("step 77 si.plt_rel_count : %x \n", si.plt_rel_count);
        shdr.sh_size = 4*8 /*Pure code*/ + 16 * si.plt_rel_count;		// plt 大小计算
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 16;
        shdr.sh_entsize = 0x10;

        shdrs.push_back(shdr);
    }

    // gen.text&ARM.extab
    if(si.plt_rel != nullptr) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text");		// 更改：&.ARM.extab
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;		// 添加权限		 | SHF_WRITE
        shdr.sh_addr =  si.intAddr; //shdrs[sPLT].sh_addr;		//  + shdrs[sPLT].sh_size 修改起始偏移
        // Align 8
        //while (shdr.sh_addr & 0x7) {
        //    shdr.sh_addr ++;
        //}
		
		shdr.sh_addr = shdr.sh_addr % 4 == 0 ? shdr.sh_addr : shdr.sh_addr + 4 - shdr.sh_addr % 4;
		FLOGD("step 8 shdr.sh_addr : %x , align : %x \n", shdr.sh_addr, shdr.sh_addr % 4);

        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;       // calc later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen ARM.exidx
    if(si.ARM_exidx != nullptr) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".ARM.exidx");
        shstrtab.push_back('\0');
		FLOGD(".ARM.exidx invoke \n");
        shdr.sh_type = SHT_ARMEXIDX;
        shdr.sh_flags = SHF_ALLOC | SHF_LINK_ORDER;
        shdr.sh_addr = (Elf_Addr)si.ARM_exidx - base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.ARM_exidx_count * sizeof(Elf_Addr);
        shdr.sh_link = sTEXTTAB;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }
    // gen .fini_array
    if(si.fini_array != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".fini_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.fini_array - base;
        shdr.sh_offset = si.sLoadOff + 8;		// 修复偏移，此时设置为空
        shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .init_array
    if(si.init_array != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".init_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.init_array - base;
        shdr.sh_offset = si.sLoadOff;
        shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .dynamic
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynamic");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNAMIC;		// SHT_STRTAB  SHT_DYNAMIC
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (Elf_Addr)si.dynamic - base;
        shdr.sh_offset = si.dycOffs;
		FLOGD("dynamicOff 10 dynamic  : %x \n", shdr.sh_offset);
        shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
        shdr.sh_link = sDYNSTR;		// sDYNSTR
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x10;

        shdrs.push_back(shdr);
    }

    // get .got
    if(si.plt_got != nullptr) {
        // global_offset_table
        sGOT = shdrs.size();
        auto sLast = sGOT - 1;

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".got");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;		
        // Align8??
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

        shdr.sh_offset = shdrs[sDYNAMIC].sh_offset + shdrs[sDYNAMIC].sh_size;		// 知识点:为动态链接库的结尾
		FLOGD("got 11 off  : %x \n", shdr.sh_offset);
        //shdr.sh_size = (Elf_Addr)(si.plt_got + si.plt_rel_count * 0x10) - shdr.sh_addr - base + 3 * sizeof(Elf_Addr);		// 未知？
		shdr.sh_size = si.plt_rel_count * 0x10;		// 这里暂未算出具体的计算值
		FLOGD("got 112 off  : %x \n", shdr.sh_size);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }

    // gen .data
    if(true) {
        sDATA = shdrs.size();
        auto sLast = sDATA - 1;

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".data");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
        shdr.sh_offset = shdrs[sGOT].sh_offset + shdrs[sGOT].sh_size;		// 修复偏移
		FLOGD("data seg 121 off  : %x , off : %x \n", shdr.sh_offset, si.sLoadSize + si.sLoadOff);
        shdr.sh_size = si.sLoadSize + si.sLoadOff - shdr.sh_offset;		// 修复大小
		FLOGD("data seg 12 off  : %x , off : %x \n", shdr.sh_offset, shdr.sh_size);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }
/*
    // gen .bss
    if(true) {
        sBSS = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".bss");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_NOBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdrs[sDATA].sh_offset + shdrs[sDATA].sh_size;		// 指向内部区域
		FLOGD("bss seg 13 off  : %x , off : %x \n", shdr.sh_offset);
        shdr.sh_size = 0;   // not used
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }
*/
    // gen .shstrtab, pad into last data
    if(true) {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".shstrtab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = 0;
        shdr.sh_addr = 0;
        shdr.sh_offset = fileSize;
        shdr.sh_size = shstrtab.length();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }
	
    // link section data
    if(sDYNSYM != 0) {
        shdrs[sDYNSYM].sh_link = sDYNSTR;	//sDYNSTR
    }
/*
    // sort shdr and recalc size
    for(auto i = 1; i < shdrs.size(); i++) {
        for(auto j = i + 1; j < shdrs.size(); j++) {
            if(shdrs[i].sh_addr > shdrs[j].sh_addr) {
                // exchange i, j
                auto tmp = shdrs[i];
                shdrs[i] = shdrs[j];
                shdrs[j] = tmp;

                // exchange index
                auto chgIdx = [i, j](Elf_Word &t) {
                    if(t == i) {
                        t = j;
                    } else if(t == j) {
                        t = i;
                    }
                };
				
                chgIdx(sDYNSYM);
                chgIdx(sDYNSTR);
                chgIdx(sHASH);
                chgIdx(sRELDYN);
                chgIdx(sRELPLT);
                chgIdx(sPLT);
                chgIdx(sTEXTTAB);
                chgIdx(sARMEXIDX);
                chgIdx(sFINIARRAY);
                chgIdx(sINITARRAY);
                chgIdx(sDYNAMIC);
                chgIdx(sGOT);
                chgIdx(sDATA);
                chgIdx(sBSS);
                chgIdx(sSHSTRTAB);
            }
        }
    }
*/
    if(sDYNSYM != 0) {
        auto sNext = sDYNSYM + 1;
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sTEXTTAB + 1;
        shdrs[sTEXTTAB].sh_size = si.fLoadSize - shdrs[sTEXTTAB].sh_addr;	// 修复 textsize
		FLOGD("text section length : %x \n", shdrs[sTEXTTAB].sh_size);
    }

    // fix for size
    for(auto i = 2; i < shdrs.size(); i++) {
        if(shdrs[i].sh_offset - shdrs[i-1].sh_offset < shdrs[i-1].sh_size) {
            shdrs[i-1].sh_size = shdrs[i].sh_offset - shdrs[i-1].sh_offset;
        }
    }

    FLOGD("=====================RebuildShdr End======================\n");
    return true;
}

bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() && ReadFileOffset() && ReadSoInfo() && RebuildShdr() && RebuildRelocs() && RebuildFin();
}


bool ElfRebuilder::ReadFileOffset() {
	FLOGD("=================segment======getFileOffset=========================\n");
	Elf64_Ehdr* elf64_ehdrrr = (Elf64_Ehdr*) ffd;
	unsigned seg_count = elf64_ehdrrr->e_phnum;
	size_t seg_off = elf64_ehdrrr->e_phoff;
	unsigned indexx = 0;
	int aa = 0;
	FLOGD("segment off : %x,  seg_count : %x  \n", seg_off, seg_count);
	for (Elf64_Phdr* mm = (Elf64_Phdr*) (ffd + seg_off); indexx < seg_count; mm++) {
		bool firstt = false;
		if(mm->p_type == PT_LOAD && aa == 0) {
			si.fLoadSize = mm->p_filesz;
			FLOGD("dynamicOff first loadsize : %x \n", si.fLoadSize);
			aa = aa+1;
		}
		if (mm->p_type == PT_LOAD && aa == 1) {
			si.sLoadSize = mm->p_filesz;
			si.sLoadOff = mm->p_offset;
			FLOGD("dynamicOff sec : %x , off: %x \n", si.sLoadSize, si.sLoadOff);
		}
		indexx++;
		if(mm->p_type == PT_DYNAMIC) {
			si.dycOffs = mm->p_offset;
			FLOGD("dynamicOff : %x \n", mm->p_offset);
		}
		FLOGD("segment type : %x \n", mm->p_type);
	}
}

bool ElfRebuilder::ReadSoInfo() {
    FLOGD("=======================ReadSoInfo=========================\n");
    si.base = si.load_bias = elf_reader_->load_bias();
	baseaddr = elf_reader_->load_bias();
	e_rebuild_data = new uint8_t[fileSize];
	memcpy(e_rebuild_data, (void*)ffd, fileSize);
	FLOGD("baseaddr : %x \n", baseaddr);
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    auto base = si.load_bias;
    phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load);

    /* Extract dynamic section */
    phdr_table_get_dynamic_section(si.phdr, si.phnum, si.base, &si.dynamic, &si.dynamic_count, &si.dynamic_flags, &si.dynOffset);
	FLOGE("si.dynOffset : %x, xing \n", si.dynOffset);
    if(si.dynamic == nullptr) {
        FLOGE("No valid dynamic phdr data\n");
        return false;
    }

    phdr_table_get_arm_exidx(si.phdr, si.phnum, si.base,
                             &si.ARM_exidx, (unsigned*)&si.ARM_exidx_count);
	unsigned symbolTabOff = 0;
	for (Elf_Dyn* mm = si.dynamic; mm->d_tag != DT_NULL; ++mm) {
		if (mm->d_tag == DT_STRTAB) {
			symbolTabOff = mm->d_un.d_ptr;
			FLOGD("symbolTabOff : %x \n", symbolTabOff);
		}
	}

    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
	
    for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d) {
        switch(d->d_tag){
            case DT_HASH:
                si.hash = d->d_un.d_ptr + base;
                si.nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
                si.nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
                si.bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
                si.chain = (unsigned *) (base + d->d_un.d_ptr + 8 + si.nbucket * 4);
				FLOGD("hash table found at %x, chain : %x , numnbucket %x \n", d->d_un.d_ptr, si.nchain, si.nbucket);
                break;
            case DT_STRTAB:
                si.strtab = (const char *) (base + d->d_un.d_ptr);
                FLOGD("string table found at %x\n", d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si.symtab = (Elf_Sym *) (base + d->d_un.d_ptr);
                FLOGD("symbol table found at %x\n", d->d_un.d_ptr);
                break;
            case DT_PLTREL:
				FLOGD("DT_PLTREL NUM : %x,  DT_RELA in \"%s\"\n", d->d_un.d_val, si.name);
                if (d->d_un.d_val != DT_RELA) {
                    FLOGE("unsupported DT_RELA in \"%s\"\n", si.name);
                    return false;
                }
                break;
            case DT_JMPREL:
                si.plt_rel = (Elf_Rela*) (base + d->d_un.d_ptr);
                FLOGD("%s plt_rel (DT_JMPREL) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si.plt_rel_count = d->d_un.d_val / sizeof(Elf_Rela);
                FLOGD("%s plt_rel_count (DT_PLTRELSZ) %d\n", si.name, si.plt_rel_count);
                break;
            case DT_REL:
                si.rel = (Elf_Rela*) (base + d->d_un.d_ptr);
                FLOGD("%s rel (DT_REL) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rela);
                FLOGD("%s rel_size (DT_RELSZ) %d\n", si.name, si.rel_count);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si.plt_got = (Elf_Addr *)(base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                break;
            case DT_RELA:
				si.rela_ = reinterpret_cast<Elf_Rela*>(base + d->d_un.d_ptr);
                FLOGE("supported DT_RELA in \"%s\"\n", si.name);
                //return false;
				break;
            case DT_INIT:
				si.intAddr = d->d_un.d_ptr;
                si.init_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT_ARRAY) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_INIT_ARRAYSZ) %d\n", si.name, si.init_array_count);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI_ARRAY) found at %x\n", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s destructors (DT_FINI_ARRAYSZ) %d\n", si.name, si.fini_array_count);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_PREINIT_ARRAY) found at %d\n", si.name, d->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_PREINIT_ARRAYSZ) %d\n", si.preinit_array_count);
                break;
            case DT_TEXTREL:
                si.has_text_relocations = true;
                break;
            case DT_SYMBOLIC:
                si.has_DT_SYMBOLIC = true;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
                    si.has_text_relocations = true;
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    si.has_DT_SYMBOLIC = true;
                }
                break;
            case DT_STRSZ:
                si.strtabsize = d->d_un.d_val;
                break;
            case DT_SYMENT:
            case DT_RELENT:
                break;
            case DT_MIPS_RLD_MAP:
                // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
                break;
            case DT_MIPS_RLD_VERSION:
            case DT_MIPS_FLAGS:
            case DT_MIPS_BASE_ADDRESS:
            case DT_MIPS_UNREFEXTNO:
                break;

            case DT_MIPS_SYMTABNO:
                si.mips_symtabno = d->d_un.d_val;
                break;

            case DT_MIPS_LOCAL_GOTNO:
                si.mips_local_gotno = d->d_un.d_val;
                break;

            case DT_MIPS_GOTSYM:
                si.mips_gotsym = d->d_un.d_val;
                break;
            case DT_SONAME:
                si.name = (const char *) (base + d->d_un.d_ptr + symbolTabOff);
                FLOGD("soname %s ,  off : %x \n", si.name, d->d_un.d_ptr + symbolTabOff);
                break;
            default:
                FLOGD("Unused DT entry: type 0x%08x arg 0x%08x\n", d->d_tag, d->d_un.d_val);
                break;
        }
    }
    FLOGD("=======================ReadSoInfo End=========================\n");
    return true;
}

// Finally, generate rebuild_data
bool ElfRebuilder::RebuildFin() {
    FLOGD("=======================try to finish file=========================\n");
    auto load_size = si.max_load - si.min_load;
	
	auto shdr_off = fileSize + shstrtab.length();
	FLOGD("shdr_off 1 : %x \n", shdr_off);
	int rsize = shdr_off % 8 == 0 ? 0 : 8 - shdr_off % 8;
	shdr_off = shdr_off + rsize;
	FLOGD("shdr_off 2 : %x , align : %x \n", shdr_off, rsize);
	
    rebuild_size = fileSize + shstrtab.length() +shdrs.size() * sizeof(Elf_Shdr) + rsize;
	FLOGD("si.base : %x , secSize : %x , num : Elf_Shdr \n", si.base, shdrs.size() * sizeof(Elf_Shdr), sizeof(Elf_Shdr));
	FLOGD("rebuild size : %x, load_size : %x , shstrtab.length : %x , soloadbase : %x , fileSize : %x \n", load_size, rebuild_size, shstrtab.length(), si.base, fileSize);
    rebuild_data = new uint8_t[rebuild_size];
    memcpy(rebuild_data, (void*)e_rebuild_data, fileSize);
	FLOGD("rebuild_data 1 : %x \n", rebuild_data);
    // pad with shstrtab
    memcpy(rebuild_data + fileSize, shstrtab.c_str(), shstrtab.length());
	FLOGD("rebuild_data 2 : %x \n", rebuild_data);
	
	
    // pad with shdrs
	
	FLOGD("rebuild_data section : %x , sizeof: %x \n", shdrs.size(), sizeof(Elf_Shdr));
    memcpy(rebuild_data + (int)shdr_off, (void*)&shdrs[0], shdrs.size() * sizeof(Elf_Shdr));
	FLOGD("rebuild_data 3 : %x \n", rebuild_data);
    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_shnum = shdrs.size();
    ehdr.e_shoff = (Elf_Addr)shdr_off;
    ehdr.e_shstrndx = sSHSTRTAB;
	FLOGD("ehdr.e_shnum : %x, ehdr.e_shoff : %x , ehdr.e_shstrndx : %x \n", ehdr.e_shnum, ehdr.e_shoff, ehdr.e_shstrndx);
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));
	FLOGD("rebuild_data 4 : %x \n", rebuild_data);

    FLOGD("=======================End=========================\n");
    return true;
}

bool ElfRebuilder::RebuildRelocs() {
    FLOGD("=======================RebuildRelocs=========================\n");
    if(!elf_reader_->dump_so_file_) return true;
    auto relocate = [](Elf_Addr base, Elf_Rela* rel, size_t count, Elf_Addr dump_base) {
        if(rel == nullptr || count == 0) return false;
        for(auto idx = 0; idx < count; idx++, rel++) {
#ifndef __LP64__
            auto type = ELF32_R_TYPE(rel->r_info);
            auto sym = ELF32_R_SYM(rel->r_info);
#else
            auto type = ELF64_R_TYPE(rel->r_info);
            auto sym = ELF64_R_SYM(rel->r_info);
#endif
            auto prel = reinterpret_cast<Elf_Addr *>(base + rel->r_offset);
            if(type == 0) { // R_*_NONE
                continue;
            }
            switch (type) {
                // I don't known other so info, if i want to fix it, I must dump other so file
                case R_386_RELATIVE:
                case R_ARM_RELATIVE:
                    *prel = *prel - dump_base;
                    break;
                default:
                    break;
            }
        }

        return true;
    };
    relocate(si.load_bias, si.plt_rel, si.plt_rel_count, elf_reader_->dump_so_base_);
    relocate(si.load_bias, si.rel, si.rel_count, elf_reader_->dump_so_base_);
    FLOGD("=======================RebuildRelocs End=======================\n");
    return true;
}




