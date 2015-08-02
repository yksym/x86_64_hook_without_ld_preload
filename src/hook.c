#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include <gelf.h>
#include "hook.h"

struct Arg {
    const char* libPath;//in
    size_t offset;//out
};

static int cb(struct dl_phdr_info *info, size_t size, void* data)
{
    struct Arg* arg = (struct Arg*) data;
    //printf("%08lx %s\n", info->dlpi_addr, info->dlpi_name);
    if (strcmp(arg->libPath, info->dlpi_name) == 0) {
        arg->offset = (size_t) info->dlpi_addr;
    }
    return 0;
}

void* getPLTAddrFromElf(const char *filename, const char* funcname, GElf_Addr bias);

static Addr_t getPLTAddr(const char* libPath, const char* funcname)
{
    struct Arg arg;
    arg.libPath = libPath;
    arg.offset = 0;
    dl_iterate_phdr(cb, &arg);

    size_t addr = (size_t)getPLTAddrFromElf(libPath, funcname, arg.offset);

    return (Addr_t)(addr + arg.offset);
}

Addr_t getGOTAddr(const char* libPath, const char* funcname)
{
    Addr_t plt = getPLTAddr(libPath, funcname);
    //printf("%p\n", plt);
    uint8_t jmp[6];
    memcpy(jmp, plt, sizeof(jmp));
    //printf("%x %x %x %x %x %x\n", jmp[0], jmp[1],jmp[2],jmp[3],jmp[4],jmp[5]);
    uint32_t offset;
    memcpy(&offset, jmp+2, sizeof(offset));
    //printf("%x\n", offset);
    Addr_t ret = (Addr_t)((size_t)plt + offset + sizeof(jmp));
    //printf("%p\n", ret);
    return ret;
}

