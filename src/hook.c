#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
//#include <gelf.h>
#include "hook.h"

struct Arg {
    const char* libname;//in
    size_t offset;//out
    char libpath[512];
};

static int cb(struct dl_phdr_info *info, size_t size, void* data)
{
    struct Arg* arg = (struct Arg*) data;
    const char* hoge = basename(info->dlpi_name);
    //printf("%08lx %s\n", info->dlpi_addr, info->dlpi_name);
    if (strcmp(basename(arg->libname), basename(info->dlpi_name)) == 0) {
        arg->offset = (size_t) info->dlpi_addr;
        strcpy(arg->libpath, info->dlpi_name);
    }
    return 0;
}

int execCmd(const char* cmd, char* output)
{
    FILE    *fp;
    //puts(cmd);
    if ( (fp=popen(cmd, "r")) ==NULL) {
        return -1;
    }
    while(fgets(output, 1024, fp) != NULL) {
    }
    (void) pclose(fp);
    return 0;
}


void* getPLTAddrFromElf(const char *filepath, const char* funcname, size_t bias)
{
    char cmd[512];
    char output[512];
    sprintf(cmd, "objdump -d %s | grep '<%s@plt>:' | awk '{print $1}' | head -n 1", filepath, funcname);
    int ret = execCmd(cmd, output);
    if (ret) {
        exit (-1);
    }
    //puts(output);
    long n = strtol(output, NULL, 16);
    return (void*)(n + bias);
}


static Addr_t getPLTAddr(const char* libname, const char* funcname)
{
    struct Arg arg;
    arg.libname = libname;
    arg.offset = 0;
    strcpy(arg.libpath, libname);
    dl_iterate_phdr(cb, &arg);

    void* addr = getPLTAddrFromElf(arg.libpath, funcname, arg.offset);
    //printf("%s %s %p\n", arg.libpath, funcname, addr);

    return (Addr_t)(addr);
}

Addr_t getGOTAddr(const char* libname, const char* funcname)
{
    Addr_t plt = getPLTAddr(libname, funcname);
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

