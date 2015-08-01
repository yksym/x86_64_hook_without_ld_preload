#include <stdio.h>
#include <stdint.h>
#include "hook.h"

static Addr_t getPLTAddr(const char* libPath, const char* funcname)
{
    return (Addr_t)0x4008b0;
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
