#ifndef HOOK_H
#define HOOK_H
#include <string.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef void* Addr_t;
Addr_t getGOTAddr(const char* libPath, const char* funcname);
#ifdef __cplusplus
};
#endif

#ifdef __cplusplus
//https://gist.github.com/NeoCat/1519275
template <class RET, class... ARGV>
class LibHook {
public:
	typedef RET rtype;
	typedef RET(*ftype)(ARGV...);
protected:
	Addr_t* gote;
	ftype hook;
	Addr_t orgAddr, newAddr;

public:
	LibHook(const char* libPath, const char *funcname, ftype hook) : hook(hook) {
		gote = (Addr_t*)getGOTAddr(libPath, funcname);
        if (gote == NULL) throw "cannot parse elf";
        orgAddr = *gote;
        newAddr = (Addr_t)hook;
        *gote = newAddr;
	}

	~LibHook() {
        *gote = orgAddr;
	}
};

template <class RET, class... ARGS>
LibHook<RET,ARGS...> _resolve_ftype(RET(*f)(ARGS...))
{
    throw "This function must not be called.";
    return LibHook<RET,ARGS...>();
}

#define DECL_ORG_FUNC(func, ofunc) \
    typedef decltype(&func) func ## _t;\
    func ## _t ofunc = (func ## _t) dlsym(RTLD_NEXT, #func);

#define HOOK(program, func, hfunc)                  \
        typedef decltype(_resolve_ftype(func)) HookT;       \
        HookT hook(program, #func, hfunc);

#endif

#endif//HOOK_H
