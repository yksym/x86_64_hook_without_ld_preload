#include <stdio.h>
#include <stdlib.h>
#include <hook.h>


extern "C" {
    void* calloc_hook(size_t n, size_t size)
    {
        DECL_ORG_FUNC(calloc, org_calloc);
        puts("hello");
        return org_calloc(n, size);
    }
};

void test(const char* program)
{
    puts("1st");
    void* a = calloc(1, 10);
    free(a);

    puts("2nd");
    {
        HOOK(program, calloc, calloc_hook);
        void* b = calloc(1, 10);
        free(b);
    }

    puts("3rd");
    void* c = calloc(1, 10);
    free(c);
}

int main(int argc, char** argv)
{
    test(argv[0]);
    return 0;
}
