#include <stdio.h>
#include <stdlib.h>
#include <hook.h>


extern "C" {
    void* calloc_hook(size_t n, size_t size)
    {
        DECL_ORG_FUNC(calloc, org_calloc);
        puts( __FUNCTION__ );
        return org_calloc(n, size);
    }
};

void test(const char* program)
{
    puts(__FILE__ ": 1st");
    {
        HOOK(program, calloc, calloc_hook);
        void* b = calloc(1, 10);
        free(b);
    }

    puts(__FILE__ ": 2nd");
    void* c = calloc(1, 10);
    free(c);

    puts(__FILE__ ": 3rd");
    {
        HOOK(program, calloc, calloc_hook);
        void* b = calloc(1, 10);
        free(b);
    }
}

void test2(const char* program);

int main(int argc, char** argv)
{
    test(argv[0]);
    test2(LIB_NAME);
    return 0;
}
