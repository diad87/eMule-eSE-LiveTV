#include <langinfo.h>
#include <stdio.h>

int main()
{
        char *retval;

        retval = nl_langinfo(CODESET);
        printf("%s\n", retval);
}

