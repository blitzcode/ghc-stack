
#include "crash.h"

void someCFuncA()
{
    someCFuncB();
    someCFuncB();
}

void someCFuncB()
{
    * (char *) 1 = 0;
}

