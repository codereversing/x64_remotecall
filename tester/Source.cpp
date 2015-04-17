#include <stdio.h>

int main(void)
{
    unsigned int i = 0;
    while (true)
    {
        if (i == 0xABCDDCBA)
        {
            i = 0;
        }
        //No sleeps as that puts the thread in a yielded state
    }

    return 0;
}