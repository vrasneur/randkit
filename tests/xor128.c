#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

uint32_t xor128() {
    static uint32_t x = 123456789;
    static uint32_t y = 362436069;
    static uint32_t z = 521288629;
    static uint32_t w = 88675123;

    uint32_t t;

    t = x ^ (x << 11);
    x = y;
    y = z;
    z = w;
    w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));

    return w;
}

int main(void)
{
    int f = open("xor128.random",  O_CREAT | O_WRONLY);
    
    for(int i = 0; i < 100; i++)
    {
        uint32_t rnd = xor128();
        printf("%" PRIu32 "\n", rnd);
    
        write(f, &rnd, sizeof(rnd));
    }
    close(f);

    return 0;
}
