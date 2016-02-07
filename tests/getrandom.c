#define _GNU_SOURCE

#include <linux/random.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>


int main(void)
{
#ifndef __NR_getrandom
  puts("getrandom syscall not supported!");
  
  return -1;
#else
  unsigned char buf[6] = { 1, 2, 3, 4, 5, 6 };;

  long ret = syscall(__NR_getrandom, buf, sizeof(buf), 0);
  
  printf("ret: %d\n", ret);
  
  for(int i = 0; i < 6; i++) {
    printf("random (%d): %02X\n", i, buf[i]);
  }

  return 0;
#endif
}
