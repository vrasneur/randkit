#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>

int main(void)
{
  unsigned char buf[6] = { 1, 2, 3, 4, 5, 6 };
  int fd = open("/dev/urandom", O_RDONLY);
  ssize_t ret = read(fd, buf, sizeof(buf));

  printf("ret: %d\n", ret);
  
  for(int i = 0; i < sizeof(buf); i++) {
    printf("random (%d): %02X\n", i, buf[i]);
  }
  
  close(fd);
}
