#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>

int main(void)
{
  unsigned char buf[6] = { 'a', 'z', 'e', 'r', 't', '\n' };
  int fd = open("/dev/urandom", O_WRONLY);
  ssize_t ret = write(fd, buf, sizeof(buf));

  printf("ret: %d\n", ret);
  
  for(int i = 0; i < sizeof(buf); i++) {
    printf("random (%d): %02X\n", i, buf[i]);
  }
  
  close(fd);
}
