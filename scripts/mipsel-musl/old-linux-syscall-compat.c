#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

static int set_fd_flags(int fd, int flags) {
  if ((flags & O_CLOEXEC) != 0) {
    int old_flags = fcntl(fd, F_GETFD);
    if (old_flags < 0 || fcntl(fd, F_SETFD, old_flags | FD_CLOEXEC) < 0) {
      return -1;
    }
  }
  if ((flags & O_NONBLOCK) != 0) {
    int old_flags = fcntl(fd, F_GETFL);
    if (old_flags < 0 || fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
      return -1;
    }
  }
  return 0;
}

int __wrap_epoll_create1(int flags) {
  int fd = (int)syscall(SYS_epoll_create1, flags);
  if (fd >= 0 || errno != ENOSYS) {
    return fd;
  }
  if ((flags & ~EPOLL_CLOEXEC) != 0) {
    errno = EINVAL;
    return -1;
  }
  fd = (int)syscall(SYS_epoll_create, 1024);
  if (fd < 0) {
    return fd;
  }
  if ((flags & EPOLL_CLOEXEC) != 0 && set_fd_flags(fd, O_CLOEXEC) < 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

int __wrap_eventfd(unsigned int initval, int flags) {
  int fd = (int)syscall(SYS_eventfd2, initval, flags);
  if (fd >= 0 || errno != ENOSYS) {
    return fd;
  }
  if ((flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)) != 0) {
    errno = EINVAL;
    return -1;
  }
  if ((flags & EFD_SEMAPHORE) != 0) {
    errno = ENOSYS;
    return -1;
  }
  fd = (int)syscall(SYS_eventfd, initval);
  if (fd < 0) {
    return fd;
  }
  if (set_fd_flags(fd, flags) < 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}
