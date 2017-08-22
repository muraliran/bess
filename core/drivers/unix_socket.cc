// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <signal.h>
#include <sys/epoll.h>

#include "unix_socket.h"

// TODO(barath): Clarify these comments.
// Only one client can be connected at the same time.  Polling sockets is quite
// exprensive, so we throttle the polling rate.  (by checking sockets once every
// RECV_TICKS schedules)

// TODO: Revise this once the interrupt mode is  implemented.

#define RECV_SKIP_TICKS 256
#define SIG_THREAD_EXIT SIGUSR2


static void EpollAdd(int epoll_fd, int new_fd, uint32_t events) {
    struct epoll_event event;
    event.events = events;
    event.data.fd = new_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &event);
}

static void EpollDel(int epoll_fd, int fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
}

void UnixSocketPort::AcceptThread() {
  sigset_t sigset;
  sigfillset(&sigset);
  sigdelset(&sigset, SIG_THREAD_EXIT);

  while (true) {
    struct epoll_event event;
    if (epoll_pwait(epoll_fd_, &event, 1, -1, &sigset) < 0) {
      if (errno == EINTR) {
        if (accept_thread_stop_req_) {
          break;
        } else {
          continue;
        }
      } else {
        PLOG(ERROR) << "[UnixSocketPort]:epoll_wait()";
      }

    } else if (event.data.fd == listen_fd_) {
      if (event.events & EPOLLIN) {
        // new client connected
        int fd;
        while (true) {
          fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK);
          if (fd >= 0 || errno != EINTR) {
            break;
          }
        }
        if (fd < 0) {
          PLOG(ERROR) << "[UnixSocketPort]:accept4()";
        } else {
          EpollAdd(epoll_fd_, fd, EPOLLRDHUP);
          client_fd_ = fd;
        }
      } else {
        LOG(ERROR) << "[UnixSocketPort]:epoll_wait(): "
                   << "Unexpected event " << event.events
                   << " in listen_fd_";
      }

    } else if (event.data.fd == client_fd_) {
      if (event.events & EPOLLRDHUP) {
        // connection dropped by client
        int fd = client_fd_;
        client_fd_ = -1;
        EpollDel(epoll_fd_, fd);
        close(fd);
      } else {
        LOG(ERROR) << "[UnixSocketPort]:epoll_wait(): "
                   << "Unexpected event " << event.events
                   << " in client_fd_";
      }

    } else {
      LOG(ERROR) << "[UnixSocketPort]:epoll_wait(): "
                 << "Unexpected fd " << event.data.fd;
    }
  }
}

static void AcceptThreadHandler(int sig) {
  sig = sig;
}

CommandResponse UnixSocketPort::Init(const bess::pb::UnixSocketPortArg &arg) {
  const std::string path = arg.path();
  int num_txq = num_queues[PACKET_DIR_OUT];
  int num_rxq = num_queues[PACKET_DIR_INC];

  size_t addrlen;

  int ret;

  if (num_txq > 1 || num_rxq > 1) {
    return CommandFailure(EINVAL, "Cannot have more than 1 queue per RX/TX");
  }

  listen_fd_ = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (listen_fd_ < 0) {
    DeInit();
    return CommandFailure(errno, "socket(AF_UNIX) failed");
  }

  addr_.sun_family = AF_UNIX;

  if (path.length() != 0) {
    snprintf(addr_.sun_path, sizeof(addr_.sun_path), "%s", path.c_str());
  } else {
    snprintf(addr_.sun_path, sizeof(addr_.sun_path), "%s/bess_unix_%s",
             P_tmpdir, name().c_str());
  }

  // This doesn't include the trailing null character.
  addrlen = sizeof(addr_.sun_family) + strlen(addr_.sun_path);

  // Non-abstract socket address?
  if (addr_.sun_path[0] != '@') {
    // Remove existing socket file, if any.
    unlink(addr_.sun_path);
  } else {
    addr_.sun_path[0] = '\0';
  }

  ret = bind(listen_fd_, reinterpret_cast<struct sockaddr *>(&addr_), addrlen);
  if (ret < 0) {
    DeInit();
    return CommandFailure(errno, "bind(%s) failed", addr_.sun_path);
  }

  ret = listen(listen_fd_, 1);
  if (ret < 0) {
    DeInit();
    return CommandFailure(errno, "listen() failed");
  }


  epoll_fd_ = epoll_create(1);
  if (epoll_fd_ < 0) {
    DeInit();
    return CommandFailure(errno, "epoll_create(1) failed");
  }
  EpollAdd(epoll_fd_, listen_fd_, EPOLLIN);


  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = AcceptThreadHandler;
  if (sigaction(SIG_THREAD_EXIT, &sa, NULL) < 0) {
    DeInit();
    return CommandFailure(errno, "sigaction(SIG_THREAD_EXIT) failed");
  }


  accept_thread_ = std::thread([&]() {
      this->AcceptThread();
    });

  return CommandSuccess();
}

void UnixSocketPort::DeInit() {
  if (accept_thread_.joinable()) {
    accept_thread_stop_req_ = true;
    pthread_kill(accept_thread_.native_handle(), SIG_THREAD_EXIT);
    accept_thread_.join();
  }

  if (listen_fd_ != kNotConnectedFd) {
    close(listen_fd_);
  }
  if (client_fd_ != kNotConnectedFd) {
    close(client_fd_);
  }
  if (epoll_fd_ != kNotConnectedFd) {
    close(epoll_fd_);
  }
}

int UnixSocketPort::RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  int client_fd = client_fd_;

  DCHECK_EQ(qid, 0);

  if (client_fd == kNotConnectedFd) {
    return 0;
  }

  if (recv_skip_cnt_) {
    recv_skip_cnt_--;
    return 0;
  }

  int received = 0;
  while (received < cnt) {
    bess::Packet *pkt = static_cast<bess::Packet *>(bess::Packet::Alloc());
    int ret;

    if (!pkt) {
      break;
    }

    // Datagrams larger than 2KB will be truncated.
    ret = recv(client_fd, pkt->data(), SNBUF_DATA, 0);

    if (ret > 0) {
      pkt->append(ret);
      pkts[received++] = pkt;
      continue;
    }

    bess::Packet::Free(pkt);

    if (ret < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EBADF) {
        break;
      }

      if (errno == EINTR) {
        continue;
      }
    }

    // Connection closed.
    break;
  }

  if (received == 0) {
    recv_skip_cnt_ = RECV_SKIP_TICKS;
  }

  return received;
}

int UnixSocketPort::SendPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  int sent = 0;
  int client_fd = client_fd_;

  DCHECK_EQ(qid, 0);

  if (client_fd == kNotConnectedFd) {
    return 0;
  }

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = pkts[i];

    int nb_segs = pkt->nb_segs();
    struct iovec iov[nb_segs];

    struct msghdr msg = msghdr();
    msg.msg_iov = iov;
    msg.msg_iovlen = nb_segs;

    ssize_t ret;

    for (int j = 0; j < nb_segs; j++) {
      iov[j].iov_base = pkt->head_data();
      iov[j].iov_len = pkt->head_len();
      pkt = pkt->next();
    }

    ret = sendmsg(client_fd, &msg, 0);
    if (ret < 0) {
      break;
    }

    sent++;
  }

  if (sent) {
    bess::Packet::Free(pkts, sent);
  }

  return sent;
}

ADD_DRIVER(UnixSocketPort, "unix_port",
           "packet exchange via a UNIX domain socket")
