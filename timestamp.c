#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define UDP_MAX_LENGTH 1500

typedef struct {
  int fd;
  int port;
  int err_no;
  struct sockaddr_in local;
  struct sockaddr_in remote;
  struct timeval time_kernel;
  struct timeval time_user;
  int64_t time_device;
  int64_t prev_serialnum;
} socket_info;


typedef struct {
  int64_t serialnum;

  int64_t user_time_serialnum;
  int64_t user_time;

  int64_t kernel_time_serialnum;
  int64_t kernel_time;

  int64_t device_time64;
  
  size_t message_bytes;
} message_header;

int64_t old_diff=0;


static int setup_udp_receiver(socket_info *inf, int port, int type) {
  inf->port = port;
  inf->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (inf->fd < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: socket failed: %s\n",
            strerror(inf->err_no));
    return inf->fd;
  }

  int timestampOn = 0;

  timestampOn |= (type&1 ? SOF_TIMESTAMPING_RX_SOFTWARE : 0) |
    (type&2  ? SOF_TIMESTAMPING_RX_HARDWARE : 0 ) |
    (type&4  ?  SOF_TIMESTAMPING_RAW_HARDWARE : 0);
  

 
  int r = setsockopt(inf->fd, SOL_SOCKET, SO_TIMESTAMPING, &timestampOn,
                     sizeof timestampOn);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  int on = 1;
  r = setsockopt(inf->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt2 failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->local = (struct sockaddr_in){.sin_family = AF_INET,
                                    .sin_port = htons((uint16_t)port),
                                    .sin_addr.s_addr = htonl(INADDR_ANY)};
  r = bind(inf->fd, (struct sockaddr *)&inf->local, sizeof inf->local);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: bind failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->prev_serialnum = -1;

  return 0;
}

static int setup_udp_sender(socket_info *inf, int port, char *address, int type) {
  inf->port = port;
  inf->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (inf->fd < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_client: socket failed: %s\n",
            strerror(inf->err_no));
    return inf->fd;
  }
  
  int timestampOn = 0;

  timestampOn |= (type&1 ? SOF_TIMESTAMPING_TX_SOFTWARE : 0) |
    (type&2  ? SOF_TIMESTAMPING_TX_HARDWARE : 0  ) |
    (type&4  ?  SOF_TIMESTAMPING_RAW_HARDWARE : 0 );
  

 
  int r = setsockopt(inf->fd, SOL_SOCKET, SO_TIMESTAMPING, &timestampOn,
                     sizeof timestampOn);
  if (r < 0) {
    inf->err_no = errno;
    fprintf(stderr, "setup_udp_server: setsockopt failed: %s\n",
            strerror(inf->err_no));
    return r;
  }

  inf->remote = (struct sockaddr_in){.sin_family = AF_INET,
                                     .sin_port = htons((uint16_t)port)};
  r = inet_aton(address, &inf->remote.sin_addr);
  if (r == 0) {
    fprintf(stderr, "setup_udp_client: inet_aton failed\n");
    inf->err_no = 0;
    return -1;
  }

  inf->local = (struct sockaddr_in){.sin_family = AF_INET,
                                    .sin_port = htons(0),
                                    .sin_addr.s_addr = htonl(INADDR_ANY)};
  inf->prev_serialnum = -1;

  return 0;
}

static void handle_scm_timestamping(struct scm_timestamping *ts,socket_info *inf ) {
  for (size_t i = 0; i < sizeof ts->ts / sizeof *ts->ts; i++) {
    printf("timestamp: %lld.%.9lds\n", (long long)ts->ts[i].tv_sec,
           ts->ts[i].tv_nsec);
    if( inf && i==2 ){
      inf->time_device=ts->ts[i].tv_sec*1000000000L+ts->ts[i].tv_nsec;
    }
   
  }
  
}

static void handle_time(struct msghdr *msg, socket_info *inf) {

  if( inf ){
    inf->time_device=0;
  }
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
       cmsg = CMSG_NXTHDR(msg, cmsg)) {
    printf("level=%d, type=%d, len=%zu\n", cmsg->cmsg_level, cmsg->cmsg_type,
           cmsg->cmsg_len);

    if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
      struct sock_extended_err *ext =
          (struct sock_extended_err *)CMSG_DATA(cmsg);
      printf("errno=%d, origin=%d\n", ext->ee_errno, ext->ee_origin);
      continue;
    }

    if (cmsg->cmsg_level != SOL_SOCKET)
      continue;

    switch (cmsg->cmsg_type) {
    case SO_TIMESTAMPNS: {
      struct scm_timestamping *ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
      handle_scm_timestamping(ts,NULL);
    } break;
    case SO_TIMESTAMPING: {
      struct scm_timestamping *ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
      handle_scm_timestamping(ts,inf);
    } break;
    default:
      /* Ignore other cmsg options */
      break;
    }
  }
  printf("End messages\n");
}

static ssize_t udp_receive(socket_info *inf, char *buf, size_t len) {
  char ctrl[2048];
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  struct msghdr msg = (struct msghdr){.msg_control = ctrl,
                                      .msg_controllen = sizeof ctrl,
                                      .msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  ssize_t recv_len = recvmsg(inf->fd, &msg, 0);
  gettimeofday(&inf->time_user, NULL);

  if (recv_len < 0) {
    inf->err_no = errno;
    fprintf(stderr, "udp_receive: recvfrom failed: %s\n",
            strerror(inf->err_no));
  }

  int64_t rx_time,diff;
  
  message_header *header = (message_header *)buf;
  printf("previous rx time=%ld\n", inf->time_device);
  printf("tx timestamp from received packet=%ld\n", header->device_time64);
  printf("tx rx diff=%ld\n", diff=(inf->time_device - header->device_time64));
  printf("variation from previous diff=%ld\n", old_diff-diff);
  printf("header->serialnum=%ld inf->prev_serialnum=%ld\n", header->serialnum,inf->prev_serialnum);
  old_diff=diff;
  
  handle_time(&msg,inf);

  return recv_len;
}

static ssize_t udp_send(socket_info *inf, char *buf, size_t len) {
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  struct msghdr msg = (struct msghdr){.msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  gettimeofday(&inf->time_user, NULL);
  ssize_t send_len = sendmsg(inf->fd, &msg, 0);
  if (send_len < 0) {
    inf->err_no = errno;
    fprintf(stderr, "udp_send: sendmsg failed: %s\n", strerror(inf->err_no));
  }

  return send_len;
}

static ssize_t meq_receive(socket_info *inf, char *buf, size_t len) {
  struct iovec iov = (struct iovec){.iov_base = buf, .iov_len = len};
  char ctrl[2048];
  struct msghdr msg = (struct msghdr){.msg_control = ctrl,
                                      .msg_controllen = sizeof ctrl,
                                      .msg_name = &inf->remote,
                                      .msg_namelen = sizeof inf->remote,
                                      .msg_iov = &iov,
                                      .msg_iovlen = 1};
  ssize_t recv_len = recvmsg(inf->fd, &msg, MSG_ERRQUEUE);
  if (recv_len < 0) {
    inf->err_no = errno;
    if (errno != EAGAIN) {
      fprintf(stderr, "meq_receive: recvmsg failed: %s\n",
              strerror(inf->err_no));
    }
    return recv_len;
  }
  handle_time(&msg,inf);

  return recv_len;
}



static const size_t payload_max = UDP_MAX_LENGTH - sizeof(message_header);

static ssize_t generate_random_message(socket_info *inf, char *buf,
                                       size_t len) {
  if (len < sizeof(message_header)) {
    return -1;
  }
  message_header *header = (message_header *)buf;
  char *payload = (char *)(header + 1);
  size_t payload_len = (size_t)random() % (payload_max + 1);
  if (payload_len > len - sizeof(message_header)) {
    payload_len = len - sizeof(message_header);
  }
  for (size_t i = 0; i < payload_len; i++) {
    payload[i] = (char)random();
  }

  static int64_t serial_num = 0;
  *header = (message_header){
      .user_time_serialnum = inf->prev_serialnum,
      .user_time = inf->time_user.tv_sec * 1000000000L + inf->time_user.tv_usec,
      .kernel_time_serialnum = inf->prev_serialnum,
      .kernel_time =
          inf->time_kernel.tv_sec * 1000000000L + inf->time_kernel.tv_usec,
      .serialnum = serial_num,
      .device_time64 = inf->time_device,
      .message_bytes = payload_len};
  size_t total = payload_len + sizeof *header;

  printf("uts%5" PRId64 ": kt=%" PRId64 ", ut=%" PRId64 ", sn=%" PRId64
         ": s=%zu\n",
         header->user_time_serialnum, header->kernel_time, header->user_time,
         header->serialnum, total);

  inf->prev_serialnum = serial_num++;

  return (ssize_t)total;
}

static void sender_loop(char *host, int port, int type) {
  socket_info inf;
  int ret = setup_udp_sender(&inf, port, host,type);
  if (ret < 0) {
    return;
  }

  for (int i = 0; i < 2000; i++) {
    useconds_t t = random() % 2000000;
    usleep(t);
    char packet_buffer[4096];
    ssize_t len =
        generate_random_message(&inf, packet_buffer, sizeof packet_buffer);
    if (len < 0) {
      return;
    }
    udp_send(&inf, packet_buffer, (size_t)len);
    message_header *mh=(message_header *)packet_buffer;
    
    printf("tx time of serial number %ld = %ld\n", mh->serialnum,
	   mh->device_time64);

    while (meq_receive(&inf, packet_buffer, sizeof packet_buffer) != -1) {
    }
  }
}

static void receiver_loop(int port, int type) {
  socket_info inf;
  
  int ret = setup_udp_receiver(&inf, port, type);
  if (ret < 0) {
    return;
  }

  printf("Receiving on port %d\n", port);
  
  for (int i = 0; i < 1000; i++) {
    char packet_buffer[4096];
    udp_receive(&inf, packet_buffer, sizeof packet_buffer);
  }
}

#define USAGE "Usage: %s [-r | -s host ][-p port][-t type]\n" 

int main(int argc, char *argv[]) {
  int port=8000;
  char *host=NULL;
  
  if (argc < 2) {
    fprintf(stderr, USAGE, argv[0]);
    return 0;
  }

  int a=1,type=1; 
  for( a=1; a<argc ; a++){
    
    if (0 == strcmp(argv[a], "-s")) {
      if (argc <= a+1) {
	fprintf(stderr, USAGE, argv[0]);
	return 0;
      }
      a++;
      host=argv[a];
      continue;
    }

    if (0 == strcmp(argv[a], "-r")) {
      continue;
    }

    if (0 == strcmp(argv[a], "-p")) {
      if (argc <= a+1) {
	fprintf(stderr, USAGE, argv[0]);
	return 0;
      }
      a++;
      port=atoi(argv[a]);
      continue;
    }
    
    if (0 == strcmp(argv[a], "-t")) {
      if (argc <= a+1) {
	fprintf(stderr, USAGE, argv[0]);
	return 0;
      }
      a++;
      type=atoi(argv[a]);
      continue;
    }
  } 
  
  printf("%s%s on port %d with flags %s%s%s(%d)\n",
	 host==NULL ? "receiving" : "sending to ",
	 host, port,
	 type&1 ? "SW," : "",
	 type&2 ? "HW," : "",
	 type&4 ? "RAW," : "", type
	 
	 );


  if( host!=NULL ){

    sender_loop(host, port, type);

  }
  else{
    receiver_loop(port,type);
  }


  
}
