#include <iostream>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <vector>

#include <zlib.h>

#include "def.h"

using namespace std;

#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FINISH 2

struct sockaddr_in recv_addr;
struct sockaddr_in addr;
int sock_fd = 0;


double cwnd = 0;
int thresh = 0, dup_ack = 0;
int base = 0;
int state = 0;
bool isTimerRunning = false;
int file_fd;
int last_seq_num = 0, last_seg_num = 0;
bool finish = 0;
// the size of this quene is cwnd and it starts from base.
vector<struct segment> transmit_queue; 

void setIP(char *dst, char *src){
    if(strcmp(src, "0.0.0.0") == 0 || strcmp(src, "local") == 0 || strcmp(src, "localhost") == 0){
        sscanf("127.0.0.1", "%s", dst);
    }
    else{
        sscanf(src, "%s", dst);
    }
    return;
}

void transmitNew() {
    /*
        After you remove some segments in the window or the cwnd increases, there will be more segments
        that is contained inside the window.
        (Re)transmit those segments, no matter whether this segment has ever been sent before.
    */
    for (int i = transmit_queue.size(); i < (int)cwnd; i++) {
        if (finish) 
            break;
        int read_bytes = 0;
        segment sgmt{};
        bzero(sgmt.data, sizeof(char) * MAX_SEG_SIZE);
        if ((read_bytes = read(file_fd, sgmt.data, MAX_SEG_SIZE)) < 0) {
            perror("read()");
            exit(1);
        }
        sgmt.head.length = read_bytes;
        sgmt.head.seqNumber = last_seq_num+1;
        sgmt.head.checksum = crc32(0L, (const Bytef *)sgmt.data, read_bytes);
        sgmt.head.ack = sgmt.head.fin = sgmt.head.syn = 0;
        transmit_queue.push_back(sgmt);

        if (read_bytes < MAX_SEG_SIZE) {
            finish = true;
            last_seg_num = i;
        }
        if (read_bytes == 0) {
            break;
        }
        printf("send\tdata\t#%d,\twinSize = %d\n", sgmt.head.seqNumber , int(cwnd));
        if (sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr)) < 0) {
            perror("sendto()");
            exit(1);
        }
        last_seq_num = max(sgmt.head.seqNumber, last_seq_num);
    }
}

void transmitMissing() {
    // (Re)transmit the first segment in the window.
    segment sgmt = transmit_queue[0];
    printf("resnd\tdata\t#%d,\twinSize = %d\n", sgmt.head.seqNumber , int(cwnd));
    if (sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr)) < 0) {
        perror("sendto()");
        exit(1);
    }
}

void markSACK(int sack_num) {
    // Remove the segment with sequence number seqNumber from the transmit queue
    for (int i = 0; i < transmit_queue.size(); i++) {
        if (transmit_queue[i].head.seqNumber == sack_num) {
            transmit_queue.erase(transmit_queue.begin()+i);
            break;
        }
    }
}

void updateBase(int ack_num) {
    // Update base, transmit queue and window s.t. base > ackNumber
    for (int i = 0; i < transmit_queue.size(); i++) {
        if (transmit_queue[i].head.seqNumber == ack_num) {
            transmit_queue.erase(transmit_queue.begin(), transmit_queue.begin()+i+1);
            break;
        }
    }
}

void setState(int new_state) {
    // Go to a specific state.
    state = new_state;
}

bool isAtState(int query_state) {
    // True if the state is at `state` else False
    return (state == query_state);
}

void resetTimer() {
    struct itimerval interval, reset;
    reset.it_interval = {0, 0};
    reset.it_value = {0, 0};
    interval.it_interval = {0, 0};
    interval.it_value = {0, TIMEOUT_MILLISECONDS*100};
    setitimer(ITIMER_REAL, &reset, nullptr);
    setitimer(ITIMER_REAL, &interval, nullptr);
}

void timeoutHandler(int id) {
    //The thing needed to do if timeout
    printf("time\tout,\tthreshold = %d,\twinSize = %d\n", thresh , int(cwnd));
    thresh = max(1, int(cwnd/2));
    cwnd = 1;
    dup_ack = 0;
    transmitMissing();
    resetTimer();
    setState(SLOW_START);
}

void init() {
    cwnd = 1;
    thresh = 16;
    dup_ack = 0;
    transmitNew(); // 1 segment will be transmitted
    signal(SIGALRM, timeoutHandler);
    resetTimer();
    setState(SLOW_START);
}

void dupCumulativeACK(struct segment pkt) {
    dup_ack += 1;
    markSACK(pkt.head.sackNumber);
    transmitNew();
    if (dup_ack == 3) {
        transmitMissing();
    }
}

void newCumulativeACK(struct segment pkt) {
    double new_segs = 0;
    dup_ack = 0;
    markSACK(pkt.head.sackNumber);
    updateBase(pkt.head.ackNumber);
    if (isAtState(SLOW_START)){
        new_segs = 1;
        if (cwnd >= thresh)
            setState(CONGESTION_AVOIDANCE);
    } else if (isAtState(CONGESTION_AVOIDANCE)) {
        new_segs = double(1) / int(cwnd);
    }
    cwnd += new_segs;
    //not sure if this is correct
    transmitNew(); // ((int)cwnd - (int)(cwnd-new_segs) == 1 ? 1 : 0) segments will be transmitted
    resetTimer();
}

void clearTimer() {
    struct itimerval reset;
    reset.it_interval = {0, 0};
    reset.it_value = {0, 0};
    setitimer(ITIMER_REAL, &reset, nullptr);
}


// ./sender <send_ip> <send_port> <agent_ip> <agent_port> <src_filepath>
int main(int argc, char *argv[]) {
    // parse arguments
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <send_ip> <send_port> <agent_ip> <agent_port> <src_filepath>" << endl;
        exit(1);
    }

    int send_port, agent_port;
    char send_ip[50], agent_ip[50];

    // read argument
    setIP(send_ip, argv[1]);
    sscanf(argv[2], "%d", &send_port);

    setIP(agent_ip, argv[3]);
    sscanf(argv[4], "%d", &agent_port);

    char *filepath = argv[5];

    // make socket related stuff
    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);

    
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(agent_port);
    recv_addr.sin_addr.s_addr = inet_addr(agent_ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(send_port);
    addr.sin_addr.s_addr = inet_addr(send_ip);
    memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));    
    bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));

    // make a segment (do file IO stuff on your own)
    if ((file_fd = open(filepath, O_RDONLY)) < 0) {
        perror("open()");
        exit(1);
    }
    init();
    int last_cumulative_ack = 0;
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);
    while (true) {
        socklen_t recv_addr_sz;
        segment sgmt{};
        // receive a segment!
        if (recvfrom(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz) < 0) {
            perror("recvfrom()");
            exit(1);
        }

        printf("recv\tack\t#%d,\tsack\t#%d\n", sgmt.head.ackNumber , sgmt.head.sackNumber);
        // block SIGALRM because every event should be atomic
        if (sigprocmask(SIG_BLOCK, &sigset, nullptr) < 0) {
            perror("sigprocmask()");
            exit(1);
        }
        if (finish && sgmt.head.ackNumber == last_seq_num)
            break;
        // unblock SIGALRM
        if (sigprocmask(SIG_UNBLOCK, &sigset, nullptr) < 0) {
            perror("sigprocmask()");
            exit(1);
        }
        
        // block SIGALRM because every event should be atomic
        if (sigprocmask(SIG_BLOCK, &sigset, nullptr) < 0) {
            perror("sigprocmask()");
            exit(1);
        }
        if (sgmt.head.ackNumber == last_cumulative_ack) {
            // duplicate cumulative ACK
            dupCumulativeACK(sgmt);
        } else {
            // new cumulative ACK
            newCumulativeACK(sgmt);
            last_cumulative_ack = sgmt.head.ackNumber;
        }
        // unblock SIGALRM
        if (sigprocmask(SIG_UNBLOCK, &sigset, nullptr) < 0) {
            perror("sigprocmask()");
            exit(1);
        }
    }

    // state == FINISH
    // resetTimer();
    clearTimer();
    socklen_t recv_addr_sz;
    segment send_pkt = transmit_queue[last_seg_num], recv_pkt{};
    send_pkt.head.fin = 1;
    printf("send\tfin\n");
    if (sendto(sock_fd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr)) < 0) {
        perror("sendto()");
        exit(1);
    }

    // receive a segment!
    int recyBytes = 0;
    if ((recyBytes = recvfrom(sock_fd, &recv_pkt, sizeof(recv_pkt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz)) < 0) {
        perror("recvfrom()");
        exit(1);
    }
    // if (recyBytes == 0) {
    //     printf("ERROOOOOOOOOOOOOOOR\n");
    // }
    // if (recv_pkt.head.fin == 1 && recv_pkt.head.ack == 1)
    printf("recv\tfinack\n");
    
    fflush(stdout);
    close(file_fd);
}