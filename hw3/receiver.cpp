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
#include <vector>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

#include <zlib.h>

#include "def.h"

using namespace std;

struct sockaddr_in recv_addr;
struct sockaddr_in addr;
int sock_fd = 0, file_fd = 0, seqBase = 0, accumulatedBytes = 0;

vector<segment> segment_buffer(MAX_SEG_BUF_SIZE);
int base = 1;
bool finish = false;

unsigned char sha256_hash[EVP_MAX_MD_SIZE];
unsigned int hash_len;
EVP_MD_CTX *sha256 = EVP_MD_CTX_new();

// to hex string
string hexDigest(const void *buf, int len) {
    const unsigned char *cbuf = static_cast<const unsigned char *>(buf);
    ostringstream hx{};

    for (int i = 0; i != len; ++i)
        hx << hex << setfill('0') << setw(2) << (unsigned int)cbuf[i];

    return hx.str();
}

void setIP(char *dst, char *src){
    if(strcmp(src, "0.0.0.0") == 0 || strcmp(src, "local") == 0 || strcmp(src, "localhost") == 0){
        sscanf("127.0.0.1", "%s", dst);
    }
    else{
        sscanf(src, "%s", dst);
    }
    return;
}

void flush() {
    // Flush buffer and deliver to application (i.e. hash and store)
    printf("flush\n");
    // update seqBase
    seqBase += MAX_SEG_BUF_SIZE;
    // calculate SHA256 hash
    int nBytes = 0;
    for (int i = 0; i < segment_buffer.size(); i++) {
        if (segment_buffer[i].head.length == 0) {
            break;
        }
        nBytes += segment_buffer[i].head.length;
        EVP_DigestUpdate(sha256, segment_buffer[i].data, segment_buffer[i].head.length);
        EVP_MD_CTX *tmp_sha256 = EVP_MD_CTX_new();
        EVP_MD_CTX_copy_ex(tmp_sha256, sha256);
        EVP_DigestFinal_ex(tmp_sha256, sha256_hash, &hash_len);
        EVP_MD_CTX_free(tmp_sha256);
    }
    printf("sha256\t%d\t%s\n", nBytes+accumulatedBytes , hexDigest(sha256_hash, hash_len).c_str());
    if (finish)
        printf("finsha\t%s\n", hexDigest(sha256_hash, hash_len).c_str());    
    accumulatedBytes += nBytes;

    // flush buffer
    for (int i = 0; i < segment_buffer.size(); i++) {
        if (segment_buffer[i].head.length == 0) {
            break;
        }
        if (write(file_fd, segment_buffer[i].data, segment_buffer[i].head.length) < 0) {
            perror("write");
            exit(1);
        }
        segment_buffer[i].head.length = 0;
        segment_buffer[i].head.seqNumber = 0;
        segment_buffer[i].head.checksum = 0;
        bzero(segment_buffer[i].data, sizeof(char) * MAX_SEG_SIZE);
    }
    // for (int i = 0; i < segment_buffer.size(); i++) {
    // }
}

bool isAllReceived() {
    /*
        True if every packet (i.e. packet before AND INCLUDING fin) is received.
        This actually should happen when you receive FIN, no matter what.
    */
   return finish;
}

void endReceive() {
    // Indicate that this connection is finished
    EVP_MD_CTX_free(sha256);
    close(sock_fd);
}

bool isBufferFull() {
    // True if the buffer is full else False
    for (int i = 0; i < MAX_SEG_BUF_SIZE; i++) {
        if (segment_buffer[i].head.length == 0) {
            return false;
        }
    }
    return true;
}

bool isCorrupt(struct segment pkt) {
    // True if the packet is corrupted else False
    return pkt.head.checksum != crc32(0L, (const Bytef *)pkt.data, pkt.head.length);
}

void sendSACK(int ack_seq_num, int sack_seq_num, bool is_fin=false) {
    // Send a SACK packet
    segment sgmt{};
    sgmt.head.ack = 1;
    sgmt.head.ackNumber = ack_seq_num;
    sgmt.head.sackNumber = sack_seq_num;
    sgmt.head.fin = is_fin;
    if (is_fin)
        printf("send\tfinack\n");
    else
        printf("send\tack\t#%d,\tsack\t#%d\n", ack_seq_num , sack_seq_num);
    sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
}

void markSACK(int seq_num, struct segment pkt) {
    /*
        Mark and put segment with sequence number seq_num in buffer
        (only if it is in current buffer range, if it is over buffer range then 
        you should've dropped this packet.)
    */
    seq_num = (seq_num-1) % MAX_SEG_BUF_SIZE;
    segment_buffer[seq_num].head.length = pkt.head.length;
    segment_buffer[seq_num].head.seqNumber = pkt.head.seqNumber;
    segment_buffer[seq_num].head.checksum = pkt.head.checksum;
    memcpy(segment_buffer[seq_num].data, pkt.data, pkt.head.length);
}

// not sure if this is correct
void updateBase(int ack_num) {
    // Update base and buffer s.t. base is the first unsacked packet
    for (int i = 0; i < segment_buffer.size(); i++) {
        if (i == (ack_num-1)%MAX_SEG_BUF_SIZE)
            continue;
        // printf("size:%ld, i:%d, acknum:%d, mod:%d\n", segment_buffer.size(), i, ack_num, (ack_num-1)%MAX_SEG_BUF_SIZE);
        if (segment_buffer[i].head.seqNumber == 0) {
            base = i + 1 + seqBase;
            break;
        }
    }
    if (ack_num % MAX_SEG_BUF_SIZE == 0 && ack_num / MAX_SEG_BUF_SIZE > 0) {
        base = MAX_SEG_BUF_SIZE + seqBase + 1;
    }
    // printf("acknum:%d, base:%d, %d, %d\n", ack_num, base, ack_num % MAX_SEG_BUF_SIZE, ack_num / MAX_SEG_BUF_SIZE);
}

bool isOverBuffer(int seq_num) {
    /*
        True if the sequence number is above buffer range
        e.g. if the buffer stores sequence number in range [1, 257) and receives
            a segment with seqNumber 257 (or above 257), return True
    */
    if (seq_num >= MAX_SEG_BUF_SIZE + seqBase) {
        return true;
    } 
    return false;
} 

// ./receiver <recv_ip> <recv_port> <agent_ip> <agent_port> <dst_filepath>
int main(int argc, char *argv[]) {
    // parse arguments
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <recv_ip> <recv_port> <agent_ip> <agent_port> <dst_filepath>" << endl;
        exit(1);
    }

    int recv_port, agent_port;
    char recv_ip[50], agent_ip[50];

    // read argument
    setIP(recv_ip, argv[1]);
    sscanf(argv[2], "%d", &recv_port);

    setIP(agent_ip, argv[3]);
    sscanf(argv[4], "%d", &agent_port);

    char *filepath = argv[5];

    // make socket related stuff
    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);

    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(agent_port);
    recv_addr.sin_addr.s_addr = inet_addr(agent_ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(recv_port);
    addr.sin_addr.s_addr = inet_addr(recv_ip);
    memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));    
    bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr));

    if ((file_fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0777)) < 0) {
        perror("open");
        exit(1);
    }
    EVP_DigestInit_ex(sha256, EVP_sha256(), NULL);

    while (!finish) {
        int recvBytes = 0;
        socklen_t recv_addr_sz;
        struct segment recv_sgmt{};
        recvBytes = recvfrom(sock_fd, &recv_sgmt, sizeof(recv_sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz);
        if (recvBytes <= 0)
            continue;
        // printf("recvBytes:%d, seq_num:%d, base:%d\n", recvBytes, recv_sgmt.head.seqNumber, base);

        if (recv_sgmt.head.fin) {
            printf("recv\tfin\n");
            finish = true;
            sendSACK(base-1, base-1, recv_sgmt.head.fin);
            if (isAllReceived()) {
                flush();
                endReceive();
            } else if (isBufferFull()) {
                flush();
            }
            break;
        } else if (isCorrupt(recv_sgmt)) {
            // Corrupt: drop
            // (still send sack, but effectively only cumulative ack)
            printf("drop\tdata\t#%d\t(corrupted)\n", recv_sgmt.head.seqNumber);
            sendSACK(base-1, base-1, false);
            // not sure if this is correct
            continue;
        }

        if (recv_sgmt.head.seqNumber == base) {
            // In order
            updateBase(recv_sgmt.head.seqNumber);
            markSACK(recv_sgmt.head.seqNumber, recv_sgmt);
            printf("recv\tdata\t#%d\t(in order)\n", recv_sgmt.head.seqNumber);
            sendSACK(base-1, recv_sgmt.head.seqNumber, recv_sgmt.head.fin);
            if (isAllReceived()) {
                flush();
                endReceive();
            } else if (isBufferFull()) {
                flush();
            }
        } else {
            // Out of order
            if (isOverBuffer(recv_sgmt.head.seqNumber)) {
                // out of buffer range (buffer_end), drop
                // (still send sack, but effectively only cumulative ack)
                printf("drop\tdata\t#%d\t(buffer overflow)\n", recv_sgmt.head.seqNumber);
                sendSACK(base-1, base-1, false);
            } else {
                // out of order sack or under buffer range
                // just do sack the normal way
                printf("recv\tdata\t#%d\t(out of order, sack-ed)\n", recv_sgmt.head.seqNumber);
                markSACK(recv_sgmt.head.seqNumber, recv_sgmt);
                sendSACK(base-1, recv_sgmt.head.seqNumber, recv_sgmt.head.fin);
            }
        }
    }
    
    // receive a segment! (do the logging on your own)
    // socklen_t recv_addr_sz;
    // segment recv_sgmt{};
    // recvfrom(sock_fd, &recv_sgmt, sizeof(recv_sgmt), 0, (struct sockaddr *)&recv_addr, &recv_addr_sz);

    // cerr << "get data: " << string(recv_sgmt.data, recv_sgmt.head.length) << endl;

    // send a segment!
    // segment sgmt{};
    // sgmt.head.ack = 1;
    // sgmt.head.ackNumber = recv_sgmt.head.seqNumber;
    // sgmt.head.sackNumber = recv_sgmt.head.seqNumber;

    // sendto(sock_fd, &sgmt, sizeof(sgmt), 0, (struct sockaddr *)&recv_addr, sizeof(sockaddr));
    close(file_fd);
}