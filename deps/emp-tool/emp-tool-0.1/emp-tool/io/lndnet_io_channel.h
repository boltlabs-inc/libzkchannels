#ifndef LND_NETWORK_IO_CHANNEL
#define LND_NETWORK_IO_CHANNEL

#include "emp-tool/io/io_channel.h"
#include "emp-tool/io/net_callback.h"

namespace emp {

/** @addtogroup IO
  @{
 */
    class LndNetIO: public IOChannel<LndNetIO> {
    public:
        bool is_server;
        void* peer_ptr;
        cb_receive recv;
        cb_send send;
        uint64_t counter = 0;
        char * buffer = nullptr;
        char * recv_buffer = nullptr;
        int buffer_ptr = 0;
        int recv_buffer_ptr = 0;
        int received_ptr = 0;
        int buffer_cap = NETWORK_BUFFER_SIZE;
        bool has_send = false;
        LndNetIO(void* peer_ptr, cb_send send, cb_receive recv, bool is_server, bool quiet = false) {
            this->is_server = is_server;
            this->peer_ptr = peer_ptr;
            this->recv = recv;
            this->send = send;
            buffer = new char[buffer_cap];
            recv_buffer = new char[buffer_cap];
            if(!quiet)
                std::cout << "connected\n";
        }
        void sync() {
            int tmp = 0;
            if(is_server) {
                send_data(&tmp, 1);
                recv_data(&tmp, 1);
            } else {
                recv_data(&tmp, 1);
                send_data(&tmp, 1);
                flush();
            }
        }

        ~LndNetIO() {
            flush();
            delete[] buffer;
            delete[] recv_buffer;
        }

        void flush() {
            if (buffer_ptr != 0)
                (*send)(buffer, buffer_ptr, peer_ptr);
            buffer_ptr = 0;
        }

        void send_data(const void * data, int len) {
            counter += len;
            if (len >= buffer_cap) {
                if(has_send) {
                    flush();
                }
                has_send = false;
                (*send)((char *) data, len, peer_ptr);
                return;
            }
            if (buffer_ptr + len > buffer_cap)
                flush();
            memcpy(buffer + buffer_ptr, data, len);
            buffer_ptr += len;
            has_send = true;
        }

        void recv_data(void  * data, int len) {
            int sent = 0;
            if(has_send) {
                flush();
            }
            has_send = false;
            while (sent < len) {
                int prev_sent = sent;
                if (len-sent > received_ptr - recv_buffer_ptr) {
                    Receive_return recv_msg = (*recv)(peer_ptr);
                    int res = recv_msg.r1;
                    memcpy(recv_buffer, recv_msg.r0, res);
                    received_ptr += res;
                }
                sent += received_ptr - recv_buffer_ptr;
                memcpy(prev_sent + (char*) data, recv_buffer+recv_buffer_ptr, len-prev_sent);
                recv_buffer_ptr += len-prev_sent;
                if (recv_buffer_ptr == received_ptr) {
                    recv_buffer_ptr = 0;
                    received_ptr = 0;
                }
            }
        }

        LndNetIO* duplicate(int id) {
            return new LndNetIO(peer_ptr, send, recv, is_server);
        }
    };

}

#endif  //LND_NETWORK_IO_CHANNEL
