#ifndef UNIX_NETWORK_IO_CHANNEL
#define UNIX_NETWORK_IO_CHANNEL

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "emp-tool/io/io_channel.h"
using std::string;

#ifdef UNIX_PLATFORM

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

namespace emp {
/** @addtogroup IO
  @{
 */

class UnixNetIO: public IOChannel<UnixNetIO> { public:
    bool is_server;
    int mysocket = -1;
    int consocket = -1;
    FILE * stream = nullptr;
    char * buffer = nullptr;
    bool has_sent = false;
    uint64_t counter = 0;

    UnixNetIO(const char *socket_path, bool is_server, bool quiet = false) {
        this->is_server = is_server;
        if (is_server) {
            // unix domain socket - server
            unlink(socket_path); // clean up
            struct sockaddr_un dest;
            memset(&dest, 0, sizeof(dest));
            dest.sun_family = AF_UNIX;
            strncpy(dest.sun_path, socket_path, sizeof(dest.sun_path)-1);
            // std::cout << "socket: " << string(dest.sun_path) << "\n";

            mysocket = socket(AF_UNIX, SOCK_STREAM, 0);

            if(bind(mysocket, (struct sockaddr *)&dest, sizeof(struct sockaddr)) < 0) {
                perror("error: bind");
                exit(1);
            }

            if(listen(mysocket, 1) < 0) {
                perror("error: listen");
                exit(1);
            }

            consocket = accept(mysocket, NULL, NULL);
            if (consocket == -1) {
                perror("error: accept");
                exit(1);
            }
        }
        else {
            // unix domain socket - client
            struct sockaddr_un dest;
            memset(&dest, 0, sizeof(dest));
            dest.sun_family = AF_UNIX;
            strncpy(dest.sun_path, socket_path, sizeof(dest.sun_path)-1);

            while(1) {
                consocket = socket(AF_UNIX, SOCK_STREAM, 0);

                if (connect(consocket, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == 0) {
                    break;
                }
                usleep(1000);
            }
        }
        set_nodelay();
        stream = fdopen(consocket, "wb+");
        buffer = new char[NETWORK_BUFFER_SIZE];
        memset(buffer, 0, NETWORK_BUFFER_SIZE);
        setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
        if(!quiet)
            std::cout << "connected via unix domain socket: " << string(socket_path) << "\n";
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

    ~UnixNetIO(){
        fflush(stream);
        close(consocket);
        delete[] buffer;
    }

    void set_nodelay() {
        const int one=1;
        setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    }

    void set_delay() {
        const int zero = 0;
        setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&zero,sizeof(zero));
    }

    void flush() {
        fflush(stream);
    }

    void send_data(const void * data, int len) {
        counter += len;
        int sent = 0;
        while(sent < len) {
            int res = fwrite(sent + (char*)data, 1, len - sent, stream);
            if (res >= 0)
                sent+=res;
            else
                fprintf(stderr,"error: net_send_data %d\n", res);
        }
        has_sent = true;
    }

    void recv_data(void  * data, int len) {
        if(has_sent)
            fflush(stream);
        has_sent = false;
        int sent = 0;
        while(sent < len) {
            int res = fread(sent + (char*)data, 1, len - sent, stream);
            if (res >= 0)
                sent += res;
            else
                fprintf(stderr,"error: net_send_data %d\n", res);
        }
    }
};
/**@}*/

}

#else  // not UNIX_PLATFORM

#include <boost/asio.hpp>
// using boost::asio::ip::tcp;
using boost::asio::local::stream_protocol;

namespace emp {

/** @addtogroup IO
  @{
 */
class UnixNetIO: public IOChannel<UnixNetIO> {
public:
	bool is_server;
	uint64_t counter = 0;
	char * buffer = nullptr;
	int buffer_ptr = 0;
	int buffer_cap = NETWORK_BUFFER_SIZE;
	bool has_send = false;
	boost::asio::io_service io_service;
    stream_protocol::socket s = stream_protocol::socket(io_service);

	UnixNetIO(const char *socket_path, bool is_server, bool quiet = false) {
		this->is_server = is_server;
        stream_protocol::endpoint ep(socket_path);

		if (is_server) {
			stream_protocol::acceptor acceptor(io_service, ep);
			s = stream_protocol::socket(io_service);
			acceptor.accept(s);
		} else {
			s = stream_protocol::socket(io_service);
			s.connect(ep);
		}
		s.set_option( boost::asio::socket_base::send_buffer_size( 65536 ) );
		buffer = new char[buffer_cap];
		set_nodelay();
		if(!quiet)
            std::cout << "connected via unix domain socket: " << string(socket_path) << "\n";
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

    ~UnixNetIO() {
        flush();
        delete[] buffer;
    }

    void set_nodelay() {
        s.set_option(boost::asio::local::stream_protocol::no_delay(true));
    }

    void set_delay() {
        s.set_option(boost::asio::local::stream_protocol::no_delay(false));
    }

    void flush() {
        boost::asio::write(s, boost::asio::buffer(buffer, buffer_ptr));
        buffer_ptr = 0;
    }

    void send_data(const void * data, int len) {
        counter += len;
        if (len >= buffer_cap) {
            if(has_send) {
                flush();
            }
            has_send = false;
            boost::asio::write(s, boost::asio::buffer(data, len));
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
        while(sent < len) {
            int res = s.read_some(boost::asio::buffer(sent + (char *)data, len - sent));
            if (res >= 0)
                sent += res;
            else
                fprintf(stderr,"error: net_send_data %d\n", res);
        }
    }

    UnixNetIO* duplicate(int id) {
	    return this;
//        io = new UnixNetIO(socket_path, is_server);
    }
};

}

#endif  //UNIX_PLATFORM
#endif  //UNIX_NETWORK_IO_CHANNEL
