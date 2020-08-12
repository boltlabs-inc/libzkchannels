#ifndef GO_NETWORK_IO_CHANNEL
#define GO_NETWORK_IO_CHANNEL

#include "emp-tool/io/io_channel.h"

using std::string;

namespace emp {

/** @addtogroup GoNetIO
  @{
 */
class GoNetIO: public IOChannel<GoNetIO> {
public:
	bool is_server;
	void* peer_ptr;
	FILE *stream = nullptr;
	char * buffer = nullptr;
	bool has_sent = false;
	uint64_t counter = 0;

	GoNetIO(void *stream_ptr, bool is_server, bool quiet = false) {
		this->is_server = is_server;
		// expecting an existing pointer to a file descriptor
		this->stream = static_cast<FILE*>(stream_ptr);
		if(this->stream != NULL)
		    std::cout << "GoNetIO: connected via GoNetIO\n";
		else
		    std::cerr << "GoNetIO: invalid file descriptor for socket specified\n";
		// create the buffer and check that
		buffer = new char[NETWORK_BUFFER_SIZE];
		memset(buffer, 0, NETWORK_BUFFER_SIZE);
		setvbuf(this->stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
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

	~GoNetIO(){
		fflush(stream);
		delete[] buffer;
	}

//	void set_nodelay() {
//		const int one=1;
//		setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
//	}
//
//	void set_delay() {
//		const int zero = 0;
//		setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&zero,sizeof(zero));
//	}

	void flush() {
		fflush(stream);
	}

    void duplicate(void * io, int id) {
        io = new GoNetIO(stream, is_server);
    }

	void send_data(const void * data, int len) {
		counter += len;
		int sent = 0;
		while(sent < len) {
			int res = fwrite(sent + (char*)data, 1, len - sent, stream);
			if (res >= 0)
				sent+=res;
			else
				fprintf(stderr, "send_data::error: net_send_data %d\n", res);
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
				fprintf(stderr,"recv_data::error: net_send_data %d\n", res);
		}
	}

//	cb_receive recv;
//	cb_send send;
//
//	GoNetIO(void* peer_ptr, cb_receive recv, cb_send send, bool is_server, bool quiet = false) {
//	    this->is_server = is_server;
//	    this->peer_ptr = peer_ptr;
//	    this->recv = recv;
//	    this->send = send;
//	}
//
//	void sync() {
//		int tmp = 0;
//		if(is_server) {
//			send_data(&tmp, 1);
//			recv_data(&tmp, 1);
//		} else {
//			recv_data(&tmp, 1);
//			send_data(&tmp, 1);
//		}
//	}
//
//	~GoNetIO() {
//
//	}
//
//	void flush() { }
//
//	void send_data(const void * data, int len) {
//		send((char *) data, len, peer_ptr);
//	}
//
//	void recv_data(void  * data, int len) {
//		Receive_l recv_msg = recv(peer_ptr);
//		data = recv_msg.r0;
//		len = recv_msg.r1;
//	}

};

}

#endif // GO_NETWORK_IO_CHANNEL
