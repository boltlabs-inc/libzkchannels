#ifndef FEQ_H__
#define FEQ_H__
#include <emp-tool/emp-tool.h>

namespace emp {
template<typename IO>
class Feq {
public:
	Hash h;
	IO* io = nullptr;
	int party;
    Feq(IO* io, int party) {
		this->io = io;
		this->party = party;
	}
	void add(void * data, int length) {
		h.put(data, length);
	}
	bool compare() {
		char dgst[Hash::DIGEST_SIZE + 1];
		char dgst2[Hash::DIGEST_SIZE];
		char dgst3[Hash::DIGEST_SIZE];
		char dgst4[Hash::DIGEST_SIZE];
		dgst[Hash::DIGEST_SIZE] = 0x0;
		h.digest(dgst);
		dgst[Hash::DIGEST_SIZE] = party & 0xF;
		Hash::hash_once(dgst2, dgst, sizeof(dgst));
		dgst[Hash::DIGEST_SIZE] = (ALICE + BOB - party) & 0xF;
		Hash::hash_once(dgst3, dgst, sizeof(dgst));
		if (party == ALICE) {
			io->send_data(dgst2, Hash::DIGEST_SIZE);
			io->recv_data(dgst4, Hash::DIGEST_SIZE);
		} else {
			io->recv_data(dgst4, Hash::DIGEST_SIZE);
			io->send_data(dgst2, Hash::DIGEST_SIZE);
			io->flush();
		}
		return strncmp(dgst3, dgst4, Hash::DIGEST_SIZE) == 0;
	}
};

}
#endif// FEQ_H__
