#include <emp-tool/emp-tool.h>
#include "abit.h"
#include<thread>
using namespace std;
using namespace emp;

static inline uint64_t get_cycles()
{
	uint64_t t;
	__asm volatile ("rdtsc" : "=A"(t));
	return t;
}
	int size = 1<<25;
const int nt = 10;
void fun(ABit * abit, int party, bool * bb, block * t1) {
	if(party == ALICE) {
		abit->send(t1, size);
	} else {
		abit->recv(t1, bb, size);
	}
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO *io[nt];
	NetIO *io2[nt];
	ABit *abit[nt];
	ABit *abit2[nt];
	block *t1[nt];bool*bb[nt];
	block *t2[nt];bool*bb2[nt];
	PRG prg;
	for(int i = 0; i < nt; ++i){ 
		io[i] = new NetIO(party==ALICE ? nullptr:IP, port+i);
		io2[i] = new NetIO(party==ALICE ? nullptr:IP, port+i+20);
		abit[i] = new ABit(io[i]);
		abit2[i] = new ABit(io2[i]);
		t1[i] = new block[size];
		bb[i] = new bool[size];
		t2[i] = new block[size];
		bb2[i] = new bool[size];
		prg.random_bool(bb[i], size);
	}
	
	auto tt1 = clock_start();
	vector<thread> ths;
	for(int i = 0; i < nt; ++i) {
		ths.push_back(thread(fun, abit[i], party, bb[i], t1[i]));
		ths.push_back(thread(fun, abit2[i], ALICE+BOB-party, bb2[i], t2[i]));
		}

	for(int i = 0; i < 2*nt; ++i)
		ths[i].join();
	cout << time_from(tt1)<<endl;

	/*	block Delta, tmp;
		if (party == ALICE) {
		io->send_block(&(abit.Delta), 1);
		io->send_block(t1, size);
		} else {
		io->recv_block (&Delta, 1);
		for(int i = 0; i < size; ++i) {
		io->recv_block (&tmp, 1);
		if(bb[i])
		tmp = xorBlocks(tmp, Delta);
		assert(memcmp(&t1[i], &tmp, 16)==0);
		}
		}*/
	return 0;
}
