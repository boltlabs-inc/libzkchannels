#ifndef FPRE_H__
#define FPRE_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <thread>
#include "feq.h"
#include "emp-ag2pc/helper.h"
#include "c2pc_config.h"

namespace emp {
//#define __debug
template<typename IO>
void abit_run(DeltaOT<IO> * abit, IO * io, bool send, block * blocks, bool * bools, int length) {
	io->flush();
	if(send) {
		abit->send(blocks, length);
	} else {
		abit->recv(blocks, bools, length);
	}
	io->flush();
}

template<typename IO>
class Fpre;
template<typename IO>
void combine_merge(Fpre<IO> * fpre, int start, int length, int I, bool * data, bool* data2, block * MAC2, block * KEY2, bool *r2, int * location);

template<typename IO>
class Fpre {
	public:
		ThreadPool *pool;
		const static int THDS = fpre_threads;
		int batch_size = 0, bucket_size = 0, size = 0;
		int party;
		block * keys = nullptr;
		bool * values = nullptr;
		PRG prg;
		PRP prp;
		PRP *prps;
		IO *io[THDS];
		IO *io2[THDS];
		DeltaOT<IO> *abit1[THDS], *abit2[THDS];
		block Delta;
		Feq<IO> *eq[THDS];
		block * MAC = nullptr, *KEY = nullptr;
		bool * r = nullptr;
		block * pretable = nullptr;
		Fpre(IO * in_io, int in_party, int bsize = 1000) {
			pretable = DeltaOT<IO>::preTable(40);
			pool = new ThreadPool(THDS*2);
			prps = new PRP[THDS];
			this->party = in_party;
			for(int i = 0; i < THDS; ++i) {
                io[i] = in_io->duplicate(2*i+1);
                io2[i] = in_io->duplicate(2*i+2);
				eq[i] = new Feq<IO>(io[i], party);
			}
			abit1[0] = new DeltaOT<IO>(io[0], pretable, 40);
			abit2[0] = new DeltaOT<IO>(io2[0], pretable, 40);

			MOTExtension<IO> ote(io[0]);
			block tmp_k0[128*2], tmp_k1[128*2];
			bool tmp_s[128*2];
			int l = 128+40;
			if(party == ALICE) {
				prg.random_bool(tmp_s, l);
				ote.recv_rot(tmp_k0, tmp_s, l);
				abit1[0]->setup_send(tmp_s, tmp_k0);
				abit1[0]->send(tmp_k0, l);
				for(int i = 0; i < l; ++i)
					tmp_k1[i] = xorBlocks(abit1[0]->Delta, tmp_k0[i]);
				abit2[0]->setup_recv(tmp_k0, tmp_k1);
			}
			else {
				ote.send_rot(tmp_k0, tmp_k1, l);
				abit1[0]->setup_recv(tmp_k0, tmp_k1);
				prg.random_bool(tmp_s, l);
				abit1[0]->recv(tmp_k0, tmp_s, l);
				abit2[0]->setup_send(tmp_s, tmp_k0);
			}

			for(int i = 1; i < THDS; ++i) {
				abit1[i] = new DeltaOT<IO>(io[i], pretable, 40);
				abit2[i] = new DeltaOT<IO>(io2[i], pretable, 40);
				if (party == ALICE) {
					abit1[i]->setup_send(abit1[0]->s, abit1[0]->k0);
					abit2[i]->setup_recv(abit2[0]->k0, abit2[0]->k1);
				} else {
					abit1[i]->setup_recv(abit1[0]->k0, abit1[0]->k1);
					abit2[i]->setup_send(abit2[0]->s, abit2[0]->k0);
				}
			}
			if(party == ALICE) Delta = abit1[0]->Delta;
			else Delta = abit2[0]->Delta;
			set_batch_size(bsize);
		}
		void set_batch_size(int size) {
			size = std::max(size, 320);
			batch_size = ((size+THDS-1)/THDS)*THDS;
			if(batch_size >= 280*1000)
				bucket_size = 3;
			else if(batch_size >= 3100)
				bucket_size = 4;
			else bucket_size = 5;
			if (MAC != nullptr) {
				delete[] MAC;
				delete[] KEY;
				delete[] r;
			}
			MAC = aalloc<block>(batch_size * bucket_size * 3);
			KEY = aalloc<block>(batch_size * bucket_size * 3);
			r = new bool[batch_size * bucket_size * 3];
		}
		~Fpre() {
			if(MAC != nullptr) {
				free(MAC);
				free(KEY);
				delete[]r;
			}
			delete[] prps;
			delete pool;
			for(int i = 0; i < THDS; ++i) {
				delete abit1[i];
				delete abit2[i];
				delete io[i];
				delete io2[i];
				delete eq[i];
			}
		}
		void refill() {
			prg.random_bool(r, batch_size * 3 * bucket_size);
#ifdef __debug
			double t1 = timeStamp();
#endif
			vector<future<void>> res;
			for(int i = 0; i < THDS; ++i) {
				int start = i*batch_size/THDS;
				int length = batch_size/THDS;
				res.push_back(pool->enqueue([this, start, length, i](){
							io[i]->flush();
							io2[i]->flush();
							generate(MAC + start * bucket_size*3, KEY + start * bucket_size*3, r + start * bucket_size*3, length * bucket_size, i);
							io[i]->flush();
							io2[i]->flush();
							check(   MAC + start * bucket_size*3, KEY + start * bucket_size*3, r + start * bucket_size*3, party == ALICE, length * bucket_size, io[i], i);
							io[i]->flush();
							check(   MAC + start * bucket_size*3, KEY + start * bucket_size*3, r + start * bucket_size*3, party == BOB, length * bucket_size, io2[i], i);
							io2[i]->flush();
							}));
			}
			for(int i = 0; i < THDS; ++i)
				res[i].get();
#ifdef __debug
			double t2 = timeStamp();
			cout << "\t Fpre: Generate N Check:\t"<< t2-t1<<endl;
			check_correctness(MAC, KEY, r, batch_size*bucket_size);
			t1 = timeStamp();
#endif
			combine(MAC, KEY, r, batch_size, bucket_size);
#ifdef __debug
			t2 = timeStamp();
			cout << "\t Fpre: Permute N Combine:\t"<< t2-t1<<endl;
			check_correctness(MAC, KEY, r, batch_size);
#endif
			for(int i = 0; i < THDS; ++i)
				if(!eq[i]->compare()) {
					error("FEQ error\n");
				}
		}
		void generate(block * MAC, block * KEY, bool * r, int length, int I) {
			if (party == ALICE) {
				if(I%2 == 1) {
					future<void> res = pool->enqueue(abit_run<IO>, abit1[I], io[I], true, KEY, nullptr, length*3);
					abit_run<IO>(abit2[I], io2[I], false, MAC, r, length*3);
					res.get();
				} else {
					future<void> res = pool->enqueue(abit_run<IO>, abit1[I], io[I], true, KEY, nullptr, length*3);
					abit_run<IO>(abit2[I], io2[I], false, MAC, r, length*3);
					res.get();
				}
				uint8_t * data = new uint8_t[length];
				for(int i = 0; i < length; ++i) {
					block tmp[4], tmp2[4];
					tmp[0] = KEY[3*i];
					tmp[1] = xorBlocks(tmp[0], Delta);
					tmp[2] = KEY[3*i+1];
					tmp[3] = xorBlocks(tmp[2], Delta);
					prps[I].template H<4>(tmp, tmp, 4*i);

					tmp2[0] = xorBlocks(tmp[0], tmp[2]);
					tmp2[1] = xorBlocks(tmp[1], tmp[2]);
					tmp2[2] = xorBlocks(tmp[0], tmp[3]);
					tmp2[3] = xorBlocks(tmp[1], tmp[3]);

					data[i] = getLSB(tmp2[0]);
					data[i] |= (getLSB(tmp2[1])<<1);
					data[i] |= (getLSB(tmp2[2])<<2);
					data[i] |= (getLSB(tmp2[3])<<3);
					if ( ((false != r[3*i] ) && (false != r[3*i+1])) != r[3*i+2] )
						data[i] = data[i] ^ 0x1;
					if ( ((true != r[3*i] ) && (false != r[3*i+1])) != r[3*i+2] )
						data[i] = data[i] ^ 0x2;
					if ( ((false != r[3*i] ) && (true != r[3*i+1])) != r[3*i+2] )
						data[i] = data[i] ^ 0x4;
					if ( ((true != r[3*i] ) && (true != r[3*i+1])) != r[3*i+2] )
						data[i] = data[i] ^ 0x8;

					io[I]->send_data(&data[i], 1);
				}
				bool *bb = new bool[length];
				recv_bool(io[I], bb, length);
				for(int i = 0; i < length; ++i) {
					if(bb[i]) KEY[3*i+2] = xorBlocks(KEY[3*i+2], Delta);
				}
				delete[] bb;
				delete[] data;
			} else {
				if(I%2 == 1) {
					future<void> res = pool->enqueue(abit_run<IO>, abit1[I], io2[I], false, MAC, r, length*3);
					abit_run<IO>(abit2[I], io[I], true, KEY, nullptr, length*3);
					res.get();
				} else {
					future<void> res = pool->enqueue(abit_run<IO>, abit1[I], io2[I], false, MAC, r, length*3);
					abit_run<IO>( abit2[I], io[I], true, KEY, nullptr, length*3);
					res.get();
				}
				uint8_t tmp;
				bool *d = new bool[length];
				for(int i = 0; i < length; ++i) {
					io[I]->recv_data(&tmp, 1);
					block H = xorBlocks(prps[I].H(MAC[3*i], 4*i + r[3*i]), prps[I].H(MAC[3*i+1], 4*i + 2 + r[3*i+1]));

					uint8_t res = getLSB(H);
					tmp >>= (r[3*i+1]*2+r[3*i]);
					d[i] = r[3*i+2] != ((tmp&0x1) != (res&0x1));
					r[3*i+2] = (!(tmp&0x1) != !(res&0x1));
				}
				send_bool<IO>(io[I], d, length);
				delete[] d;
			}
		}
		void check(const block * MAC, const block * KEY, const bool * r, bool checker, int length, IO * local_io, int I) {
			local_io->flush();
			block * T = new block[length]; 
			if(checker) {
				for(int i = 0; i < length; ++i) {
					block tmp[2], tmp2[2], tmp3[2];
					tmp[0] = double_block(KEY[3*i]);
					tmp[1] = double_block(xorBlocks(KEY[3*i], Delta));

					tmp2[0] = KEY[3*i+2];
					if(r[3*i+2]) tmp2[0] = xorBlocks(tmp2[0], Delta);

					tmp2[1] = xorBlocks(KEY[3*i+1], KEY[3*i+2]);
					if(r[3*i+2] != r[3*i+1]) tmp2[1] = xorBlocks(tmp2[1], Delta);

					tmp2[0] = double_block( double_block (tmp2[0]));
					tmp2[1] = double_block( double_block (tmp2[1]));

					tmp3[0] = xorBlocks(tmp[r[3*i]], tmp2[0]);
					tmp3[1] = xorBlocks(tmp[!r[3*i]], tmp2[1]);

					prps[I].template H<2>(tmp, tmp3, 2*i);

					T[i] = tmp[r[3*i]];
					tmp[1] = xorBlocks(tmp[0], tmp[1]);
					local_io->send_block(&tmp[1], 1);
				}
				for(int i = 0; i < length; ++i) {
					block W = xorBlocks(T[i], prps[I].H(MAC[3*i], 2*i+r[3*i])), tmp;

					local_io->recv_block(&tmp, 1);
					if(r[3*i]) W = xorBlocks(W, tmp);

					eq[I]->add(&W, sizeof(block));
				}
			} else {
				for(int i = 0; i < length; ++i) {
					block V[2], tmp2[2];
					V[0] = double_block(MAC[3*i]);
					V[1] = double_block(MAC[3*i]);
					tmp2[0] = double_block(double_block(MAC[3*i+2]));
					tmp2[1] = double_block(double_block(xorBlocks(MAC[3*i+2], MAC[3*i+1])));
					xorBlocks_arr(V, V, tmp2, 2);
					prps[I].template H<2>(V, V, 2*i);

					block U;
					local_io->recv_block(&U, 1);

					tmp2[0] = KEY[3*i];
					tmp2[1] = xorBlocks(KEY[3*i], Delta);
					prps[I].template H<2>(tmp2, tmp2, 2*i);
					T[i] = xorBlocks(tmp2[0], tmp2[1]);
					T[i] = xorBlocks(T[i], V[0]);
					T[i] = xorBlocks(T[i], V[1]);

					block T2 = xorBlocks(tmp2[0], V[r[3*i]]);
					if(r[3*i])
						T2 = xorBlocks(T2, U);
					eq[I]->add(&T2, sizeof(block));
				}
				local_io->send_block(T, length);
			}
			local_io->flush();
			delete[] T;
		}
		void check_correctness(block * MAC, block * KEY, bool * r, int length) {
			if (party == ALICE) {
				io[0]->send_data(r, length*3);
				io[0]->send_block(&Delta, 1);
				io[0]->send_block(KEY, length*3);
				block DD;io[0]->recv_block(&DD, 1);

				for(int i = 0; i < length*3; ++i) {
					block tmp;io[0]->recv_block(&tmp, 1);
					if(r[i]) tmp = xorBlocks(tmp, DD);
					if (!block_cmp(&tmp, &MAC[i], 1))
						cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
				}

			} else {
				bool tmp[3];
				for(int i = 0; i < length; ++i) {
					io[0]->recv_data(tmp, 3);
					bool res = ((tmp[0] != r[3*i] ) && (tmp[1] != r[3*i+1]));
					if(res != (tmp[2] != r[3*i+2]) ) {
						cout <<i<<"\tWRONG!"<<endl<<flush;
					}
				}
				block DD;io[0]->recv_block(&DD, 1);

				for(int i = 0; i < length*3; ++i) {
					block tmp;io[0]->recv_block(&tmp, 1);
					if(r[i]) tmp = xorBlocks(tmp, DD);
					if (!block_cmp(&tmp, &MAC[i], 1))
						cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
				}

				io[0]->send_block(&Delta, 1);
				io[0]->send_block(KEY, length*3);
			}
		}

		void combine(block * MAC, block * KEY, bool * r, int length, int bucket_size) {
			block S, HS, S2, HS2; prg.random_block(&S, 1);
			HS = S;
			prp.permute_block(&HS, 1);
			if (party == ALICE) {
				io[0]->send_block(&HS, 1);
				io[0]->recv_block(&HS2, 1);
				io[0]->recv_block(&S2, 1);
				io[0]->send_block(&S, 1);
			} else {
				io[0]->recv_block(&HS2, 1);
				io[0]->send_block(&HS, 1);
				io[0]->send_block(&S, 1);
				io[0]->recv_block(&S2, 1);
			}
			S = xorBlocks(S, S2);
			HS = S2;
			prp.permute_block(&HS, 1);
			if (!block_cmp(&HS, &HS2, 1)) {
				cout <<"cheat!"<<endl;
			}
			int * ind = new int[length*bucket_size];
			int *location = new int[length*bucket_size];
			for(int i = 0; i < length*bucket_size; ++i) location[i] = i;
			PRG prg(&S);
			prg.random_data(ind, length*bucket_size*4);
			for(int i = length*bucket_size-1; i>=0; --i) {
				int index = ind[i]%(i+1);
				index = index>0? index:(-1*index);
				int tmp = location[i];
				location[i] = location[index];
				location[index] = tmp;
			}
			delete[] ind;

			bool *data = new bool[length*bucket_size];	
			bool *data2 = new bool[length*bucket_size];
			block * MAC2 = new block[length*3];
			block * KEY2 = new block[length*3];
			bool * r2 = new bool[length*3];
			vector<future<void>> res;
			for(int i = 0; i < THDS; ++i)
				res.push_back(pool->enqueue(combine_merge<IO>, this, length/THDS*i, length/THDS, i, data, data2, MAC2, KEY2, r2, location));
			for(int i = 0; i < THDS; ++i)
				res[i].get();
			memcpy(MAC, MAC2, sizeof(block)*3*length);
			memcpy(KEY, KEY2, sizeof(block)*3*length);
			memcpy(r, r2, sizeof(bool)*3*length);
			delete[] data;
			delete[] location;
			delete[] data2;
			delete[] MAC2;
			delete[] KEY2;
			delete[] r2;
		}
};
template<typename IO>
void combine_merge(Fpre<IO> * fpre, int start, int length, int I, bool * data, bool* data2, block * MAC2, block * KEY2, bool *r2, int * location) {
	fpre->io[I]->flush();
	int bucket_size = fpre->bucket_size;
	for(int i = start; i < start+length; ++i) {
		for(int j = 1; j < bucket_size; ++j) {
			data[i*bucket_size+j] = (fpre->r[location[i*bucket_size]*3+1]!=fpre->r[location[i*bucket_size+j]*3+1]);
		}
	}
	if(fpre->party == ALICE) {
		send_bool<IO>(fpre->io[I], data + start * bucket_size, length*bucket_size);
		recv_bool<IO>(fpre->io[I], data2 + start*bucket_size, length*bucket_size);
	} else {
		recv_bool<IO>(fpre->io[I], data2 + start*bucket_size, length*bucket_size);
		send_bool<IO>(fpre->io[I], data + start * bucket_size, length*bucket_size);
	}
	for(int i = start; i < start+length; ++i) {
		for(int j = 1; j < bucket_size; ++j) {
			data[i*bucket_size+j] = (data[i*bucket_size+j] != data2[i*bucket_size+j]);
		}
	}
	for(int i = start; i < start+length; ++i) {
		for(int j = 0; j < 3; ++j) {
			MAC2[i*3+j] = fpre->MAC[location[i*bucket_size]*3+j];
			KEY2[i*3+j] = fpre->KEY[location[i*bucket_size]*3+j];
			r2[i*3+j] = fpre->r[location[i*bucket_size]*3+j];
		}
		for(int j = 1; j < bucket_size; ++j) {
			MAC2[3*i] = xorBlocks(MAC2[3*i], fpre->MAC[location[i*bucket_size+j]*3]);
			KEY2[3*i] = xorBlocks(KEY2[3*i], fpre->KEY[location[i*bucket_size+j]*3]);
			r2[3*i] = (r2[3*i] != fpre->r[location[i*bucket_size+j]*3]);

			MAC2[i*3+2] = xorBlocks(MAC2[i*3+2], fpre->MAC[location[i*bucket_size+j]*3+2]);
			KEY2[i*3+2] = xorBlocks(KEY2[i*3+2], fpre->KEY[location[i*bucket_size+j]*3+2]);
			r2[i*3+2] = (r2[i*3+2] != fpre->r[location[i*bucket_size+j]*3+2]);

			if(data[i*bucket_size+j]) {
				KEY2[i*3+2] = xorBlocks(KEY2[i*3+2], fpre->KEY[location[i*bucket_size+j]*3]);
				MAC2[i*3+2] = xorBlocks(MAC2[i*3+2], fpre->MAC[location[i*bucket_size+j]*3]);
				r2[i*3+2] = (r2[i*3+2] != fpre->r[location[i*bucket_size+j]*3]);
			}
		}
	}
	fpre->io[I]->flush();
}
}
#endif// FPRE_H__
