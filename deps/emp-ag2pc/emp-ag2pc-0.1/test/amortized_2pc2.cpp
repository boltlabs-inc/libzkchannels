#include <emp-tool/emp-tool.h>
#include "amortized_2pc.h"
using namespace std;
using namespace emp;
double get_io_count(Fpre * fpre, NetIO * io) {
	double res = 0;
#ifdef COUNT_IO
	for(int i = 0; i < fpre->THDS; ++i) {
		res += fpre->io[i]->counter;
		res += fpre->io2[i]->counter;
	}
	res += io->counter;
#endif
	return res;
}

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
const static int runs = 128;
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	string file = "ands.txt";//circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
	file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
//	file = circuit_file_location+"/sha-256.txt";

	CircuitFile cf(file.c_str());

	auto t1 = clock_start();
	AmortizedC2PC<runs> twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)/runs<<endl;
	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)/runs<<endl;
	double c1 = get_io_count(twopc.fpre, io);
	cout <<c1<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<(time_from(t1))/runs<<endl;
double c2 = get_io_count(twopc.fpre, io);
cout <<c2 - c1<<endl;


	bool in[512], out[512];
	t1 = clock_start();
	for(int i = 0; i < runs; ++i) {
		twopc.online(in, out);
	}
	cout << "online:\t"<<party<<"\t"<<(time_from(t1))/runs<<endl;
double c3 = get_io_count(twopc.fpre, io);
cout <<c3 - c2<<endl;
	delete io;

	return 0;
}
