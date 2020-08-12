#include <emp-tool/emp-tool.h>
#include "2pc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	string file = string(argv[3])+"_"+string(argv[4])+"_"+string(argv[5]) +"_"+string(argv[6]);
	file = "circuits/"+file;

	CircuitFile cf(file.c_str());
	auto t1 = clock_start();
	C2PC twopc(io, party, &cf);
	twopc.function_independent();
	twopc.function_dependent();
	int lenin = party == ALICE ? atoi(argv[3]): atoi(argv[4]);
	bool *in = new bool[lenin];
	bool * out = new bool[atoi(argv[5])];
	memset(in, false, lenin);
	twopc.online(in, out);
	cout << file <<"\t"<<time_from(t1)<<endl;
	delete io;
	return 0;
}
