#include <emp-tool/emp-tool.h>
#include "amortized_2pc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
static char out3[] = "92b404e556588ced6c1acd4ebf053f6809f73a93";//bafbc2c87c33322603f38e06c3e0f79c1f1b1475";
const static int runs = 4;
int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);

	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	string file = "ands.txt";//circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
	file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
	file = circuit_file_location+"/sha-1.txt";

	CircuitFile cf(file.c_str());

	auto t1 = clock_start();
	AmortizedC2PC<runs> twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;
	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;


	bool in[512], out[512];
	for(int i = 0; i < runs; ++i) {
		memset(in, false, 512);
		memset(out, false, 512);
		t1 = clock_start();
		twopc.online(in, out);
		cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;
		if(party == BOB){
			string res = "";
			for(int i = 0; i < 160; ++i)
				res += (out[i]?"1":"0");
			cout << (res == hex_to_binary(string(out3))? "GOOD!":"BAD!")<<endl;
		}
	}
	delete io;

	return 0;
}
