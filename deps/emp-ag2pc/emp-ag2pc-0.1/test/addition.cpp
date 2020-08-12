#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
    int party, port;
	parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==BOB ? nullptr:IP, port);
	io->set_nodelay();
	string file = circuit_file_location+"addition.circuit.txt";//circuit_file_location + name;
	cout << file << endl;
    CircuitFile cf(file.c_str());
    int in_length = party==BOB?cf.n2:cf.n1;
    bool *in = new bool[in_length];
    memset(in, false, in_length);
    cout << "input size: max " << cf.n1 << "\t" << cf.n2;
    if (party == BOB) {
        uint32_t in1 = 5;
        int32_to_bool(in, in1, 32);
        uint32_t in3 = 1;
        int32_to_bool(&in[32], in3, 32);
    } else {
        uint32_t in2 = 2;
        int32_to_bool(in, in2, 32);
    }
	test_with_in(party, io, in, cf, string("A000000040000000000000004000000000000000"));
	delete io;
	delete[] in;
	return 0;
}

//void test_circ(uint32_t in1, uint32_t in2, uint32_t in3, uint32_t in4) {
//    Integer test1 = Integer(32, in1, BOB);
//    Integer test2 = Integer(32, in2, BOB);
//    Integer test3 = Integer(32, in3, ALICE);
//
//    Integer test5 = test2 + test3;
//    Integer test6 = Integer(32, 0, PUBLIC);
//    test1.reveal<uint32_t>(BOB);
//    test2.reveal<uint32_t>(BOB);
//    test3.reveal<uint32_t>(BOB);
//    test5.reveal<uint32_t>(BOB);
//    test6.reveal<uint32_t>(BOB);
//}