#include "test-e2e.h"
#include "translation.h"
#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>

using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
void test_ecdsa_e2e(EcdsaPartialSig_l psl, char *hashedmsg, uint32_t party, uint32_t digest[8]) {
    assert (party == 1 || party == 2);
    int port = 24689;
    NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	string file = circuit_file_location + "ecdsa.circuit.txt";
    cout << file << endl;
	CircuitFile cf(file.c_str());
    //
    // initialize some timing stuff?
	auto t1 = clock_start();
	C2PC<NetIO> twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

    // preprocessing?
	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

    // more preprocessing?
	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

    char one = '1';

    // create and fill in input vectors (to all zeros with memset)
    int in_length = party==BOB?cf.n2:cf.n1;
	bool *in = new bool[in_length];
	cout << "input size: MERCH " << cf.n1 << "\tCUST " << cf.n2<<endl;
	bool * out = new bool[cf.n3];
	memset(in, false, in_length);
	int pos = 0;
	if (party == ALICE) {
	    pos = translate_ecdsaPartialSig(psl, in, pos);
	    string hmsg = change_base(string(hashedmsg), 16, 10);
	    string tmp = dec_to_bin(hmsg);
        std::reverse(tmp.begin(), tmp.end());
        for(int i = pos; i < pos+tmp.length(); ++i)
            in[i] = (tmp[i-pos] == one);
        pos = pos + tmp.length();
        int32_to_bool(&in[pos], 4294967295, 32);
        pos = pos + 224;
        pos = pos + 32;

        string q2str = "57896044618658097711785492504343953926418782139537452191302581570759080747169";
        tmp = "";
        tmp = dec_to_bin(q2str);
        std::reverse(tmp.begin(), tmp.end());
        for(int i = 0; i < tmp.length(); ++i)
            in[i + pos] = (tmp[i] == one);
        pos = pos + 516;
        string qstr = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
        tmp = "";
        tmp = dec_to_bin(qstr);
        std::reverse(tmp.begin(), tmp.end());
        for(int i = 0; i < tmp.length(); ++i)
            in[i+pos] = (tmp[i] == one);
        pos = pos + 258;
        cout << "Position merch: " << pos << endl;

	}

    string res = "";
    for(int i = 0; i < in_length; ++i)
			res += (in[i]?"1":"0");
    cout << "in: " << res << endl;

	memset(out, false, cf.n3);

    // online protocol execution
	t1 = clock_start();
	twopc.online(in, out);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;

    // compare result to our hardcoded expected result
	if(party == BOB){
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "result: " << res << endl;
		for (int i = 0; i < 8; ++i) {
            int start = i*32;
            digest[i] = bool_to_int<uint32_t>(&out[start], 32);
        }
	}
	delete[] in;
	delete[] out;
}


