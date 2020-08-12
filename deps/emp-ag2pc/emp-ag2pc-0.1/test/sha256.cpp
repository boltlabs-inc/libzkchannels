#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	test(party, io, circuit_file_location+"sha-256.txt", "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8");
	delete io;
	return 0;
}
