#include <iostream>
#include <fstream>
using namespace std;

void generate_circuit(int n1, int n2, int n3, int C) {
	ofstream fout("circuits/"+to_string(n1)+"_"+to_string(n2)+"_"+to_string(n3)+"_"+to_string(C));
	fout<<C<<" "<<max(n1+n2+C,n1+n2+n3)<<" "<<endl;
	fout << n1<<" "<<n2<<" "<<n3<<endl; 
	for(int i = 0; i < C; ++i)
		fout<<"2 1 0"<<" "<<n1<<" "<<n1+n2+i<<" AND\n";
	for (int i = C+1; i <= n3; ++i)
		fout<<"2 1 0"<<" "<<n1<<" "<<n1+n2+i<<" XOR\n";
	fout.close();
}
int main() {
	generate_circuit(128,128,128, 1<<26);
	return 0;
	for(int n1 = 8; n1 < 25; ++n1)
		generate_circuit(1<<n1,128,128, 1024);

	for(int n2 = 8; n2 < 25; ++n2)
		generate_circuit(128, 1<<n2,128, 1024);

	for(int n3 = 8; n3 < 25; ++n3)
		generate_circuit(128, 128, 1<<n3, 1024);

	for(int C = 8; C < 25; ++C)
		generate_circuit(128, 128, 128, 1<<C);
}