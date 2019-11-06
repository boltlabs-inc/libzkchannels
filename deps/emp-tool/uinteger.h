#ifndef UINTEGER_H__
#define UINTEGER_H__

#include "emp-tool/circuits/bit.h"
#include "emp-tool/circuits/number.h"
#include "emp-tool/circuits/comparable.h"
#include "emp-tool/circuits/swappable.h"
#include <vector>
#include <bitset>
#include <algorithm>
#include <math.h>
#include <execinfo.h>
using std::vector;
using std::min;
namespace emp {
class UInteger : public Swappable<UInteger>, public Comparable<UInteger> { public:
	int length = 0;
	Bit* bits = nullptr;

	UInteger(UInteger&& in) : length(in.length) {
		bits = in.bits;
		in.bits = nullptr;
	}
	UInteger(const UInteger& in): length(in.length) {
		bits = new Bit[length];
		memcpy(bits, in.bits, sizeof(Bit)*length);
	}
	UInteger& operator= (UInteger rhs){
		length = rhs.length;
		std::swap(bits, rhs.bits);
		return *this;
	}
	UInteger(int len, const void * b) : length(len) {
		bits = new Bit[len];
		memcpy(bits, b, sizeof(Bit)*len);
	}
	~UInteger() {
		if (bits!=nullptr) delete[] bits;
	}

	UInteger(int length, const string& str, int party = PUBLIC);
	UInteger(int length, long long input, int party = PUBLIC);
	UInteger() :length(0),bits(nullptr){ }

//Comparable
	Bit geq(const UInteger & rhs) const;
	Bit equal(const UInteger & rhs) const;

//Swappable
	UInteger select(const Bit & sel, const UInteger & rhs) const;
	UInteger operator^(const UInteger& rhs) const;

	int size() const;
	template<typename O>
	O reveal(int party=PUBLIC) const;

	UInteger abs() const;
	UInteger& resize(int length, bool signed_extend = true);
	UInteger modExp(UInteger p, UInteger q);
	UInteger leading_zeros() const;
	UInteger hamming_weight() const;

    // TODO: add shifts by regular Ints
	UInteger operator<<(int shamt)const;
	UInteger operator>>(int shamt)const;
	UInteger operator<<(const UInteger& shamt)const;
	UInteger operator>>(const UInteger& shamt)const;
    UInteger operator>>(const Integer& shamt)const;

	UInteger operator+(const UInteger& rhs)const;
	UInteger operator-(const UInteger& rhs)const;
	UInteger operator-()const;
	UInteger operator*(const UInteger& rhs)const;
	UInteger operator/(const UInteger& rhs)const;
	UInteger operator%(const UInteger& rhs)const;
	UInteger operator&(const UInteger& rhs)const;
	UInteger operator|(const UInteger& rhs)const;
    UInteger operator~() const; // complement

	Bit& operator[](int index);
	const Bit & operator[](int index) const;
	
//batcher
	template<typename... Args>
	static size_t bool_size(size_t size, Args... args) {
		return size;
	}
	static void bool_data(bool* data, size_t len, long long num) {
		bool_data(data, len, std::to_string(num));
	}
	static void bool_data(bool* data, size_t len, string str) {
		string bin = change_base(str,10,2);
		std::reverse(bin.begin(), bin.end());
//		cout << "convert " <<str<<" "<<bin<<endl;
		int l = (bin.size() > (size_t)len ? len : bin.size());
		for(int i = 0; i < l; ++i)
			data[i] = (bin[i] == '1');
		for (size_t i = l; i < len; ++i)
			data[i] = 0; //data[l-1];
	}
};

void uint_init(Bit * bits, const bool* b, int length, int party = PUBLIC);
#include "emp-tool/circuits/uinteger.hpp"
}
#endif// UINTEGER_H__
