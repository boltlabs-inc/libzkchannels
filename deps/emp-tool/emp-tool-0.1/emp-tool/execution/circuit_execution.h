#ifndef CIRCUIT_EXECUTION_H__
#define CIRCUIT_EXECUTION_H__
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/constants.h"
namespace emp {
class CircuitExecution { 
public:
#ifndef THREADING
	static CircuitExecution * circ_exec;
#else
	static __thread CircuitExecution * circ_exec;
#endif
	virtual block and_gate(const block& in1, const block& in2) = 0;
	virtual block xor_gate(const block&in1, const block&in2) = 0;
	virtual block not_gate(const block& in1) = 0;
	virtual block public_label(bool b) = 0;
	virtual ~CircuitExecution (){ }
};
enum RTCktOpt{on, off};
}
#endif