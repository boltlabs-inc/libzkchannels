Compile contract directly from SmartPy 
======================================

Relies on SmartPy beta release (12/21/2020) - https://smartpy.io/releases/20201221-47a09702e111f9b44259b2ffb91b001c89cc7317

1. Install SmartPy:

	sh <(curl -s https://smartpy.io/releases/20201221-47a09702e111f9b44259b2ffb91b001c89cc7317/cli/install.sh)

2. Compile contracts:

	mkdir out/
	~/smartpy-cli/SmartPy.sh test zkchannel_smartpy_script.py out/

3. Copy the generated contract in `out/basic_interpreted` dir as follows:

	cp out/basic_interpreted/testContractCode.0.7.tz ./zkchannel_pssig_v2.tz
