if [ "$(uname)" == "Darwin" ]; then
	brew update
	brew list openssl || brew install openssl
	brew list xctool || brew install xctool
	brew list pkg-config || brew install pkg-config
	brew list cmake || brew install cmake
	brew list gmp || brew install gmp
	brew list boost || brew install boost
else
	CC=`lsb_release -rs | cut -c 1-2`
	VER=`expr $CC + 0`
	if [[ $VER -gt 15 ]]; then
		sudo apt-get install -y software-properties-common
		sudo apt-get update
		sudo apt-get install -y cmake git build-essential libssl-dev libgmp-dev python 
		sudo apt-get install -y libboost-dev
		sudo apt-get install -y libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}-dev
	else
		sudo apt-get install -y software-properties-common
		sudo add-apt-repository -y ppa:george-edison55/cmake-3.x
		sudo add-apt-repository -y ppa:kojoley/boost
		sudo apt-get update
		sudo apt-get install -y cmake git build-essential libssl-dev libgmp-dev python 
		sudo apt-get install -y libboost1.58-dev
		sudo apt-get install -y libboost-{chrono,log,program-options,date-time,thread,system,filesystem,regex,test}1.58-dev
	fi
fi
