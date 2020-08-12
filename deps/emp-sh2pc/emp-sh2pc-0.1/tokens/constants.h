#pragma once
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;

typedef struct Constants Constants;
struct Constants {
    Integer ipad;
    Integer opad;

    Integer xeightfirstbyte;
    Integer xeightfourthbyte;

    Integer hmacinnerhashlength;
    Integer hmacouterhashlength;
    Integer hmackeycommitmentpreimagelength;
    Integer doubleshapreimagelength;
    Integer commitmentpreimagelength;
    Integer customerdelayerscriptpreimagelength;
    Integer customerdelayerscriptpreimagelengthshort;
    Integer customerdelayerscriptpreimagelengthveryshort;
    Integer escrowtransactionpreimagelength;
    Integer merchtransactionpreimagelength;
    Integer merchtransactionpreimagelengthshort;
    Integer merchtransactionpreimagelengthveryshort;
    Integer hashoutputspreimagelength;

    Integer xsevenf;
    Integer xsixthreedot;
    Integer xeighteight;
    Integer xtwentyone;
    Integer xsixsevenzero;
    Integer xbtwosevenfive;
    Integer xsixeightac;
    Integer xtwentytwodot;
    Integer xsixteen;
    Integer xzerozerofourteen;
    Integer threesevensixa;
    Integer xfourtyone;
    Integer xzerotwo;
    Integer xthreedot;
    Integer xcdot;
    Integer xninedot;
    Integer xfdot;
    Integer xfourteendot;
    Integer xsevendot;
    Integer xtwentytwoninedot;
    Integer xsevenzerosixdot;
    Integer xfoursevenfivedot;
    Integer xfivetwoae;
    Integer xzeroone;
    Integer xseventwosixdot;
    Integer xsevenonesixdot;
    Integer xsevenzerosixthreedot;
    Integer xfiftytwo;
    Integer xaedot;
    Integer xbtwosevendot;
    Integer xacsixeight;
    Integer xfourteenzerozero;

    Integer fullF;
    Integer fullFsixtyfour;
    Integer fullFthirtytwo;
    Integer xzerozeroff;
    Integer xff;
    Integer ffffffzerozero;
    Integer ffzerozero;

    Integer thirtytwo;
    Integer zero;
    Integer one;
    Integer two;
    Integer eighty;
    Integer maxint16;
};

typedef struct Q Q;
struct Q {
    Integer q;
    Integer q2;
};

Q distribute_Q(const int party);
Constants distribute_Constants(const int party);
Bit constants_not_equal(const Constants& lhs, const Constants& rhs);
Bit q_not_equal(const Q& lhs, const Q& rhs);
