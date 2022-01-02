//
// Created by 양현서 on 4/20/21.
//

class ARMMachine {
    int regs[17];
    bool undefined;
    bool swi;

    void execute(char *insn);
};

const int N_SHIFT = 31;
const int V_SHIFT = 28;
const int N_MASK = 1 << N_SHIFT;
const int Z_MASK = 1 << 30;
const int C_MASK = 1 << 29;
const int V_MASK = 1 << V_SHIFT;

const int P_MASK = 1 << 24;
const int U_MASK = 1 << 23;
const int S_MASK = 1 << 22;
const int W_MASK = 1 << 21;
const int L_MASK = 1 << 20;
