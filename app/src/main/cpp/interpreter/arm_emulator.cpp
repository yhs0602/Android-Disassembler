//
// Created by 양현서 on 4/20/21.
//

#include "arm_emulator.h"

void ARMMachine::execute(char *insn) {
    void *bytes = insn;
    unsigned int instruction = *(unsigned int *) bytes;
    unsigned char cond = (instruction >> 28u) & 0xFFu;
    do {
        if (cond == 0 && (regs[16] & Z_MASK) == 0)
            break;
        if (cond == 1 && (regs[16] & Z_MASK) != 0)
            break;
        if (cond == 2 && (regs[16] & C_MASK) == 0)
            break;
        if (cond == 3 && (regs[16] & C_MASK) != 0)
            break;
        if (cond == 4 && (regs[16] & N_MASK) == 0)
            break;
        if (cond == 5 && (regs[16] & N_MASK) != 0)
            break;
        if (cond == 6 && (regs[16] & V_MASK) == 0)
            break;
        if (cond == 7 && (regs[16] & V_MASK) != 0)
            break;
        if (cond == 8 && (regs[16] & C_MASK) == 0 || (regs[16] & Z_MASK) != 0)
            break;
        if (cond == 9 && (regs[16] & C_MASK) != 0 && (regs[16] & Z_MASK) == 0)
            break;
        if (cond == 10 && ((regs[16] & N_MASK) >> N_SHIFT) != ((regs[16] & V_MASK) >> V_SHIFT))
            break;
        if (cond == 11 && ((regs[16] & N_MASK) >> N_SHIFT) == ((regs[16] & V_MASK) >> V_SHIFT))
            break;
        if (cond == 12 && (regs[16] & Z_MASK) != 0 ||
            ((regs[16] & N_MASK) >> N_SHIFT) != ((regs[16] & V_MASK) >> V_SHIFT))
            break;
        if (cond == 13 && (regs[16] & Z_MASK) == 0 &&
            ((regs[16] & N_MASK) >> N_SHIFT) == ((regs[16] & V_MASK) >> V_SHIFT))
            break;
//        if(cond == 14 && false)
//            break;
        unsigned int grp = (instruction >> 25) & 7u;
        unsigned int real_insn = instruction & 0x7FFF;
        if (real_insn >> 4 == 0x12FFF1) { // Branch and Exchange Rn
            unsigned char reg = real_insn & 0xF;
            regs[15] = regs[reg]; // jump FIXME : IP relative
            return;
        }

        if (grp == 5) { // branch
            unsigned char link = real_insn >> 24 & 0x1;
            if (link) {
                regs[14] = (regs[15] + 4) & 0xFFFFFFFE;
            }
            int offset = (real_insn & 0x7FF) << 2; // FIXME: Negative offset
            regs[15] = regs[15] + offset;
            return;
        }

        if (grp == 3 && (instruction & (1 << 4)) == 1) { // Undefined
            undefined = true;
            break;
        }

        if (grp == 7) { // coprocessor, interrupt
            if ((instruction & (1 << 24)) == 1) {
                swi = true;
                break;
            }
            // TODO: Coprocessor
            break;
        }
        if (grp == 6) { // Coprocessor data transfer

        }

        if (grp == 4) { // block data transfer
            bool post = (instruction & P_MASK) == 0;
            bool down = (instruction & U_MASK) == 0;
            bool loadPSROrForceUserMode = (instruction & S_MASK) != 0;
            bool writeback = (instruction & W_MASK) != 0;
            bool load = (instruction & L_MASK) != 0;
            unsigned char regn = instruction >> 16 & 0xF;
            // push / load from stack.
        }

        if (grp == 3 || grp == 2) { // single data transfer
            bool immoff = grp == 3;
            bool post = (instruction & P_MASK) == 0;
            bool down = (instruction & U_MASK) == 0;
            bool loadPSROrForceUserMode = (instruction & S_MASK) != 0;
            bool writeback = (instruction & W_MASK) != 0;
            bool load = (instruction & L_MASK) != 0;
            unsigned char regn = instruction >> 16 & 0xF;
            unsigned char regd = instruction >> 12 & 0xF;
            int base = regs[regn];

        }

        if (grp == 0 || grp == 1) { // Data processing / PSR Transfer with I = 1
            bool immopnd = grp == 1;
            unsigned char opcode = instruction >> 21 & 0xF;
            bool setCond = (instruction & (1 << 20)) == 1;
            unsigned char regn = instruction >> 16 & 0xF;
            unsigned char regd = instruction >> 12 & 0xF;
            if (immopnd) {
                unsigned char regm = instruction & 0xF;
                unsigned int shift = instruction >> 4 & 0xFF;
                unsigned char shiftType = shift >> 1 & 0x3;
                if ((shift & 0x1) == 0) {
                    unsigned char shiftAmount = shift >> 3 & 0x1F;
                } else {
                    unsigned char reg_s = shift  >> 4 & 0xF;

                }
            } else {
                unsigned char imm = instruction & 0xFF;
                unsigned char rotate = instruction >> 8 & 0xF;
            }
            // TODO: opcode..
        }


    } while (false);

}

