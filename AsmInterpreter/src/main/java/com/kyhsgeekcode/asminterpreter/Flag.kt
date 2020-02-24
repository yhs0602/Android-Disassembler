package com.kyhsgeekcode.asminterpreter

enum class Flag {
    Zero,
    Carry,
    Sign,   //Negative
    Overflow,   //V,O,W

    HalfCarry, // H, A, DC
    Parity,
    Interrupt,
    Supervisor,
}
