package com.kyhsgeekcode.disassembler;

import android.os.Handler;
import android.os.Looper;

import java.util.List;

public abstract class AssemblyProvider {
    public abstract long getAll(int handle, byte[] bytes, long offset, long size, long virtaddr);

    public abstract long getSome(int handle, byte[] bytes, long offset, long size, long virtaddr, int count);
}
