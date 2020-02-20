package com.kyhsgeekcode.disassembler;

import android.os.Handler;
import android.os.Looper;

import java.util.List;

public abstract class AssemblyProvider {
    public AssemblyProvider(DisasmListViewAdapter adapter, /*Unused */long total) {
        this.total = total;
        this.adapter = adapter;
    }

    public abstract long getAll(byte[] bytes, long offset, long size, long virtaddr);

    public abstract long getSome(byte[] bytes, long offset, long size, long virtaddr, int count);

    //Used by JNI
    public void AddItem(final DisassemblyListItem lvi) {
        new Handler(Looper.getMainLooper()).post(() -> {
            long addr = lvi.disasmResult.address;
            List<Symbol> syms = activity.parsedFile.getSymbols();
            for (Symbol sym : syms) {
                if (sym.st_value == addr) {
                    lvi.comments = sym.demangled;
                    break;
                }
            }
            adapter.addItem(lvi);
            adapter.notifyDataSetChanged();
            return;
        });
    }

    MainActivity activity;
    private long total;
    DisasmListViewAdapter adapter;
}
