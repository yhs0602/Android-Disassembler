package com.kyhsgeekcode.disassembler;

import java.util.List;

public abstract class AssemblyProvider {
    public AssemblyProvider(MainActivity activity, ListViewAdapter adapter, long total) {
        this.activity = activity;
        this.total = total;
        this.adapter = adapter;
    }

    public abstract long getAll(byte[] bytes, long offset, long size, long virtaddr);

    public abstract long getSome(byte[] bytes, long offset, long size, long virtaddr, int count);

    //Used by JNI
    public void AddItem(final ListViewItem lvi) {
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                long addr = lvi.disasmResult.address;
                List<Symbol> syms = activity.parsedFile.symbols;
                for (Symbol sym : syms) {
                    if (sym.st_value == addr) {
                        lvi.comments = sym.demangled;
                        break;
                    }
                }
                adapter.addItem(lvi);
                adapter.notifyDataSetChanged();
                return;
            }
        });
    }

    MainActivity activity;
    long total;
    ListViewAdapter adapter;
}
