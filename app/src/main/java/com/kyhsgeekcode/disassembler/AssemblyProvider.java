package com.kyhsgeekcode.disassembler;

import android.os.Handler;
import android.os.Looper;

import java.util.List;

public abstract class AssemblyProvider {
    DisasmListViewAdapter adapter;
    private long total;

    public AssemblyProvider(DisasmListViewAdapter adapter, /*Unused */long total) {
        this.total = total;
        this.adapter = adapter;
    }

    public abstract long getAll(int handle, byte[] bytes, long offset, long size, long virtaddr);

    public abstract long getSome(int handle, byte[] bytes, long offset, long size, long virtaddr, int count);

    //Used by JNI
    public void AddItem(final DisassemblyListItem lvi) {
        new Handler(Looper.getMainLooper()).post(() -> {
            long addr = lvi.disasmResult.address;
            AbstractFile theFile = adapter.getFile();
            List<Symbol> syms = theFile.getExportSymbols();
            for (Symbol sym : syms) {
                if (sym.st_value == addr) {
                    lvi.AddComment(sym.demangled);
                    break;
                }
            }

            if (lvi.disasmResult.isCall()) {
                if (theFile instanceof ElfFile) {
                    ElfFile theElfFile = (ElfFile) theFile;
                    long target = lvi.disasmResult.getJumpOffset();
                    int pltIndex = theElfFile.getPltIndexFromJumpAddress(target);
                    if (pltIndex > 0) {
                        ImportSymbol theSym = theFile.getImportSymbols().get(pltIndex);
                        lvi.AddComment(theSym.getDemangled() + "@plt");
                    }
                }
            }
            adapter.addItem(lvi);
            adapter.notifyDataSetChanged();
        });
    }
}
