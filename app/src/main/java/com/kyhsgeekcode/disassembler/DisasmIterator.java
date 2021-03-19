package com.kyhsgeekcode.disassembler;

import android.os.Handler;
import android.os.Looper;

import java.util.List;

public class DisasmIterator extends AssemblyProvider {
    public DisasmIterator(DisasmListViewAdapter adapter) {
        super(adapter);
    }

    public native long getAll(int handle, byte[] bytes, long offset, long size, long virtaddr/*,ArrayList<ListViewItem> arr*/);

    public native long getSome(int handle, byte[] bytes, long offset, long size, long virtaddr, int count/*,ArrayList<ListViewItem> arr*/);

    public int showNoti(int progress) {
        //mBuilder.setProgress((int)total,progress, false);
        // Displays the progress bar for the first time.
        //mNotifyManager.notify(0, mBuilder.b uild());
        //binaryDisasmFragment.runOnUiThread(binaryDisasmFragment.runnableRequestLayout);
        if (Thread.interrupted()) {
            return -1;
        }
        return 0;
    }

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

    public native int CSoption(int handle, int type, int vslue);
}
