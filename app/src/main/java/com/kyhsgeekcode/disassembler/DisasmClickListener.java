package com.kyhsgeekcode.disassembler;

import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;

import java.util.ArrayList;
import java.util.List;

import static com.kyhsgeekcode.UtilKt.setClipBoard;
import static com.kyhsgeekcode.disassembler.UIUtilsKt.showEditDialog;
import static com.kyhsgeekcode.disassembler.UIUtilsKt.showSelDialog;

public class DisasmClickListener implements View.OnClickListener {
    BinaryDisasmFragment binaryDisasmFragment;
    private String TAG = "Disassembler";
    private int position;
    private DisasmListViewAdapter adapter;

    public DisasmClickListener(BinaryDisasmFragment fragment, DisasmListViewAdapter adapter,  int position) {
        this.binaryDisasmFragment = fragment;
        this.position = position;
        this.adapter = adapter;
    }

    @Override
    public void onClick(View view) {
        final DisassemblyListItem lvi = (DisassemblyListItem) adapter.getItem(position);
        final DisasmResult dar = lvi.disasmResult;
        menus = new ArrayList<>();
        menus.add(EDIT_COMMENT);
        menus.add(COPY);
        //menus.add(PATCH);
        if (dar.isBranch() || dar.isCall()) {
            menus.add(JUMP);
        }
        if (!menus.isEmpty()) {
            showSelDialog(binaryDisasmFragment.getActivity(), menus, lvi.toSimpleString() + " at " + lvi.address, (p1, p21) -> {
                String item = menus.get(p21);
                if (EDIT_COMMENT.equals(item)) {
                    final EditText et = new EditText(binaryDisasmFragment.getActivity());
                    et.setText(lvi.getComments());
                    showEditDialog(binaryDisasmFragment.getActivity(), EDIT_COMMENT, EDIT_COMMENT, et
                            , "OK", (p11, p211) -> {
                                String cmt = et.getText().toString();
                                lvi.setComments(cmt);
                            }, "Cancel", null);
                    //context,title msg et, y yc n nc
                } else if (COPY.equals(item)) {
                    //List<String> its=new ArrayList<>();
                    setClipBoard(lvi.toCodeString(binaryDisasmFragment.getColumns()));//toString());
                    UIUtilsKt.showToast(binaryDisasmFragment.getActivity(), R.string.copied);
                } else if (JUMP.equals(item)) {
                    long target = dar.address + dar.jumpOffset;//NOT an offset?? FIXME
                    Log.d(TAG, "jump" + Long.toHexString(dar.address) + "," + Long.toHexString(dar.jumpOffset) + "," + Long.toHexString(target));
                    binaryDisasmFragment.jumpto(target);
                }
            });
        }
    }

    List<String> menus = new ArrayList<>();
    final String EDIT_COMMENT = "Edit comment";
    final String COPY = "Copy to clipboard";
    final String PATCH = "Patch assembly";
    final String JUMP = "Follow jump";
}
