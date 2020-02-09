package com.kyhsgeekcode.disassembler;

import android.content.DialogInterface;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;

import java.util.ArrayList;
import java.util.List;

import static com.kyhsgeekcode.disassembler.UIUtilsKt.ShowEditDialog;
import static com.kyhsgeekcode.disassembler.UIUtilsKt.ShowSelDialog;

public class DisasmClickListener implements AdapterView.OnItemClickListener {
    MainActivity activity;
    private String TAG = "Disassembler";

    public DisasmClickListener(MainActivity activity) {
        this.activity = activity;
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View p2, int position, long id) {
        final ListViewItem lvi = (ListViewItem) parent.getItemAtPosition(position);
        final DisasmResult dar = lvi.disasmResult;
        menus = new ArrayList<>();
        menus.add(EDIT_COMMENT);
        menus.add(COPY);
        //menus.add(PATCH);
        if (dar.isBranch() || dar.isCall()) {
            menus.add(JUMP);
        }
        if (!menus.isEmpty()) {
            ShowSelDialog(activity, menus, lvi.toSimpleString() + " at " + lvi.address, new DialogInterface.OnClickListener() {


                @Override
                public void onClick(DialogInterface p1, int p2) {
                    String item = menus.get(p2);
                    if (EDIT_COMMENT.equals(item)) {
                        final EditText et = new EditText(activity);
                        et.setText(lvi.getComments());
                        ShowEditDialog(activity, EDIT_COMMENT, EDIT_COMMENT, et
                                , "OK", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface p1, int p2) {
                                        String cmt = et.getText().toString();
                                        lvi.setComments(cmt);
                                        return;
                                    }
                                }, "Cancel", null);
                        //context,title msg et, y yc n nc
                    } else if (COPY.equals(item)) {
                        //List<String> its=new ArrayList<>();
                        activity.setClipBoard(lvi.toCodeString(activity.getColumns()));//toString());
                        activity.showToast(R.string.copied);
                    } else if (JUMP.equals(item)) {
                        long target = dar.address + dar.jumpOffset;//NOT an offset?? FIXME
                        Log.d(TAG, "jump" + Long.toHexString(dar.address) + "," + Long.toHexString(dar.jumpOffset) + "," + Long.toHexString(target));
                        activity.jumpto(target);
                    }
                    return;
                }
            });
        }
        return;
    }

    List<String> menus = new ArrayList<>();
    final String EDIT_COMMENT = "Edit comment";
    final String COPY = "Copy to clipboard";
    final String PATCH = "Patch assembly";
    final String JUMP = "Follow jump";
}
