package com.kyhsgeekcode.disassembler.Utils;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import com.kyhsgeekcode.disassembler.R;

import java.util.List;

public class UIUtil {
    public static void ShowEditDialog(Activity a, String title, String message, final EditText edittext,
                                      String positive, DialogInterface.OnClickListener pos,
                                      String negative, DialogInterface.OnClickListener neg) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setMessage(message);
        builder.setView(edittext);
        builder.setPositiveButton(positive, pos);
        builder.setNegativeButton(negative, neg);
        builder.show();
    }

    //The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application
    public static void ShowSelDialog(Activity a, final List<String> ListItems, String title, DialogInterface.OnClickListener listener) {
        final CharSequence[] items = ListItems.toArray(new String[ListItems.size()]);
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setItems(items, listener);
        builder.show();
    }

    public static void ShowAlertDialog(Activity a, String title, String content, DialogInterface.OnClickListener listener) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setCancelable(false);
        builder.setMessage(content);
        builder.setPositiveButton(R.string.ok, listener);
        builder.show();
    }

    public static void ShowAlertDialog(Activity a, String title, String content) {
        ShowAlertDialog(a, title, content, null);
    }

    public static void ShowYesNoCancelDialog(Activity a, String title, String content,
                                             DialogInterface.OnClickListener ok,
                                             DialogInterface.OnClickListener no,
                                             DialogInterface.OnClickListener can) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setCancelable(false);
        builder.setMessage(content);
        builder.setPositiveButton(R.string.ok, ok).setNegativeButton("No", no);
        builder.setNeutralButton(R.string.cancel, can);
        builder.show();
    }

    public static void setClipBoard(Context context, String s) {
        ClipboardManager cb = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Android Disassembler", s);
        cb.setPrimaryClip(clip);
        //Toast.makeText(this,"Copied to clipboard:"+s,Toast.LENGTH_SHORT).show();
    }

    //https://stackoverflow.com/a/8127716/8614565
    public static void disableEnableControls(boolean enable, ViewGroup vg) {
        for (int i = 0; i < vg.getChildCount(); i++) {
            View child = vg.getChildAt(i);
            child.setEnabled(enable);
            if (child instanceof ViewGroup) {
                disableEnableControls(enable, (ViewGroup) child);
            }
        }
    }

    public static void showToast(Context context, String s) {
        Toast.makeText(context, s, Toast.LENGTH_SHORT).show();
    }

    public static void showToast(Context context, int resid) {
        Toast.makeText(context, resid, Toast.LENGTH_SHORT).show();
    }


}
