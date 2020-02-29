package com.kyhsgeekcode.disassembler;

import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.view.Window;

public abstract class AsyncTaskDialog<Param, Result> extends AsyncTask<Param, Integer, Result> {
    ProgressDialog dialog;
    Context context;
    String title;
    String message;
    int max;
    public AsyncTaskDialog(Context context, String title, String message, int max) {
        this.context = context;
        this.title = title;
        this.message = message;
        this.max = max;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        // create dialog
        dialog = new ProgressDialog(context);
        dialog.setTitle(title);
        dialog.setMessage(message);
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        dialog.setProgress(0);
        dialog.setMax(max);
        dialog.setCancelable(false);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.show();
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        dialog.setProgress(values[0]);
    }

    @Override
    protected void onPostExecute(Result result) {
        super.onPostExecute(result);
        dialog.dismiss();
    }
}
