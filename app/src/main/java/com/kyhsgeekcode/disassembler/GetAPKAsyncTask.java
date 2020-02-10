package com.kyhsgeekcode.disassembler;

import android.content.DialogInterface;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.util.Log;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class GetAPKAsyncTask extends AsyncTaskDialog<Void, Void> {
    MainActivity activity;
    List<String> apklists;
    List<String> pathlists;

    private static final String TAG = "GetAPK";

    public GetAPKAsyncTask(MainActivity activity) {
        super(activity, "Searching APKs", "", 10);
        this.activity = activity;
    }

    @Override
    protected Void doInBackground(Void... voids) {
        apklists = new ArrayList<>();
        pathlists = new ArrayList<>();
        final PackageManager pm = context.getPackageManager();
        //get a list of installed apps.
        List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
        int numpkg = packages.size();
        dialog.setMax(numpkg * 2);
        dialog.setMessage("Sorting APKs...");
        publishProgress(1);
        Collections.sort(packages, new Comparator<ApplicationInfo>() {
            @Override
            public int compare(ApplicationInfo o1, ApplicationInfo o2) {
                String applabel1 = (String) pm.getApplicationLabel(o1);
                String applabel2 = (String) pm.getApplicationLabel(o2);
                return applabel1.compareTo(applabel2);
            }
        });
        publishProgress(numpkg);
        int i = 0;
        Drawable defaultD = context.getDrawable(android.R.drawable.gallery_thumb);
        for (ApplicationInfo packageInfo : packages) {
            //Log.d(TAG, "Installed package :" + packageInfo.packageName);
            //Log.d(TAG, "Apk file path:" + packageInfo.sourceDir);
            String applabel = (String) pm.getApplicationLabel(packageInfo);
            Drawable icon = defaultD;
            try {
                icon = pm.getApplicationIcon(packageInfo.packageName);
            } catch (PackageManager.NameNotFoundException e) {
                Log.e(TAG, "", e);
            }
            String label = applabel + "(" + packageInfo.packageName + ")";
            apklists.add(label);
            pathlists.add(packageInfo.sourceDir);
            i++;
            if (i % 10 == 0) {
                publishProgress(i + numpkg);
            }
        }
        return null;
    }

    @Override
    protected void onPostExecute(Void aVoid) {
        super.onPostExecute(aVoid);
        activity.showSelDialog(apklists, "Choose APK from installed", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String path = pathlists.get(which);
                activity.onChoosePath(path);
            }
        });
    }
}
