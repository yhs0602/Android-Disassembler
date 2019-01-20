package com.kyhsgeekcode.disassembler;

import android.app.*;
import android.content.*;
//import android.support.multidex.*;

public class EnableMultidex extends /*MultiDex*/Application
 {
    private static EnableMultidex enableMultiDex;
    public static Context context;

    public EnableMultidex(){
        enableMultiDex=this;
    }

    public static EnableMultidex getEnableMultiDexApp() {
        return enableMultiDex;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        context = getApplicationContext();

    }
}
