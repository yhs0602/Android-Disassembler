package com.kyhsgeekcode.disassembler

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi

/////////////////////////////////////End Show **** dialog///////////////////////////////////////////
///////////////////////////////////////Permission///////////////////////////////////////////////////
val TAG = "PermissionUtils"
fun requestAppPermissions(a: Activity) {
    if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
        (a as MainActivity).onRequestPermissionsResult(MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE,
                emptyArray(), intArrayOf(PackageManager.PERMISSION_GRANTED))
        return
    }

    if (hasReadPermissions(a) && hasWritePermissions(a) /*&&hasGetAccountPermissions(a)*/) {
        Log.i(TAG, "Has permissions")
        a.onRequestPermissionsResult(MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE,
                emptyArray(), intArrayOf(PackageManager.PERMISSION_GRANTED))
        return
    }
    showPermissionRationales(a, Runnable {
        a.requestPermissions(arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE //,Mani fest.permission.GET_ACCOUNTS
        ), MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE) // your request code
    })
}

@RequiresApi(Build.VERSION_CODES.M)
fun hasGetAccountPermissions(c: Context): Boolean {
    return c.checkSelfPermission(Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED
}

fun hasReadPermissions(c: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        c.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    } else {
        return true
    }
}

fun hasWritePermissions(c: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        c.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    } else {
        return true
    }
}

fun showPermissionRationales(a: Activity, run: Runnable?) {
    showAlertDialog(a, a.getString(R.string.permissions),
            a.getString(R.string.permissionMsg),
            DialogInterface.OnClickListener { p1, p2 ->
                run?.run()
                //requestAppPermissions(a);
            })
}
