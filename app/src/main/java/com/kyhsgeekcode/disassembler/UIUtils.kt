package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.Context
import android.content.DialogInterface
import android.content.res.Resources
import android.util.Log
import android.view.ViewGroup
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.kyhsgeekcode.sendErrorReport

fun getScreenHeight(): Int {
    return Resources.getSystem().displayMetrics.heightPixels
}

fun showYesNoCancelDialog(
    a: Activity,
    title: String?,
    content: String?,
    ok: DialogInterface.OnClickListener?,
    no: DialogInterface.OnClickListener?,
    can: DialogInterface.OnClickListener?
) {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setCancelable(false)
    builder.setMessage(content)
    builder.setPositiveButton(R.string.ok, ok).setNegativeButton("No", no)
    builder.setNeutralButton(R.string.cancel, can)
    builder.show()
}

// /////////////////////////////////Show***Dialog/////////////////////////////////////
// The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application
fun showEditDialog(
    a: Activity,
    title: String?,
    message: String?,
    edittext: EditText?,
    positive: String?,
    pos: DialogInterface.OnClickListener?,
    negative: String?,
    neg: DialogInterface.OnClickListener?
): AlertDialog {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setMessage(message)
    builder.setView(edittext)
    builder.setPositiveButton(positive, pos)
    builder.setNegativeButton(negative, neg)
    return builder.show()
}

// The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application
fun showSelDialog(a: Activity, ListItems: List<String>, title: String?, listener: DialogInterface.OnClickListener?) {
    val items: Array<String> = ListItems.toTypedArray()
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setItems(items, listener)
    builder.show()
}

fun showAlertDialog(a: Activity, title: String?, content: String?, listener: DialogInterface.OnClickListener?) {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setCancelable(false)
    builder.setMessage(content)
    builder.setPositiveButton(R.string.ok, listener)
    builder.show()
}

fun showAlertDialog(a: Activity, title: String?, content: String?) {
    showAlertDialog(a, title, content, null)
}

// https://stackoverflow.com/a/8127716/8614565
fun disableEnableControls(enable: Boolean, vg: ViewGroup?) {
    for (i in 0 until vg!!.childCount) {
        val child = vg.getChildAt(i)
        child.isEnabled = enable
        if (child is ViewGroup) {
            disableEnableControls(enable, child)
        }
    }
}

fun showYesNoDialog(
    a: Activity,
    title: String?,
    content: String?,
    pos: DialogInterface.OnClickListener?,
    neg: DialogInterface.OnClickListener?
) {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setCancelable(false)
    builder.setMessage(content)
    builder.setPositiveButton(android.R.string.ok, pos).setNegativeButton(android.R.string.no, neg)
    builder.show()
}

fun showErrorDialog(a: Activity, title: Int, err: Throwable, sendError: Boolean) {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setCancelable(false)
    builder.setMessage(Log.getStackTraceString(err))
    builder.setPositiveButton(R.string.ok, null)
    if (sendError) {
        builder.setNegativeButton("Send error report") { p1, p2 -> sendErrorReport(err) }
    }
    builder.show()
}

fun showErrorDialog(a: Activity, title: String, err: Throwable, sendError: Boolean) {
    val builder = AlertDialog.Builder(a)
    builder.setTitle(title)
    builder.setCancelable(false)
    builder.setMessage(Log.getStackTraceString(err))
    builder.setPositiveButton(R.string.ok, null)
    if (sendError) {
        builder.setNegativeButton("Send error report") { p1, p2 -> sendErrorReport(err) }
    }
    builder.show()
}

fun showToast(context: Context, id: Int) {
    Toast.makeText(context, id, Toast.LENGTH_SHORT).show()
}

fun showToast(context: Context, str: String) {
    Toast.makeText(context, str, Toast.LENGTH_SHORT).show()
}
