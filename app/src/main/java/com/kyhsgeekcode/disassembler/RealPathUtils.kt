package com.kyhsgeekcode.disassembler

import android.annotation.SuppressLint
import android.content.CursorLoader
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.MediaStore
import splitties.init.appCtx

object RealPathUtils {
    @SuppressLint("NewApi")
    fun getRealPathFromURI_API19(uri: Uri?): String {
        var filePath = ""
        val wholeID = DocumentsContract.getDocumentId(uri)
        // Split at colon, use second item in the array
        val id = wholeID.split(":").toTypedArray()[1]
        val column = arrayOf(MediaStore.Images.Media.DATA)
        // where id is equal to
        val sel = MediaStore.Images.Media._ID + "=?"
        val cursor = appCtx.contentResolver.query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                column, sel, arrayOf(id), null)
        val columnIndex = cursor!!.getColumnIndex(column[0])
        if (cursor.moveToFirst()) {
            filePath = cursor.getString(columnIndex)
        }
        cursor.close()
        return filePath
    }

    @SuppressLint("NewApi")
    fun getRealPathFromURI_API11to18(contentUri: Uri?): String? {
        val proj = arrayOf(MediaStore.Images.Media.DATA)
        var result: String? = null
        val cursorLoader = CursorLoader(
                appCtx,
                contentUri, proj, null, null, null)
        val cursor = cursorLoader.loadInBackground()
        if (cursor != null) {
            val column_index = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA)
            cursor.moveToFirst()
            result = cursor.getString(column_index)
        }
        return result
    }

    fun getRealPathFromURI_BelowAPI11(contentUri: Uri?): String {
        val proj = arrayOf(MediaStore.Images.Media.DATA)
        val cursor = appCtx.contentResolver.query(contentUri!!, proj, null, null, null)
        val column_index = cursor!!.getColumnIndexOrThrow(MediaStore.Images.Media.DATA)
        cursor.moveToFirst()
        return cursor.getString(column_index)
    }

    fun getRealPathFromURI(contentUri: Uri?): String? {
        var path: String?
        path = if (Build.VERSION.SDK_INT < 11)
            getRealPathFromURI_BelowAPI11(contentUri)
        else if (Build.VERSION.SDK_INT < 19)
            getRealPathFromURI_API11to18(contentUri)
        else
            getRealPathFromURI_API19(contentUri)
        // Log.d(TAG, "File Path: " + path);
// Get the file instance
// File file = new File(path);
        return path
    }
}
