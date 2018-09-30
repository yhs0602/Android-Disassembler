package com.kyhsgeekcode.disassembler;


import android.annotation.*;
import android.content.*;
import android.database.*;
import android.net.*;
import android.os.*;
import android.provider.*;
import android.util.*;
import java.io.*;

public class RealPathUtils {

	@SuppressLint("NewApi")
	public static String getRealPathFromURI_API19(Context context, Uri uri){
		String filePath = "";
		String wholeID = DocumentsContract.getDocumentId(uri);

		// Split at colon, use second item in the array
		String id = wholeID.split(":")[1];

		String[] column = { MediaStore.Images.Media.DATA };

		// where id is equal to
		String sel = MediaStore.Images.Media._ID + "=?";

		Cursor cursor = context.getContentResolver().query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
														   column, sel, new String[]{ id }, null);

		int columnIndex = cursor.getColumnIndex(column[0]);

		if (cursor.moveToFirst()) {
			filePath = cursor.getString(columnIndex);
		}
		cursor.close();
		return filePath;
	}


	@SuppressLint("NewApi")
	public static String getRealPathFromURI_API11to18(Context context, Uri contentUri) {
		String[] proj = { MediaStore.Images.Media.DATA };
		String result = null;

		CursorLoader cursorLoader = new CursorLoader(
            context,
            contentUri, proj, null, null, null);
		Cursor cursor = cursorLoader.loadInBackground();

		if(cursor != null){
			int column_index =
                cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
			cursor.moveToFirst();
			result = cursor.getString(column_index);
		}
		return result;
	}

	public static String getRealPathFromURI_BelowAPI11(Context context, Uri contentUri){
		String[] proj = { MediaStore.Images.Media.DATA };
		Cursor cursor = context.getContentResolver().query(contentUri, proj, null, null, null);
		int column_index
            = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATA);
		cursor.moveToFirst();
		return cursor.getString(column_index);
	}
	public static String getRealPathFromURI(Context context,Uri contentUri)
	{
		String path = null;
		if (Build.VERSION.SDK_INT < 11)
			path = RealPathUtils.getRealPathFromURI_BelowAPI11(context, contentUri);

		// SDK >= 11 && SDK < 19
		else if (Build.VERSION.SDK_INT < 19)
			path = RealPathUtils.getRealPathFromURI_API11to18(context, contentUri);

		// SDK > 19 (Android 4.4)
		else
			path = RealPathUtils.getRealPathFromURI_API19(context, contentUri);
		//Log.d(TAG, "File Path: " + path);
		// Get the file instance
		//File file = new File(path);
		return path;
	}
}
