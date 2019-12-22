package com.kyhsgeekcode.disassembler.Utils;


import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.MediaStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class Util {
    public static byte[] getBytes(InputStream is) throws IOException {

        int len;
        int size = 1024;
        byte[] buf;

        if (is instanceof ByteArrayInputStream) {
            size = is.available();
            buf = new byte[size];
            len = is.read(buf, 0, size);
        } else {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            buf = new byte[size];
            while ((len = is.read(buf, 0, size)) != -1)
                bos.write(buf, 0, len);
            buf = bos.toByteArray();
        }
        is.close();
        return buf;
    }

    public static String getRealPathFromURI(Context context, Uri uri) {
        String filePath;
        filePath = uri.getPath();
        //경로에 /storage가 들어가면 real file path로 판단
        if (filePath.startsWith("/storage"))
            return filePath;
        String wholeID = DocumentsContract.getDocumentId(uri);
        //wholeID는 파일명이 abc.zip이라면 /document/B5D7-1CE9:abc.zip와 같습니다.
        // Split at colon, use second item in the array
        String id = wholeID.split(":")[0];
        //Log.e(TAG, "id = " + id);
        String[] column = {MediaStore.Files.FileColumns.DATA};
        //파일의 이름을 통해 where 조건식을 만듭니다.
        String sel = MediaStore.Files.FileColumns.DATA + " LIKE '%" + id + "%'";
        //External storage에 있는 파일의 DB를 접근하는 방법 입니다.
        Cursor cursor = context.getContentResolver().query(MediaStore.Files.getContentUri("external"), column, sel, null, null);
        //SQL문으로 표현하면 아래와 같이 되겠죠????
        //SELECT _dtat FROM files WHERE _data LIKE '%selected file name%'
        int columnIndex = cursor.getColumnIndex(column[0]);
        if (cursor.moveToFirst()) {
            filePath = cursor.getString(columnIndex);
        }
        cursor.close();
        return filePath;
    }

    //https://stackoverflow.com/a/6425744/8614565
    public static void deleteRecursive(File fileOrDirectory) {
        if (fileOrDirectory.isDirectory())
            for (File child : fileOrDirectory.listFiles())
                deleteRecursive(child);

        fileOrDirectory.delete();
    }
}
