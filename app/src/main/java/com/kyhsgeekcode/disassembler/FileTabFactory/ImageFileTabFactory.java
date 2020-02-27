package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.view.View;
import android.widget.Toast;

import com.github.chrisbanes.photoview.PhotoView;
import com.kyhsgeekcode.disassembler.MainActivity;
import com.kyhsgeekcode.disassembler.TabType;

import java.io.File;

public class ImageFileTabFactory extends FileTabContentFactory {
    public ImageFileTabFactory(Context context) {
        super(context);
    }

    @Override
    public View createTabContent(String tag) {
        Bitmap bitmap = BitmapFactory.decodeFile(tag);
        PhotoView pv = new PhotoView(context);
        if (bitmap == null) {
            Toast.makeText(context, "Failed to decode the file as an Image. Opening as Text", Toast.LENGTH_SHORT).show();
            ((MainActivity) context).openNewTab(new File(tag), TabType.TEXT);
            return pv;
        }
        pv.setImageDrawable(new BitmapDrawable(context.getResources(), bitmap));
        return pv;
    }
}
