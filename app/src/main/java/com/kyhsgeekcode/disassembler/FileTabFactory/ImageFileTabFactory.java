package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.view.View;

import com.github.chrisbanes.photoview.PhotoView;

public class ImageFileTabFactory extends FileTabContentFactory {
    public ImageFileTabFactory(Context context) {
        super(context);
    }

    @Override
    public View createTabContent(String tag) {
        Bitmap bitmap = BitmapFactory.decodeFile(tag);
        PhotoView pv = new PhotoView(context);
        pv.setImageDrawable(new BitmapDrawable(context.getResources(), bitmap));
        return pv;
    }
}
