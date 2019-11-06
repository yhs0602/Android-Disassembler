package com.kyhsgeekcode.disassembler.FileTabFactory;

import android.content.Context;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ListView;

import com.kyhsgeekcode.disassembler.AbstractFile;
import com.kyhsgeekcode.disassembler.ColorHelper;
import com.kyhsgeekcode.disassembler.DisasmClickListener;
import com.kyhsgeekcode.disassembler.DisasmListViewAdapter;
import com.kyhsgeekcode.disassembler.MainActivity;
import com.kyhsgeekcode.disassembler.R;
import com.kyhsgeekcode.disassembler.RawFile;
import com.kyhsgeekcode.disassembler.TabType;

import java.io.IOException;

public class NativeDisassemblyFactory extends FileTabContentFactory {
    private static final String TAG = "NativeDisasmFactory";
    public NativeDisassemblyFactory(Context context) {
        super(context);
    }

    @Override
    public View createTabContent(String tag) {
        LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View root = inflater.inflate(R.layout.disasmtab, null);
        ListView listview = root.findViewById(R.id.disasmTabListview);
        DisasmListViewAdapter adapter = null;
        try {
            final AbstractFile file = AbstractFile.createInstance(tag);
            if(file instanceof RawFile)
                throw new IOException("Raw file not supported now. Maybe wrong adapter called");
            adapter = new DisasmListViewAdapter(file, ColorHelper.getInstance(), (MainActivity) context);
        } catch (IOException e) {
            Log.e(TAG,"Error creating adapter",e);
            return root;
        }
        listview.setAdapter(adapter);
        listview.setOnItemClickListener(new DisasmClickListener((MainActivity) context));
        listview.setOnScrollListener(adapter);
        return root;
    }

    @Override
    public void setType(String absolutePath, TabType type) {
        super.setType(absolutePath, type);
    }
}
