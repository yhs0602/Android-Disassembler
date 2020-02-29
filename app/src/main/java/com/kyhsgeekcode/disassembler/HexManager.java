package com.kyhsgeekcode.disassembler;

import android.widget.TextView;

public class HexManager {
    public final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    byte[] bytes;
    String sep = System.lineSeparator();

    public HexManager() {
        bytes = new byte[1];
    }

    public void Show(TextView tv, int startaddress) {
        //show n bytes from startaddress
        startaddress /= 16;
        startaddress *= 16;
        StringBuilder sb = new StringBuilder();
        for (int i = startaddress; i < startaddress + 12800; i++) {
            if (i >= bytes.length) {
                break;
            }
            int v = bytes[i] & 0xff;
            sb.append(hexArray[v >>> 4]);
            sb.append(hexArray[v & 0x0f]);
            if (i % 16 == 15) {
                sb.append(sep);
                sb.append("   ");
                //sb.append(i>>>4);
            } else {
                sb.append(" ");
            }
        }
        tv.setText(sb.toString().trim());
    }

    public void setBytes(byte[] b) {
        bytes = b;
    }
}
