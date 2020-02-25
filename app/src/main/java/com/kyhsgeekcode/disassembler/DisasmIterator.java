package com.kyhsgeekcode.disassembler;

public class DisasmIterator extends AssemblyProvider {
    //<<<<<<< HEAD
//<<<<<<< HEAD
    //public DisasmIterator(MainActivity binaryDisasmFragment,
    //						//NotificationManager mNotifyManager,
    //						//Notification.Builder mBuilder,
    //						DisasmListViewAdapter adapter,
    //						long total)
//=======
    //public DisasmIterator(MainActivity binaryDisasmFragment, NotificationManager mNotifyManager, Notification.Builder mBuilder, DisasmListViewAdapter adapter,  long total)
//>>>>>>> parent of 2644076... Update readme with assembly materials links
//=======
    public DisasmIterator(/* NotificationManager mNotifyManager, Notification.Builder mBuilder, */DisasmListViewAdapter adapter, long total)
//>>>>>>> parent of 2644076... Update readme with assembly materials links
    {
        super(adapter, total);
    }

    public native long getAll(int handle, byte[] bytes, long offset, long size, long virtaddr/*,ArrayList<ListViewItem> arr*/);

    public native long getSome(int handle, byte[] bytes, long offset, long size, long virtaddr, int count/*,ArrayList<ListViewItem> arr*/);

    public int showNoti(int progress) {
        //mBuilder.setProgress((int)total,progress, false);
        // Displays the progress bar for the first time.
        //mNotifyManager.notify(0, mBuilder.b uild());
        //binaryDisasmFragment.runOnUiThread(binaryDisasmFragment.runnableRequestLayout);
        if (Thread.interrupted()) {
            return -1;
        }
        return 0;
    }

    public native int CSoption(int handle, int type, int vslue);
}
