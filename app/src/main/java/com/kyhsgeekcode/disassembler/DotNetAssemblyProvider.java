package com.kyhsgeekcode.disassembler;

import java.util.List;

public class DotNetAssemblyProvider extends  AssemblyProvider{
    public DotNetAssemblyProvider(MainActivity activity,ListViewAdapter adapter, long total)
    {
        super(activity,adapter,total);
    }
    @Override
    public long getAll(byte[] bytes, long offset, long size,long virtaddr)
    {
        return 0;
    }
    @Override
    public long getSome(byte[] bytes, long offset, long size,long virtaddr,int count)
    {
        return 0;
    }

}
