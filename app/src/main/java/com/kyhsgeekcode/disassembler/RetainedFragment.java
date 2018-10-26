package com.kyhsgeekcode.disassembler;
import android.app.*;
import android.os.*;
import java.util.*;

public class RetainedFragment extends Fragment {

    // data object we want to retain
    private DisassemblyManager data;
	private byte[] filecontent;
	private ELFUtil elfUtil;
	private String path;

	public void setPath(String path)
	{
		this.path = path;
	}

	public String getPath()
	{
		return path;
	}
	
	public void setElfUtil(ELFUtil elfUtil)
	{
		this.elfUtil = elfUtil;
	}

	public ELFUtil getElfUtil()
	{
		return elfUtil;
	}
	
	public void setFilecontent(byte[] filecontent)
	{
		this.filecontent = filecontent;
	}

	public byte[] getFilecontent()
	{
		return filecontent;
	}
	
    // this method is only called once for this fragment
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // retain this fragment
        setRetainInstance(true);
    }

    public void setDisasmManager(DisassemblyManager data) {
        this.data = data;
    }

    public DisassemblyManager getDisasmManager() {
        return data;
    }
}
