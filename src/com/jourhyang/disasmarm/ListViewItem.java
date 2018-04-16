package com.jourhyang.disasmarm;

public class ListViewItem
{
	String address,bytes,label,instruction,operands,comments,condition;
	DisasmResult disasmResult;

	public ListViewItem(String address, String bytes, String label, String instruction, String operands, String comments, String condition)
	{
		this.address = address;
		this.bytes = bytes;
		this.label = label;
		this.instruction = instruction;
		this.operands = operands;
		this.comments = comments;
		this.condition = condition;
		//this.disasmResult = disasmResult;
	}

	public ListViewItem(DisasmResult disasmResult)
	{
		this.disasmResult = disasmResult;
		this.address=Long.toHexString(disasmResult.address);
		byte[] bytestmp=new byte[disasmResult.size];
		for(int i=0;i<disasmResult.size;++i)
		{
			bytestmp[i]=disasmResult.bytes[i];
		}
		this.bytes=MainActivity.bytesToHex(bytestmp);
		this.comments="";
		this.condition="";
		this.instruction=disasmResult.mnemonic;
		this.label=Integer.toString( disasmResult.size);
		this.operands=disasmResult.op_str;
	}
	public ListViewItem()
	{
		
	}

	public void setAddress(String address)
	{
		this.address = address;
	}

	public String getAddress()
	{
		return address;
	}

	public void setBytes(String bytes)
	{
		this.bytes = bytes;
	}

	public String getBytes()
	{
		return bytes;
	}

	public void setLabel(String label)
	{
		this.label = label;
	}

	public String getLabel()
	{
		return label;
	}

	public void setInstruction(String instruction)
	{
		this.instruction = instruction;
	}

	public String getInstruction()
	{
		return instruction;
	}

	public void setOperands(String operands)
	{
		this.operands = operands;
	}

	public String getOperands()
	{
		return operands;
	}

	public void setComments(String comments)
	{
		this.comments = comments;
	}

	public String getComments()
	{
		return comments;
	}

	public void setCondition(String condition)
	{
		this.condition = condition;
	}

	public String getCondition()
	{
		return condition;
	}
}
