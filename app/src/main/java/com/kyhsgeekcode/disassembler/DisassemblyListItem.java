package com.kyhsgeekcode.disassembler;

import java.io.Serializable;

import static com.kyhsgeekcode.disassembler.UtilsKt.bytesToHex;

public class DisassemblyListItem implements Serializable {
    String address, bytes, label, instruction, operands, comments, condition;
    DisasmResult disasmResult;

    //Capstone.CsInsn insn;
    public DisassemblyListItem(String address, String bytes, String label, String instruction, String operands, String comments, String condition) {
        this.address = address;
        this.bytes = bytes;
        this.label = label;
        this.instruction = instruction;
        this.operands = operands;
        this.comments = comments;
        this.condition = condition;
        //this.disasmResult = disasmResult;
    }

    public DisassemblyListItem(DisasmResult disasmResult) {
        this.disasmResult = disasmResult;
        this.address = Long.toHexString(disasmResult.address);
        byte[] bytestmp = new byte[disasmResult.size];
        //System.arraycopy();
        for (int i = 0; i < disasmResult.size; ++i) {
            bytestmp[i] = disasmResult.bytes[i];
        }
        this.bytes = bytesToHex(bytestmp);
        this.comments = "";
        this.condition = "";
        this.instruction = disasmResult.mnemonic;
        this.label = Integer.toString(disasmResult.size);
        this.operands = disasmResult.op_str;
    }

    /*public ListViewItem(Capstone.CsInsn insn)
     {
     this.insn=insn;
     this.address=Long.toHexString(insn.address);
     this.bytes=MainActivity.bytesToHex(insn.bytes());
     this.comments="";
     Arm.OpInfo info=(Arm.OpInfo) insn.operands;
     int cc=info.cc;
     this.condition=Arm_const.getCCName(cc);
     this.instruction=insn.mnemonic;
     this.label="";
     this.operands=insn.opStr;
     }
     */
    public DisassemblyListItem() {

    }

    public String toSimpleString() {
        StringBuilder builder = new StringBuilder(instruction);
        builder.append(" ");
        builder.append(operands);

        return builder.toString();
    }

    public String toCodeString(ColumnSetting cs) {

        StringBuilder sb = new StringBuilder();
        if (cs.showAddress) {
            sb.append("L_" + address);
            //sb.append(":");
        }
        if (cs.showLabel) {
            sb.append(label);
            //sb.append(":");
        }
        if (cs.showAddress || cs.showLabel)
            sb.append(":\t");
        if (cs.showBytes) {
            //sb.append("\t");
            sb.append(bytes);
        }
        if (cs.showInstruction) {
            sb.append(instruction);
        }
        if (cs.showOperands) {
            sb.append(" ");
            sb.append(operands);
        }
        if (cs.showComments) {
            sb.append("\t;");
            sb.append(comments);
        }
        //sb.append(System.lineSeparator());
        return sb.toString().trim();
    }

    public boolean isBranch() {
        return disasmResult.isBranch();
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getAddress() {
        return address;
    }

    public void setBytes(String bytes) {
        this.bytes = bytes;
    }

    public String getBytes() {
        return bytes;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public void setInstruction(String instruction) {
        this.instruction = instruction;
    }

    public String getInstruction() {
        return instruction;
    }

    public void setOperands(String operands) {
        this.operands = operands;
    }

    public String getOperands() {
        return operands;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public String getComments() {
        return comments;
    }

    public void setCondition(String condition) {
        this.condition = condition;
    }

    public String getCondition() {
        return condition;
    }

    public void AddComment(String comment) {
        this.comments += comment;
    }

    @Override
    public String toString() {
        // TODO: Implement this method
        if (disasmResult == null) {
            return "null!!!";
        }
        return disasmResult.toString();
		/*	StringBuilder sb=new StringBuilder();
		 sb.append(address);
		 sb.append(bytes);
		 sb.append(label);
		 sb.append(instruction);
		 sb.append(
		 return sb.toString();*/
    }

}
