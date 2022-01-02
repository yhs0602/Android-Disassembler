// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
package capstone

class Arm {
    class MemType /* extends Structure*/ {
        var base = 0
        var index = 0
        var scale = 0
        var disp = 0
    }

    class OpValue /* extends Union */ {
        var reg = 0
        var imm = 0
        var fp = 0.0
        var mem: MemType? = null
        var setend = 0 /*
    @Override
    public List getFieldOrder() {
      return Arrays.asList("reg", "imm", "fp", "mem", "setend");
    } */
    }

    class OpShift /* extends Structure*/ {
        var type = 0
        var value = 0 /*
    @Override
    public List getFieldOrder() {
      return Arrays.asList("type","value");
    }*/
    }

    class Operand /* extends Structure*/ {
        var vector_index = 0
        var shift: OpShift? = null
        var type = 0
        var value: OpValue? = null
        var subtracted = false /*
    public void read() {
      readField("vector_index");
      readField("type");
      if (type == ARM_OP_MEM)
        value.setType(MemType.class);
      if (type == ARM_OP_FP)
        value.setType(Double.TYPE);
      if (type == ARM_OP_PIMM || type == ARM_OP_IMM || type == ARM_OP_CIMM)
        value.setType(Integer.TYPE);
      if (type == ARM_OP_REG)
        value.setType(Integer.TYPE);
      if (type == ARM_OP_INVALID)
        return;
      readField("value");
      readField("shift");
      readField("subtracted");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("vector_index", "shift", "type", "value", "subtracted");
    }*/
    }

    class UnionOpInfo : Capstone.UnionOpInfo() {
        var usermode = false
        var vector_size = 0
        var vector_data = 0
        var cps_mode = 0
        var cps_flag = 0
        var cc = 0
        var update_flags: Byte = 0
        var writeback: Byte = 0
        var mem_barrier: Byte = 0
        var op_count: Byte = 0
        var op: Array<Operand?>

        init {
            op = arrayOfNulls(36)
        } /*
    public void read() {
      readField("usermode");
      readField("vector_size");
      readField("vector_data");
      readField("cps_mode");
      readField("cps_flag");
      readField("cc");
      readField("update_flags");
      readField("writeback");
      readField("mem_barrier");
      readField("op_count");
      op = new Operand[op_count];
      if (op_count != 0)
        readField("op");
    }

    @Override
    public List getFieldOrder() {
      return Arrays.asList("usermode", "vector_size", "vector_data",
          "cps_mode", "cps_flag", "cc", "update_flags", "writeback", "mem_barrier", "op_count", "op");
    }*/
    }

    class OpInfo(op_info: UnionOpInfo) : Capstone.OpInfo() {
        var usermode: Boolean
        var vectorSize: Int
        var vectorData: Int
        var cpsMode: Int
        var cpsFlag: Int
        var cc: Int
        var updateFlags: Boolean
        var writeback: Boolean
        var memBarrier: Int
        var op: Array<Operand?>? = null

        init {
            usermode = op_info.usermode
            vectorSize = op_info.vector_size
            vectorData = op_info.vector_data
            cpsMode = op_info.cps_mode
            cpsFlag = op_info.cps_flag
            cc = op_info.cc
            updateFlags = op_info.update_flags > 0
            writeback = op_info.writeback > 0
            memBarrier = op_info.mem_barrier.toInt()
            op = op_info.op
        }
    }
}