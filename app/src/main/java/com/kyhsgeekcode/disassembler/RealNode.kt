package com.kyhsgeekcode.disassembler

class RealNode :Node {
    override fun getNodes(): List<Node> {
        return emptyList()
    }

    override fun canExpand(): Boolean {
        return false
    }

    override fun activate() {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}