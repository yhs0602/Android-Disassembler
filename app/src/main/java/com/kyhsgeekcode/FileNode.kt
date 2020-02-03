package com.kyhsgeekcode

import com.kyhsgeekcode.disassembler.Node
import java.io.File

class FileNode(val realFile:File) : Node {
    override fun getNodes(): List<Node> {
        return emptyList()
    }

    override fun canExpand(): Boolean {
        return false
    }

    //Uses UI
    override fun activate() {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}