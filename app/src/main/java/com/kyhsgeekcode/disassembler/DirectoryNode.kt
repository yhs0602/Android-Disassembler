package com.kyhsgeekcode.disassembler

import java.io.File

class DirectoryNode(val realFile: File) :Node {
    override fun getNodes(): List<Node> {

        realFile.listFiles()
    }

    override fun canExpand(): Boolean {

    }

    override fun activate() {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}