package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.FileNode
import java.io.File

object NodeFactory {
    fun create(file: File) :Node{
        if(file.isDirectory) {
            return DirectoryNode(file)
        } else {
            return FileNode(file)
        }
    }
}