package com.kyhsgeekcode.disassembler

interface Node {
    fun getNodes() : List<Node>
    fun canExpand() : Boolean
    fun activate()
}