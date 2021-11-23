package com.kyhsgeekcode.disassembler.ui

data class TabData(val title: String, val tabKind: TabKind)


sealed class TabKind {
    class Apk(val relPath: String) : TabKind()
    class AnalysisResult() : TabKind()
    class Archive(val relPath: String) : TabKind()
    class Binary(val relPath: String) : TabKind()
    class Dex(val relPath: String) : TabKind()
    class DotNet(val relPath: String) : TabKind()
    class Image(val relPath: String) : TabKind()
    class Text(val key: String) : TabKind()
    object ProjectOverview : TabKind()
    class Hex() : TabKind()
    class Log() : TabKind()
    class FoundString() : TabKind()
}
