package com.kyhsgeekcode.disassembler.ui

data class TabData(val title: String, val tabKind: TabKind)
enum class ViewMode {
    Binary, Text
}

sealed class TabKind {
    class Apk(val relPath: String) : TabKind()
    class AnalysisResult() : TabKind()
    class Archive(val relPath: String) : TabKind()
    class Binary(val relPath: String) : TabKind()
    class BinaryDetail() : TabKind()
    class BinaryDisasm(val relPath: String, val viewMode: ViewMode) : TabKind()
    class Dex(val relPath: String) : TabKind()
    class DotNet(val relPath: String) : TabKind()
    class Image(val relPath: String) : TabKind()
    class Text(val key: String) : TabKind()
    class ProjectOverview(): TabKind()
//    BinaryExportSymbol,
//    Binary,
//    BinaryImportSymbol,
//    BinaryOverview,
//    DotNet,
//    Hex,
//    Image,
//    Log,
//    ProjectOverview,
//    String,
//    Text
}
