package com.kyhsgeekcode.disassembler.data

import android.app.Activity
import android.content.Context
import com.kyhsgeekcode.disassembler.FileTabFactory.*
import com.kyhsgeekcode.disassembler.TabType
import com.kyhsgeekcode.disassembler.analysis.Analyzer
import java.util.*

class FileContext(context: Activity, var file: AbstractFile) {
    private val context: Context
    private val analyzer: Analyzer

    private val textFactory: TextFileTabFactory
    private val imageFactory: ImageFileTabFactory
    private val nativeDisasmFactory: NativeDisassemblyFactory
    private val stringFoundFactory: StringFoundFactory

    private val factoryList: MutableList<FileTabContentFactory> = ArrayList()

    fun OpenNewTab(type: TabType): FileTabContentFactory {
        val factory = factoryList[type.ordinal]
        factory.setType(file.getPath(), type)
        return factory
    }

    init {
        this.context = context
        analyzer = Analyzer(file.fileContents)
        textFactory = TextFileTabFactory(context)
        imageFactory = ImageFileTabFactory(context)
        nativeDisasmFactory = NativeDisassemblyFactory(context)
        stringFoundFactory = StringFoundFactory(context, analyzer)
        factoryList.add(textFactory)
        factoryList.add(imageFactory)
        factoryList.add(nativeDisasmFactory)
        factoryList.add(stringFoundFactory)
    }
}