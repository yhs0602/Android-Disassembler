package com.kyhsgeekcode.disassembler.utils

import android.graphics.Color
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import prettify.PrettifyParser
import syntaxhighlight.ParseResult
import syntaxhighlight.Parser

// https://stackoverflow.com/a/19787125/8614565
object PrettifyHighlighter {
    private val parser: Parser = PrettifyParser()
    fun highlight(fileExtension: String?, sourceCode: String): SpannableStringBuilder {
//        val whitespace: Pattern = Pattern.compile("\\s+")
//        val matcher = whitespace.matcher(sourceCode)
//        val spaces = ArrayList<MatchedSpace>()
//        while (matcher.find()) {
//            spaces.add(MatchedSpace(matcher.start(), matcher.end(), matcher.group()))
//        }

        val highlighted = SpannableStringBuilder(sourceCode)
        val results: List<ParseResult> = parser.parse(fileExtension, sourceCode)
        for (result in results) {
            val type: String = result.styleKeys[0]
            highlighted.setSpan(
                ForegroundColorSpan(getColor(type)),
                result.offset,
                result.offset + result.length,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            )
//            val content = sourceCode.substring(result.offset, result.offset + result.length)
//            highlighted.append(String.format(FONT_PATTERN, getColor(type), content))
//            highlighted.append("<br>")
        }
        return highlighted
    }

    public fun getColor(type: String): Int {
        return Color.parseColor("#${if (COLORS.containsKey(type)) COLORS[type] else COLORS["pln"]}")
    }

    //    companion object {
    private val COLORS = buildColorsMap()
    private const val FONT_PATTERN = "<font color=\"#%s\">%s</font>"
    private fun buildColorsMap(): Map<String, String> {
        val map: MutableMap<String, String> = HashMap()
        map["typ"] = "87cefa"
        map["kwd"] = "00ff00"
        map["lit"] = "ffff00"
        map["com"] = "999999"
        map["str"] = "ff4500"
        map["pun"] = "eeeeee"
        map["pln"] = "ffffff"
        map["lang-in.tag"] = "00ffff"
        return map
    }

    //    }
    class MatchedSpace(val start: Int, val end: Int, val what: String)
}
