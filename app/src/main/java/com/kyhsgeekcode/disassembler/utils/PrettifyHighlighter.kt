package com.kyhsgeekcode.disassembler.utils

import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import prettify.PrettifyParser
import syntaxhighlight.ParseResult
import syntaxhighlight.Parser

// https://stackoverflow.com/a/19787125/8614565
object PrettifyHighlighter {
    private val parser: Parser = PrettifyParser()
    suspend fun highlight(fileExtension: String?, sourceCode: String): SpannableStringBuilder =
        withContext(Dispatchers.Default) {
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
            highlighted
        }

    suspend fun highlight2(fileExtension: String?, sourceCode: String): AnnotatedString =
        withContext(Dispatchers.Default) {
            val results: List<ParseResult> = parser.parse(fileExtension, sourceCode)
            buildAnnotatedString {
                for (result in results) {
                    val type: String = result.styleKeys[0]
                    withStyle(SpanStyle(Color(getColor(type)))) {
                        val theStr =
                            sourceCode.subSequence(result.offset, result.offset + result.length)
                                .toString()
                        append(theStr)
                    }
                }
            }
        }

    fun getColor(type: String): Int {
        return android.graphics.Color.parseColor(
            "#${if (COLORS.containsKey(type)) COLORS[type] else COLORS["pln"]}"
        )
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
