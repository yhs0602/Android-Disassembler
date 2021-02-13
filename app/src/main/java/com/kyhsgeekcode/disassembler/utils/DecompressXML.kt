package com.kyhsgeekcode.disassembler.utils

import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ForegroundColorSpan
import com.kyhsgeekcode.disassembler.NotThisFormatException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// https://stackoverflow.com/a/4761689/8614565

// decompressXML -- Parse the 'compressed' binary form of Android XML docs
// such as for AndroidManifest.xml in .apk files
const val endDocTag = 0x00100101
const val startTag = 0x00100102
const val endTag = 0x00100103
suspend fun decompressXML(xml: ByteArray): SpannableStringBuilder =
    withContext(Dispatchers.Default) {
        // Compressed XML file/bytes starts with 24x bytes of data,
        // 9 32 bit words in little endian order (LSB first):
        //   0th word is 03 00 08 00
        //   3rd word SEEMS TO BE:  Offset at then of StringTable
        //   4th word is: Number of strings in string table
        // WARNING: Sometime I indiscriminately display or refer to word in
        //   little endian storage format, or in integer format (ie MSB first).
        if (xml[0].toInt() != 3 || xml[1].toInt() != 0 ||
            xml[2].toInt() != 8 || xml[3].toInt() != 0
        ) {
            throw NotThisFormatException()
        }

        val numbStrings = LEW(xml, 4 * 4)

        // StringIndexTable starts at offset 24x, an array of 32 bit LE offsets
        // of the length/string data in the StringTable.
        val sitOff = 0x24 // Offset of start of StringIndexTable

        // StringTable, each string is represented with a 16 bit little endian
        // character count, followed by that number of 16 bit (LE) (Unicode) chars.
        val stOff = sitOff + numbStrings * 4 // StringTable follows StrIndexTable

        // XMLTags, The XML tag tree starts after some unknown content after the
        // StringTable.  There is some unknown data after the StringTable, scan
        // forward from this point to the flag for the start of an XML start tag.
        var xmlTagOff = LEW(xml, 3 * 4) // Start from the offset in the 3rd word.
        // Scan forward until we find the bytes: 0x02011000(x00100102 in normal int)
        var ii = xmlTagOff
        while (ii < xml.size - 4) {
            if (LEW(xml, ii) == startTag) {
                xmlTagOff = ii
                break
            }
            ii += 4
        }

        // XML tags and attributes:
        // Every XML start and end tag consists of 6 32 bit words:
        //   0th word: 02011000 for startTag and 03011000 for endTag
        //   1st word: a flag?, like 38000000
        //   2nd word: Line of where this tag appeared in the original source file
        //   3rd word: FFFFFFFF ??
        //   4th word: StringIndex of NameSpace name, or FFFFFFFF for default NS
        //   5th word: StringIndex of Element Name
        //   (Note: 01011000 in 0th word means end of XML document, endDocTag)

        // Start tags (not end tags) contain 3 more words:
        //   6th word: 14001400 meaning??
        //   7th word: Number of Attributes that follow this tag(follow word 8th)
        //   8th word: 00000000 meaning??

        // Attributes consist of 5 words:
        //   0th word: StringIndex of Attribute Name's Namespace, or FFFFFFFF
        //   1st word: StringIndex of Attribute Name
        //   2nd word: StringIndex of Attribute Value, or FFFFFFF if ResourceId used
        //   3rd word: Flags?
        //   4th word: str ind of attr value again, or ResourceId of value

        // TMP, dump string table to tr for debugging
        // tr.addSelect("strings", null);
        // for (int ii=0; ii<numbStrings; ii++) {
        //  // Length of string starts at StringTable plus offset in StrIndTable
        //  String str = compXmlString(xml, sitOff, stOff, ii);
        //  tr.add(String.valueOf(ii), str);
        // }
        // tr.parent();

        // Step through the XML tree element tags and attributes
        var off = xmlTagOff
        var indent = 0
        var startTagLineNo = -2
        val buffer = SpannableStringBuilder()
        while (off < xml.size) {
            val tag0 = LEW(xml, off)
            //int tag1 = LEW(xml, off+1*4);
            val lineNo = LEW(xml, off + 2 * 4)
            //int tag3 = LEW(xml, off+3*4);
            val nameNsSi = LEW(xml, off + 4 * 4)
            val nameSi = LEW(xml, off + 5 * 4)
            if (tag0 == startTag) { // XML START TAG
                val tag6 = LEW(xml, off + 6 * 4) // Expected to be 14001400
                val numbAttrs = LEW(xml, off + 7 * 4) // Number of Attributes to follow
                //int tag8 = LEW(xml, off+8*4);  // Expected to be 00000000
                off += 9 * 4 // Skip over 6+3 words of startTag data
                val name = compXmlString(xml, sitOff, stOff, nameSi)
                //tr.addSelect(name, null);
                startTagLineNo = lineNo

                // Look for the Attributes
                val sb = SpannableStringBuilder()
                for (ii in 0 until numbAttrs) {
                    val attrNameNsSi = LEW(xml, off) // AttrName Namespace Str Ind, or FFFFFFFF
                    val attrNameSi = LEW(xml, off + 1 * 4) // AttrName String Index
                    val attrValueSi = LEW(xml, off + 2 * 4) // AttrValue Str Ind, or FFFFFFFF
                    val attrFlags = LEW(xml, off + 3 * 4)
                    val attrResId =
                        LEW(xml, off + 4 * 4) // AttrValue ResourceId or dup AttrValue StrInd
                    off += 5 * 4 // Skip over the 5 words of an attribute
                    val attrName = compXmlString(xml, sitOff, stOff, attrNameSi)
                    val attrValue = if (attrValueSi != -1) compXmlString(
                        xml,
                        sitOff,
                        stOff,
                        attrValueSi
                    ) else "resourceID 0x" + Integer.toHexString(attrResId)
                    appendSpanned(
                        sb,
                        " $attrName",
                        ForegroundColorSpan(PrettifyHighlighter.getColor("kwd"))
                    )
                    appendSpanned(
                        sb,
                        "=\"",
                        ForegroundColorSpan(PrettifyHighlighter.getColor("pun"))
                    )
                    appendSpanned(
                        sb,
                        "$attrValue",
                        ForegroundColorSpan(PrettifyHighlighter.getColor("lit"))
                    )
                    appendSpanned(
                        sb,
                        "\"",
                        ForegroundColorSpan(PrettifyHighlighter.getColor("pun"))
                    )
                    sb.append(System.lineSeparator())
                    //tr.add(attrName, attrValue);
                }
                prtIndent(buffer, indent, "")
                appendSpanned(buffer, "<", ForegroundColorSpan(PrettifyHighlighter.getColor("pun")))
                appendSpanned(
                    buffer,
                    "$name",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("typ"))
                )
                buffer.append(sb)
                appendSpanned(buffer, ">", ForegroundColorSpan(PrettifyHighlighter.getColor("pun")))
                buffer.append(System.lineSeparator())
                indent++
            } else if (tag0 == endTag) { // XML END TAG
                indent--
                off += 6 * 4 // Skip over 6 words of endTag data
                val name = compXmlString(xml, sitOff, stOff, nameSi)

                prtIndent(buffer, indent, "") //  (line $startTagLineNo-$lineNo)
                appendSpanned(
                    buffer,
                    "</",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("pun"))
                )
                appendSpanned(
                    buffer,
                    "$name",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("typ"))
                )
                appendSpanned(
                    buffer,
                    ">  ",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("pun"))
                )
                appendSpanned(
                    buffer,
                    "(line $startTagLineNo-$lineNo)",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("com"))
                )
                buffer.append(System.lineSeparator())
                //tr.parent();  // Step back up the NobTree
            } else if (tag0 == endDocTag) {  // END OF XML DOC TAG
                break
            } else {
                appendSpanned(
                    buffer, "  Unrecognized tag code '${Integer.toHexString(tag0)}' at offset $off",
                    ForegroundColorSpan(PrettifyHighlighter.getColor("com"))
                )
                buffer.append(System.lineSeparator())
                break
            }
        } // end of while loop scanning tags and attributes of XML tree
        appendSpanned(
            buffer,
            "    end at offset $off",
            ForegroundColorSpan(PrettifyHighlighter.getColor("com"))
        )
        buffer
    } // end of decompressXML


fun compXmlString(xml: ByteArray, sitOff: Int, stOff: Int, strInd: Int): String? {
    if (strInd < 0) return null
    val strOff = stOff + LEW(xml, sitOff + strInd * 4)
    return compXmlStringAt(xml, strOff)
}


var spaces = "                                             "
fun prtIndent(buffer: SpannableStringBuilder, indent: Int, str: String) {
    buffer.append(spaces.substring(0, (indent * 2).coerceAtMost(spaces.length)) + str)
}


// compXmlStringAt -- Return the string stored in StringTable format at
// offset strOff.  This offset points to the 16 bit string length, which
// is followed by that number of 16 bit (Unicode) chars.
fun compXmlStringAt(arr: ByteArray, strOff: Int): String {
    val strLen: Int = arr[strOff + 1] shl 8 and 0xff00 or arr[strOff].toInt() and 0xff
    val chars = ByteArray(strLen)
    for (ii in 0 until strLen) {
        chars[ii] = arr[strOff + 2 + ii * 2]
    }
    return String(chars) // Hack, just use 8 byte chars
} // end of compXmlStringAt


// LEW -- Return value of a Little Endian 32 bit word from the byte array
//   at offset off.
fun LEW(arr: ByteArray, off: Int): Int {
    return arr[off + 3] shl 24 and -0x1000000 or (arr[off + 2] shl 16 and 0xff0000
            ) or (arr[off + 1] shl 8 and 0xff00) or (arr[off].toInt() and 0xFF)
} // end of LEW

infix fun Byte.shl(that: Int): Int = this.toInt().shl(that)

fun appendSpanned(builder: SpannableStringBuilder, text: String, what: Any) {
    val length: Int = builder.length
    builder.append(text)
    builder.setSpan(what, length, builder.length, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
}
