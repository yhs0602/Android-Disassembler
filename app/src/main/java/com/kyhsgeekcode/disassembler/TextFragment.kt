package com.kyhsgeekcode.disassembler

import android.graphics.Color
import android.os.Bundle
import android.text.Spannable
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.style.CharacterStyle
import android.text.style.ForegroundColorSpan
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.databinding.FragmentTextBinding
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.utils.PrettifyHighlighter
import com.kyhsgeekcode.disassembler.utils.decompressXML
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStreamReader
import java.util.*

class TextFragment : Fragment() {
    private var _binding: FragmentTextBinding? = null
    private val binding get() = _binding!!

    val TAG = "TextFragment"
    val ARG_PARAM = "param"
    private lateinit var fileContent: ByteArray
    private lateinit var relPath: String
    val spanBlue = ForegroundColorSpan(Color.BLUE)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            it.clear()
        }
        Log.d(TAG, "relPath:$relPath")
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentTextBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val ext = ProjectDataStorage.getExtension(relPath) // File(relPath).extension.toLowerCase()
        var highlighted = SpannableStringBuilder()
        var strContent: String?
        Log.d(TAG, "ext is $ext")
        if (ext == "xml") {
            Log.d(TAG, "ext is xml")
            try {
                highlighted = decompressXML(fileContent)
                strContent = null
            } catch (e: NotThisFormatException) {
                Log.d(TAG, "NotthisFormatException")
                strContent = fileContent.toString(Charsets.UTF_8)
            }
        } else {
            strContent = fileContent.toString(Charsets.UTF_8)
        }
        if (strContent != null) {
            highlighted = PrettifyHighlighter.highlight(
                if (ext == "smali") {
                    "java"
                } else {
                    ext
                }, strContent
            )
        }
//        val ssb = readAndColorize()
        binding.textFragmentTextView.setText(highlighted, TextView.BufferType.SPANNABLE)
        binding.textFragmentTextView.setBackgroundColor(Color.BLACK)
    }

    private fun readAndColorize(): SpannableStringBuilder {
        val ssb = SpannableStringBuilder()
        val terms: List<String>? = TermList[File(relPath).extension.toLowerCase()]

        val br = BufferedReader(InputStreamReader(ByteArrayInputStream(fileContent)))
        var line: String?
        while (br.readLine()
                .also { line = it } != null
        ) { // https://stackoverflow.com/a/46390973/8614565
            val ss = SpannableString(line)
            if (terms != null) {
                for (term in terms) {
                    Log.v("TextFactory", "Checking:$term")
                    var ofe = line!!.indexOf(term)
                    Log.v("TextFactory", "ofe:$ofe")
                    var ofs = 0
                    while (ofs < line!!.length && ofe != -1) {
                        ofe = line!!.indexOf(term, ofs)
                        if (ofe == -1) break else {
                            ss.setSpan(
                                CharacterStyle.wrap(spanBlue),
                                ofe,
                                ofe + term.length,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                            )
                        }
                        ofs = ofe + 1
                    }
                }
            }
            ssb.append(ss)
            ssb.append(System.lineSeparator())
            Log.d(TAG, "ss:$ss")
        }
        Log.d(TAG, "ss:$ssb")
        return ssb
    }

    companion object {
        /**
         * Use this factory method to create a new instance of
         * this fragment using the provided parameters.
         *
         * @param fileContent Parameter 1.
         * @return A new instance of fragment HexFragment.
         */
        // TODO: Rename and change types and number of parameters
        @JvmStatic
        fun newInstance(relPath: String) =
            TextFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }

        val TermList: MutableMap<String, List<String>> = HashMap()
        fun loadTerms() {
            val smaliterms: MutableList<String> = ArrayList()
            smaliterms.add(".class")
            smaliterms.add(".super")
            smaliterms.add(".source")
            smaliterms.add(".implements")
            smaliterms.add(".field")
            smaliterms.add(".method")
            TermList["smali"] = smaliterms
            TermList["il"] = smaliterms
        }

        init {
            loadTerms()
        }
    }
}
