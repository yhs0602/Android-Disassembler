package com.kyhsgeekcode.disassembler

//import kotlinx.android.synthetic.main.fragment_analysis_result.*
import android.os.Bundle
import android.view.*
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import kotlinx.android.synthetic.main.fragment_binary.*
import kotlinx.serialization.UnstableDefault
import kotlin.reflect.KClass
import kotlin.reflect.full.staticFunctions

class BinaryFragment : Fragment(), ITabController, IParsedFileProvider {
    val ARG_PARAM1 = "RELPATH"
    lateinit var relPath: String
    override lateinit var parsedFile: AbstractFile

    private lateinit var pagerAdapter: ViewPagerAdapter
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM1)!!
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary, container, false)!!

    @UnstableDefault
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        pagerAdapter = ViewPagerAdapter(childFragmentManager)
        pagerBinary.adapter = pagerAdapter
        binartTabLayout.setupWithViewPager(pagerBinary)
        parsedFile = AbstractFile.createInstance(ProjectDataStorage.resolveToRead(relPath)!!)
        setHasOptionsMenu(true)
        pagerBinary.offscreenPageLimit = 5
        pagerAdapter.addFragment(BinaryOverviewFragment.newInstance(relPath), "Overview")
        pagerAdapter.addFragment(BinaryDisasmFragment.newInstance(relPath, BinaryDisasmFragment.ViewMode.Binary), "Disassembly")
        pagerAdapter.addFragment(BinarySymbolFragment.newInstance(relPath), "Symbols")
        pagerAdapter.addFragment(BinaryDetailFragment.newInstance(relPath), "Details")
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.menu_bin, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.analyze -> {
                pagerAdapter.addFragment(AnalysisResultFragment.newInstance(relPath), "Analysis")
            }
            R.id.findString -> {
                pagerAdapter.addFragment(StringFragment.newInstance(relPath), "Strings")
            }
        }
        return super.onOptionsItemSelected(item)
    }


    companion object {
        /**
         * Use this factory method to create a new instance of
         * this fragment using the provided parameters.
         *
         * @param relPath Parameter 1.
         * @return A new instance of fragment StringFragment.
         */
        // TODO: Rename and change types and number of parameters
        @JvmStatic
        fun newInstance(relPath: String) =
                BinaryFragment().apply {
                    arguments = Bundle().apply {
                        putString(ARG_PARAM1, relPath)
                    }
                }
    }

    override fun setCurrentTab(index: Int): Boolean {
        pagerBinary.setCurrentItem(index, true)
        return pagerBinary.currentItem == index
    }

    override fun getCurrentTab(): Int = pagerBinary.currentItem

    override fun setCurrentTabByTag(tag: String, openNew: Boolean): Boolean {
        val clas: KClass<out Any>
        val fragment = when (tag) {
            TabTags.TAB_DISASM -> "BinaryDisasmFragment"
            TabTags.TAB_ANALYSIS -> "AnalysisResultFragment"
            TabTags.TAB_EXPORTSYMBOLS -> "SymbolFragment"
            TabTags.TAB_STRINGS -> "StringFragment"
            else -> return false
        }.let {
            clas = Class.forName("com.kyhsgeekcode.disassembler.$it").kotlin
            pagerAdapter.findFragmentByType(clas)
        } ?: if (!openNew) return false else {
            val frag = clas.staticFunctions.single { it.name == "newInstance" }.call(relPath) as Fragment
            pagerAdapter.addFragment(frag, tag)
        }
        pagerBinary.setCurrentItem(fragment,true)
        return true
    }

}
