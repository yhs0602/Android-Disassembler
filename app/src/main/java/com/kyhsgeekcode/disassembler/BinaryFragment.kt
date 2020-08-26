package com.kyhsgeekcode.disassembler

// import kotlinx.android.synthetic.main.fragment_analysis_result.*
import android.os.Bundle
import android.util.Log
import android.view.*
import androidx.fragment.app.Fragment
import com.google.android.material.tabs.TabLayoutMediator
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import kotlinx.android.synthetic.main.fragment_binary.*
import kotlinx.serialization.UnstableDefault
import kotlin.reflect.KClass
import kotlin.reflect.full.companionObject
import kotlin.reflect.full.companionObjectInstance
import kotlin.reflect.full.functions

class BinaryFragment : Fragment(), ITabController, IParsedFileProvider, IOnBackPressed {
    val TAG = "BinaryFragment"

    val ARG_PARAM1 = "RELPATH"
    lateinit var relPath: String
    override lateinit var parsedFile: AbstractFile

    private lateinit var pagerAdapter: ViewPagerAdapter
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM1)!!
            it.clear()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ) =
        inflater.inflate(R.layout.fragment_binary, container, false)!!

    @UnstableDefault
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        pagerAdapter = ViewPagerAdapter(childFragmentManager, lifecycle)
        pagerBinary.adapter = pagerAdapter
        TabLayoutMediator(binaryTabLayout, pagerBinary) { tab, position ->
            tab.text = pagerAdapter.getTitle(position)
            pagerBinary.setCurrentItem(tab.position, true)
        }.attach()
//        binaryTabLayout.setupWithViewPager(pagerBinary)
        parsedFile = AbstractFile.createInstance(ProjectDataStorage.resolveToRead(relPath)!!)
        setHasOptionsMenu(true)
        pagerBinary.offscreenPageLimit = 5
        pagerAdapter.addFragment(BinaryOverviewFragment.newInstance(relPath), "Overview")
        pagerAdapter.addFragment(
            BinaryDisasmFragment.newInstance(
                relPath,
                BinaryDisasmFragment.ViewMode.Binary
            ), "Disassembly"
        )
        pagerAdapter.addFragment(BinaryExportSymbolFragment.newInstance(relPath), "Export Symbols")
        pagerAdapter.addFragment(BinaryImportSymbolFragment.newInstance(relPath), "Import Symbols")
        pagerAdapter.addFragment(BinaryDetailFragment.newInstance(relPath), "Details")
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.menu_bin, menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.analyze -> {
                setCurrentTabByTag(TabTags.TAB_ANALYSIS, true)
//                pagerAdapter.addFragment(AnalysisResultFragment.newInstance(relPath), "Analysis")
            }
            R.id.findString -> {
                pagerAdapter.addFragment(StringFragment.newInstance(relPath), "Strings")
            }
            R.id.showSymbols -> {
                setCurrentTabByTag(TabTags.TAB_EXPORTSYMBOLS, true)
            }
            R.id.showDetails -> {
                setCurrentTabByTag(TabTags.TAB_DETAILS, true)
            }
            R.id.showDisassembly -> {
                setCurrentTabByTag(TabTags.TAB_DISASM, true)
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

        val classNameByTag = HashMap<String, String>()

        init {
            classNameByTag[TabTags.TAB_DISASM] = "BinaryDisasmFragment"
            classNameByTag[TabTags.TAB_ANALYSIS] = "AnalysisResultFragment"
            classNameByTag[TabTags.TAB_EXPORTSYMBOLS] = "BinaryExportSymbolFragment"
            classNameByTag[TabTags.TAB_STRINGS] = "StringFragment"
            classNameByTag[TabTags.TAB_DETAILS] = "BinaryDetailFragment"
        }
    }

    override fun setCurrentTab(index: Int): Boolean {
        pagerBinary.setCurrentItem(index, true)
        return pagerBinary.currentItem == index
    }

    override fun getCurrentTab(): Int = pagerBinary.currentItem

    override fun setCurrentTabByTag(tag: String, openNew: Boolean): Boolean {
        val clas: KClass<out Any>
        val fragment = classNameByTag[tag].let {
            clas = Class.forName("com.kyhsgeekcode.disassembler.$it").kotlin
            pagerAdapter.findFragmentByType(clas)
        } ?: if (!openNew) return false else {
            Log.d(TAG, "Open new")
            val frag = clas.companionObject!!.functions.single { it.name == "newInstance" }
                .call(clas.companionObjectInstance, relPath) as Fragment
            pagerAdapter.addFragment(frag, tag)
        }
        pagerBinary.setCurrentItem(fragment, true)
        return true
    }

    override fun findTabByTag(tag: String): Int? =
        classNameByTag[tag]?.let {
            val clas = Class.forName("com.kyhsgeekcode.disassembler.$it").kotlin
            pagerAdapter.findFragmentByType(clas)
        }

    fun jumpto(address: Long) {
        setCurrentTabByTag(TabTags.TAB_DISASM, true)
        (pagerAdapter.createFragment(findTabByTag(TabTags.TAB_DISASM)!!) as BinaryDisasmFragment).jumpto(
            address
        )
    }

    override fun onBackPressed(): Boolean {
        val fragment = pagerAdapter.createFragment(pagerBinary.currentItem)
        if ((fragment as? IOnBackPressed)?.onBackPressed() != true) {
            return false
        }
        return true
    }
}
