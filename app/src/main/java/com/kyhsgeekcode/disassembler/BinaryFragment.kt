package com.kyhsgeekcode.disassembler

//import kotlinx.android.synthetic.main.fragment_analysis_result.*
import android.os.Bundle
import android.view.*
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import kotlinx.android.synthetic.main.fragment_binary.*
import kotlinx.serialization.UnstableDefault

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
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun getCurrentTab(): Int {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun setCurrentTabByTag(tag: String): Boolean {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

}
