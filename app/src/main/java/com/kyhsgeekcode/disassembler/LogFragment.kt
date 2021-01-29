package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.databinding.FragmentLogBinding

class LogFragment : Fragment() {
    private var _binding: FragmentLogBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLogBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        binding.logRefresh.setOnRefreshListener {
            logAdapter!!.refresh()
            binding.logRefresh.isRefreshing = false
        }
        binding.loglistView.adapter = LogAdapter().also { logAdapter = it }
    }

    var logAdapter: LogAdapter? = null
}
