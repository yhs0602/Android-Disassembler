package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_log.*

class LogFragment : Fragment() {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ) =
        inflater.inflate(R.layout.fragment_log, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        logRefresh.setOnRefreshListener {
            logAdapter!!.refresh()
            logRefresh.isRefreshing = false
        }
        loglistView.adapter = LogAdapter().also { logAdapter = it }
    }

    var logAdapter: LogAdapter? = null
}
