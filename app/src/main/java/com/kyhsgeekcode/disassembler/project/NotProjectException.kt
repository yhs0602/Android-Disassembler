package com.kyhsgeekcode.disassembler.project

import java.lang.Exception

class NotProjectException(path: String) : Exception("$path is not a project")
