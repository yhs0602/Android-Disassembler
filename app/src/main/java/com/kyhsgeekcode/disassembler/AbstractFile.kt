package com.kyhsgeekcode.disassembler

import android.util.Log
import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException
import at.pollaknet.api.facile.exception.SizeMismatchException
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException
import nl.lxtreme.binutils.elf.MachineType
import splitties.init.appCtx
import java.io.Closeable
import java.io.File
import java.io.IOException

// represents a raw file and interface
abstract class AbstractFile : Closeable {

    @Throws(IOException::class)
    override fun close() {
        return
    }

    override fun toString(): String {
        if (fileContents == null) {
            return "The file has not been configured. You should setup manually in the first page before you can see the details."
        }
        val builder = StringBuilder(
            if (this is RawFile) "The file has not been configured. You should setup manually in the first page before you can see the details." +
                    System.lineSeparator() else ""
        )
        builder.append(/*R.getString(R.string.FileSize)*/"File Size:")
            .append(Integer.toHexString(fileContents.size))
            .append(ls)
        builder.append(appCtx.getString(R.string.FoffsCS))
            .append(java.lang.Long.toHexString(codeSectionBase))
            .append(ls)
        builder.append(appCtx.getString(R.string.FoffsCSEd))
            .append(java.lang.Long.toHexString(codeSectionLimit))
            .append(ls)
        builder.append(appCtx.getString(R.string.FoffsEP))
            .append(java.lang.Long.toHexString(codeSectionBase + entryPoint))
            .append(ls)
        builder.append(appCtx.getString(R.string.VAofCS))
            .append(java.lang.Long.toHexString(codeVirtAddr))
            .append(ls)
        builder.append(appCtx.getString(R.string.VAofCSE))
            .append(java.lang.Long.toHexString(codeSectionLimit + codeVirtAddr))
            .append(ls)
        builder.append(appCtx.getString(R.string.VAofEP))
            .append(java.lang.Long.toHexString(entryPoint + codeVirtAddr))
        return builder.toString()
    }

    // 	public AbstractFile(File file) throws IOException
// 	{
//
// 	}
// 	public AbstractFile(FileChannel channel)
// 	{
//
// 	}
    @JvmField
    val ls = System.lineSeparator()
    open var codeSectionBase: Long = 0
    open var codeSectionLimit: Long = 0

    val exportSymbols: MutableList<Symbol> = ArrayList()
    val importSymbols: MutableList<ImportSymbol> = ArrayList()
    lateinit var fileContents: ByteArray
    open var entryPoint: Long = 0
    open var codeVirtAddr: Long = 0
    open var machineType: MachineType = MachineType.AARCH64

    @JvmField
    var path = ""

    companion object {
        private const val TAG = "AbstractFile"

        @JvmStatic
        @Throws(IOException::class)
        fun createInstance(file: File): AbstractFile {
            // file을 읽던가 mainactivity의 코드를 잘 가져와서 AbstractFile을 만든다.
            // FacileAPI거만 아니면 파일 객체와 내용만 주면 된다.
            // 다시 읽는건 비효율적으로 보일 수 있지만 어쨌든 다시 읽어서 넘겨준다.
            // AfterReadFully() 참고하기!
            // 다 읽고
            // AfterReadFully 로직으로 AbstractFile을 만들어 리턴한다.
            // 그리고 AfterReadFully 함수는 없어질지도 모른다!
            // 그러면 중복코드도 사라짐
            // 행복회로
            val content = file.readBytes()
            if (file.path.endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) { // Unity C# dll file
                Logger.v(TAG, "Found C# unity dll")
                try {
                    val facileReflector = Facile.load(file.path)
                    // load the assembly
                    val assembly = facileReflector.loadAssembly()
                    if (assembly != null) {
                        Logger.v(TAG, assembly.toExtendedString())
                        return ILAssmebly(facileReflector)
                    } else {
                        println("File maybe contains only resources...")
                    }
                } catch (e: CoffPeDataNotFoundException) {
                    Logger.e(TAG, "", e)
                } catch (e: UnexpectedHeaderDataException) {
                    e.printStackTrace()
                } catch (e: SizeMismatchException) {
                    e.printStackTrace()
                }
            } else {
                return try {
                    ELFUtil(file, content)
                } catch (e: Exception) { // not an elf file. try PE parser
                    Log.d(TAG, "Fail elfutil", e)
                    try {
                        PEFile(file, content)
                    } catch (f: NotThisFormatException) {
                        RawFile(file, content)
                        // AllowRawSetup();
// failed to parse the file. please setup manually.
                    } catch (f: RuntimeException) { // AlertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f);
                        RawFile(file, content)
                        // AllowRawSetup();
                    } catch (g: Exception) { // AlertError("Unexpected exception: failed to parse the file. please setup manually.", g);
                        RawFile(file, content)
                        // AllowRawSetup();
                    }
                }
            }
            return RawFile(file, content)
//            return null
        }
    }
}
