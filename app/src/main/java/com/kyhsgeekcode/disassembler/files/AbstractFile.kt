package com.kyhsgeekcode.disassembler.files

import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException
import at.pollaknet.api.facile.exception.SizeMismatchException
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException
import com.kyhsgeekcode.disassembler.*
import nl.lxtreme.binutils.elf.MachineType
import splitties.init.appCtx
import timber.log.Timber
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
        if (!::fileContents.isInitialized) {
            return "The file has not been configured. You should setup manually in the first page before you can see the details."
        }
        val builder = StringBuilder(
            if (this is RawFile) "The file has not been configured. You should setup manually in the first page before you can see the details." +
                    System.lineSeparator() else ""
        )
        builder.append(/*R.getString(R.string.FileSize)*/"File Size:")
            .append(java.lang.Long.toHexString(getBinaryLength()))
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

    open fun getBinaryContents(): ByteArray = fileContents

    open fun getBinaryLength(): Long = getBinaryContents().size.toLong()

    companion object {
        private const val TAG = "AbstractFile"

        @JvmStatic
        internal fun readFileContentsForParsing(
            file: File,
            readerFactory: (File) -> BinaryRangeReader = ::FileChannelBinaryRangeReader
        ): ByteArray {
            return readerFactory(file).use { reader ->
                reader.readFully()
            }
        }

        @JvmStatic
        internal fun detectBinaryContainerFormat(
            file: File,
            readerFactory: (File) -> BinaryRangeReader = ::FileChannelBinaryRangeReader
        ): BinaryContainerFormat {
            val header = readerFactory(file).use { reader ->
                reader.read(offset = 0, length = 4)
            }
            if (header.size >= 4 &&
                header[0] == 0x7F.toByte() &&
                header[1] == 'E'.code.toByte() &&
                header[2] == 'L'.code.toByte() &&
                header[3] == 'F'.code.toByte()
            ) {
                return BinaryContainerFormat.ELF
            }
            if (header.size >= 2 &&
                header[0] == 'M'.code.toByte() &&
                header[1] == 'Z'.code.toByte()
            ) {
                return BinaryContainerFormat.PE
            }
            return BinaryContainerFormat.RAW
        }

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
            if (file.path.endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) { // Unity C# dll file
                val content = readFileContentsForParsing(file)
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
            }
            return when (detectBinaryContainerFormat(file)) {
                BinaryContainerFormat.ELF -> {
                    try {
                        ElfFile(file, filec = null, deferredContentLoader = BinaryContentLoader {
                            readFileContentsForParsing(file)
                        })
                    } catch (e: Exception) {
                        Timber.d(e, "Fail elfutil")
                        RawFile(file, filecontent = null) {
                            readFileContentsForParsing(file)
                        }
                    }
                }

                BinaryContainerFormat.PE -> {
                    val content = readFileContentsForParsing(file)
                    try {
                        PEFile(file, content, BinaryContentLoader {
                            readFileContentsForParsing(file)
                        })
                    } catch (f: NotThisFormatException) {
                        Timber.e(f, "Not this format exception")
                        RawFile(file, content)
                    } catch (f: RuntimeException) {
                        Timber.e(f, "Not this format exception")
                        RawFile(file, content)
                    } catch (g: Exception) {
                        Timber.e(g, "What the exception")
                        RawFile(file, content)
                    }
                }

                BinaryContainerFormat.RAW -> {
                    RawFile(file, filecontent = null) {
                        readFileContentsForParsing(file)
                    }
                }
            }
//            return null
        }
    }
}
