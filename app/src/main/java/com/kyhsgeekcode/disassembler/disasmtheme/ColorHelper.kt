package com.kyhsgeekcode.disassembler.disasmtheme

import capstone.*
import com.kyhsgeekcode.disassembler.DisasmResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import splitties.init.appCtx
import timber.log.Timber
import java.io.File
import java.util.*

object ColorHelper {
    private val _palette = MutableStateFlow(Palette.Default)
    val palette = _palette as StateFlow<Palette>

    var isUpdatedColor = false
    var architecture = 0

    fun addPalette(palette: Palette) {
        palettes[palette.name] = palette
    }

    fun getPaletteFile(nam: String?): File {
        val ext = appCtx.getExternalFilesDir(null)!!.absoluteFile
        val themeDir = File(ext, "themes/")
        if (!themeDir.exists()) themeDir.mkdirs()
        return File(themeDir, nam)
    }


    // combined by ORs
// index=group_type
// Common instruction groups - to be consistent across all architectures.
// public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
// public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
// 	public static final int CS_GRP_CALL    = 2;  // all call instructions
// 	public static final int CS_GRP_RET     = 3;  // all return instructions
// 	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
// 	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
// 1 2 3 4 5 6 7

    val palettes = HashMap<String, Palette>()

    fun setPalette(name: String?) {
        _palette.value = palettes[name] ?: Palette.Default
        isUpdatedColor = true
    }

    val Arm64CallIns = setOf(Arm64_const.ARM64_INS_BL, Arm64_const.ARM64_INS_BR)
    val ArmCallIns = setOf(Arm_const.ARM_INS_BL, Arm_const.ARM_INS_BLX)
    val ArmPushIns = setOf(Arm_const.ARM_INS_PUSH)
    val X86PushIns = setOf(
        X86_const.X86_INS_PUSH,
        X86_const.X86_INS_PUSHAW,
        X86_const.X86_INS_PUSHAL,
        X86_const.X86_INS_PUSHF,
        X86_const.X86_INS_PUSHFD,
        X86_const.X86_INS_PUSHFQ
    )
    val ArmPopIns = setOf(Arm_const.ARM_INS_POP)
    val X86PopIns = setOf(
        X86_const.X86_INS_POP,
        X86_const.X86_INS_POPAL,
        X86_const.X86_INS_POPF,
        X86_const.X86_INS_POPFD,
        X86_const.X86_INS_POPFQ,
        X86_const.X86_INS_POPAW
    )


    fun getColorByGrps(
        palette: Palette,
        groups: ByteArray,
        group_cnt: Int,
        id: Int,
        opcodes: ByteArray
    ): PaletteRow {
        when (architecture) {
            Capstone.CS_ARCH_ARM -> {
                if (ArmCallIns.contains(id)) {
                    return palette.call
                }
                if (ArmPushIns.contains(id)) {
                    return palette.push
                }
                if (ArmPopIns.contains(id)) {
                    return palette.pop
                }
                if (id == Arm_const.ARM_INS_BX) {
                    Timber.d("OpCodes: " + Arrays.toString(opcodes))
                    if (opcodes[0] == 0x1E.toByte() && opcodes[1] == 0xFF.toByte() &&
                        opcodes[2] == 0x2F.toByte() && opcodes[3] == 0xE1.toByte()
                    ) {
                        return palette.ret
                    }
                }
            }
            Capstone.CS_ARCH_ARM64 -> {
                if (Arm64CallIns.contains(id)) {
                    return palette.call
                }
            }
            Capstone.CS_ARCH_X86 -> {
                if (X86PushIns.contains(id)) {
                    return palette.push
                }
                if (X86PopIns.contains(id)) {
                    return palette.pop
                }

            }

        }
        var i = 0
        for (g in groups) {
            if (i >= group_cnt) break
            i++
            when (g.toInt()) {
                Capstone.CS_GRP_INVALID -> continue
                Capstone.CS_GRP_JUMP -> return palette.jmp
                Capstone.CS_GRP_CALL -> return palette.call
                Capstone.CS_GRP_RET -> return palette.ret
                Capstone.CS_GRP_INT -> return palette.interrupt
                Capstone.CS_GRP_IRET -> return palette.interrupt
                else -> Timber.w("fallback_color wrong group:($g)")
            }

        }
        return palette.default
    }

    fun getColorRow(palette: Palette, disasmResult: DisasmResult?): PaletteRow {
        if (disasmResult == null) return palette.default
        return getColorByGrps(
            palette,
            disasmResult.groups,
            disasmResult.groups_count.toInt(),
            disasmResult.id,
            disasmResult.bytes
        )
    }
}
