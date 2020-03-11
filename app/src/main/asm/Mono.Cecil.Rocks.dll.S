.section ".debug_abbrev"
.subsection 0

	.byte 1,17,1,37,8,3,8,27,8,19,11,17,1,18,1,16,6,0,0,2,46,1,3,8,135,64,8,58,15,59,15,90
	.byte 8,17,1,18,1,64,10,0,0,3,5,0,3,8,73,19,2,10,0,0,15,5,0,3,8,73,19,2,6,0,0,4
	.byte 36,0,11,11,62,11,3,8,0,0,5,2,1,3,8,11,15,0,0,17,2,0,3,8,11,15,0,0,6,13,0,3
	.byte 8,73,19,56,10,0,0,7,22,0,3,8,73,19,0,0,8,4,1,3,8,11,15,73,19,0,0,9,40,0,3,8
	.byte 28,13,0,0,10,57,1,3,8,0,0,11,52,0,3,8,73,19,2,10,0,0,12,52,0,3,8,73,19,2,6,0
	.byte 0,13,15,0,73,19,0,0,14,16,0,73,19,0,0,16,28,0,73,19,56,10,0,0,18,46,0,3,8,17,1,18
	.byte 1,0,0,0
.section ".debug_info"
.subsection 0
.Ldebug_info_start:

.LDIFF_SYM0=.Ldebug_info_end - .Ldebug_info_begin
	.long .LDIFF_SYM0
.Ldebug_info_begin:

	.hword 2
	.long 0
	.byte 8,1
	.string "Mono AOT Compiler 6.8.0.105 (tarball Tue Feb  4 21:20:20 UTC 2020)"
	.string "Mono.Cecil.Rocks.dll"
	.string ""

	.byte 2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
.LDIFF_SYM1=.Ldebug_line_start - .Ldebug_line_section_start
	.long .LDIFF_SYM1
.LDIE_I1:

	.byte 4,1,5
	.string "sbyte"
.LDIE_U1:

	.byte 4,1,7
	.string "byte"
.LDIE_I2:

	.byte 4,2,5
	.string "short"
.LDIE_U2:

	.byte 4,2,7
	.string "ushort"
.LDIE_I4:

	.byte 4,4,5
	.string "int"
.LDIE_U4:

	.byte 4,4,7
	.string "uint"
.LDIE_I8:

	.byte 4,8,5
	.string "long"
.LDIE_U8:

	.byte 4,8,7
	.string "ulong"
.LDIE_I:

	.byte 4,8,5
	.string "intptr"
.LDIE_U:

	.byte 4,8,7
	.string "uintptr"
.LDIE_R4:

	.byte 4,4,4
	.string "float"
.LDIE_R8:

	.byte 4,8,4
	.string "double"
.LDIE_BOOLEAN:

	.byte 4,1,2
	.string "boolean"
.LDIE_CHAR:

	.byte 4,2,8
	.string "char"
.LDIE_STRING:

	.byte 4,8,1
	.string "string"
.LDIE_OBJECT:

	.byte 4,8,1
	.string "object"
.LDIE_SZARRAY:

	.byte 4,8,1
	.string "object"
.section ".debug_loc"
.subsection 0
.Ldebug_loc_start:
.section ".debug_frame"
.subsection 0
	.balign 8

.LDIFF_SYM2=.Lcie0_end - .Lcie0_start
	.long .LDIFF_SYM2
.Lcie0_start:

	.long -1
	.byte 3
	.string ""

	.byte 1,120,16,12,7,8,144,1
	.balign 8
.Lcie0_end:
.text 0
	.balign 8
jit_code_start:

	.byte 144,144,144,144,144,144,144,144,144,144,144,144,144,144,144,144
.text 0
	.balign 16
.Lm_0:
	.local Mono_Cecil_Rocks_DocCommentId__ctor
	.type Mono_Cecil_Rocks_DocCommentId__ctor,@function
Mono_Cecil_Rocks_DocCommentId__ctor:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 196
	.byte 190,48,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248
call .Lp_3

	.byte 72,139,68,36,8,72,139,12,36,72,131,193,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId__ctor,.-Mono_Cecil_Rocks_DocCommentId__ctor
.Lme_0:
.text 0
	.balign 16
.Lm_1:
	.local Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,60,36,190,70,0,0,0,72,139,84,36,8
call .Lp_4

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition
.Lme_1:
.text 0
	.balign 16
.Lm_2:
	.local Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,60,36,190,69,0,0,0,72,139,84,36,8
call .Lp_4

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition
.Lme_2:
.text 0
	.balign 16
.Lm_3:
	.local Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,64,16,72,139,248,190,84,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,248,190,58,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,60,36,72,139,116,36,8,51,210
call .Lp_6

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition
.Lme_3:
.text 0
	.balign 16
.Lm_4:
	.local Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,190,77,0,0,0,73,139,215
call .Lp_4

	.byte 73,139,255,73,139,7,255,144,136,1,0,0,72,15,182,192,133,192,15,132,86,0,0,0,73,139,70,16,72,139,248,190
	.byte 96,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,248,190,96,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,70,16,72,137,68,36,16,73,139,255,73,139,7,255,144,128,1,0,0,72,139,200,72,139,68,36,16,72,139,209
	.byte 131,58,0,72,99,113,24,72,139,248,131,56,0
call .Lp_7

	.byte 73,139,255,73,139,7,255,144,152,1,0,0,72,15,182,192,133,192,116,23,73,139,255,73,139,7,255,144,144,1,0,0
	.byte 72,139,240,73,139,254
call .Lp_8

	.byte 73,139,255
call .Lp_9

	.byte 72,15,182,192,133,192,116,11,73,139,254,73,139,247
call .Lp_10

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition
.Lme_4:
.text 0
	.balign 16
.Lm_5:
	.local Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,8,76,137,60,36,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,133,0,0,0,65,131,63,0,65,15,183,135,136,0,0,0,37,0,8,0,0,133,192,64,15,151,192
	.byte 72,15,182,192,72,15,182,192,72,15,182,192,133,192,15,132,79,0,0,0,73,139,255,73,139,7,255,144,184,0,0,0
	.byte 72,139,248,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 204
call .Lp_11

	.byte 72,15,182,192,133,192,15,133,33,0,0,0,73,139,255,73,139,7,255,144,184,0,0,0,72,139,248,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 212
call .Lp_11

	.byte 72,15,182,192,235,9,184,1,0,0,0,235,2,51,192,76,139,60,36,72,131,196,8,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition
.Lme_5:
.text 0
	.balign 16
.Lm_6:
	.local Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,64,16,72,139,248,190,126,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,124,36,8,72,139,199,131,56,0
call .Lp_15

	.byte 72,139,240,72,139,60,36
call .Lp_16

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition
.Lme_6:
.text 0
	.balign 16
.Lm_7:
	.local Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition:

	.byte 72,131,236,24,76,137,60,36,72,137,124,36,8,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,124,36,8,190,80,0,0,0,73,139,215
call .Lp_4

	.byte 73,139,255,65,131,63,0
call .Lp_17

	.byte 72,15,182,192,133,192,15,132,25,0,0,0,73,139,255,73,139,7,255,144,200,0,0,0,72,139,240,72,139,124,36,8
call .Lp_8

	.byte 76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition
.Lme_7:
.text 0
	.balign 16
.Lm_8:
	.local Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition:

	.byte 72,131,236,24,76,137,52,36,76,139,247,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,70,16,72,139,248,190,40,0,0,0,131,56,0
call .Lp_5

	.byte 77,133,246,15,132,175,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 220
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,208,77,133,246,15,132,131,0,0,0,76,137,114,32,72,139,194,72,131,192,32,193,232,9,72,37,255,255,127,0
	.byte 73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 228
	.byte 72,137,66,40,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 236
	.byte 72,137,66,64,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 244
	.byte 72,139,72,40,72,137,74,24,72,139,64,32,72,137,66,16,198,66,112,0,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 252
	.byte 73,139,254,72,139,116,36,8
call .Lp_18

	.byte 73,139,70,16,72,139,248,190,41,0,0,0,131,56,0
call .Lp_5

	.byte 76,139,52,36,72,131,196,24,195,190,152,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,196,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition
.Lme_8:
.text 0
	.balign 16
.Lm_9:
	.local Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference:

	.byte 72,131,236,40,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,255,73,139,7,255,144,24,1,0,0,72,15,182,192,76,15,182,232,73,139,197,76,139,224,65,131,236,15,65,131
	.byte 252,7,115,24,73,139,196,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 260
	.byte 72,3,193,72,139,0,255,224,77,139,229,65,131,236,27,65,131,252,6,15,131,116,2,0,0,73,139,196,72,193,224,3
	.byte 139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 268
	.byte 72,3,193,72,139,0,255,224,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 276
	.byte 72,59,193,15,133,158,2,0,0,73,139,254,73,139,247
call .Lp_20

	.byte 233,54,2,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 284
	.byte 72,59,193,15,133,100,2,0,0,65,131,63,0,73,139,119,96,73,139,254
call .Lp_16

	.byte 73,139,70,16,72,139,248,190,64,0,0,0,131,56,0
call .Lp_5

	.byte 233,234,1,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 292
	.byte 72,59,193,15,133,17,2,0,0,73,139,254,73,139,247
call .Lp_21

	.byte 233,183,1,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 300
	.byte 72,59,193,15,133,215,1,0,0,73,139,254,73,139,247
call .Lp_22

	.byte 233,132,1,0,0,73,139,70,16,72,139,248,190,96,0,0,0,131,56,0
call .Lp_5

	.byte 77,139,110,16,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 308
	.byte 72,59,193,15,133,133,1,0,0,65,131,63,0,73,99,119,120,73,139,253,65,131,125,0,0
call .Lp_7

	.byte 233,47,1,0,0,73,139,70,16,72,139,248,190,96,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,248,190,96,0,0,0,131,56,0
call .Lp_5

	.byte 77,139,110,16,77,133,255,15,132,30,0,0,0,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 308
	.byte 72,59,193,15,133,21,1,0,0,65,131,63,0,73,99,119,120,73,139,253,65,131,125,0,0
call .Lp_7

	.byte 233,198,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 316
	.byte 72,59,193,15,133,209,0,0,0,73,139,254,73,139,247,186,33,0,0,0
call .Lp_23

	.byte 233,142,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 324
	.byte 72,59,193,15,133,146,0,0,0,73,139,254,73,139,247,186,124,0,0,0
call .Lp_23

	.byte 233,86,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,32,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 332
	.byte 72,59,193,15,133,75,0,0,0,65,131,63,0,73,139,119,96,73,139,254
call .Lp_16

	.byte 73,139,70,16,72,139,248,190,42,0,0,0,131,56,0
call .Lp_5

	.byte 235,13,73,139,254,73,139,247,51,210
call .Lp_6

	.byte 76,139,36,36,76,139,108,36,8,76,139,116,36,16,76,139,124,36,24,72,131,196,40,195,190,96,0,0,0,191,19,1
	.byte 0,0
call .Lp_19

	.byte 190,152,0,0,0,235,239,190,208,0,0,0,235,232,190,13,1,0,0,235,225,190,118,1,0,0,235,218,190,193,1,0
	.byte 0,235,211,190,244,1,0,0,235,204,190,64,2,0,0,235,197,190,115,2,0,0,235,190

	.size Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference
.Lme_9:
.text 0
	.balign 16
.Lm_a:
	.local Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType
	.type Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType,@function
Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,73,139,127,96
call .Lp_24

	.byte 72,15,182,192,133,192,15,133,232,0,0,0,65,131,63,0,73,139,119,96,73,139,254,186,1,0,0,0
call .Lp_6

	.byte 73,139,70,16,72,139,248,190,123,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,255,65,131,63,0
call .Lp_25

	.byte 72,137,68,36,16,77,133,246,15,132,198,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 340
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,208,72,139,116,36,16,77,133,246,15,132,149,0,0,0,76,137,114,32,72,139,194,72,131,192,32,193,232,9,72
	.byte 37,255,255,127,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 348
	.byte 72,137,66,40,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 356
	.byte 72,137,66,64,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 364
	.byte 72,139,72,40,72,137,74,24,72,139,64,32,72,137,66,16,198,66,112,0,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 372
	.byte 73,139,254
call .Lp_26

	.byte 73,139,70,16,72,139,248,190,125,0,0,0,131,56,0
call .Lp_5

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195,191,41,1,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 190,170,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,219,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType,.-Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType
.Lme_a:
.text 0
	.balign 16
.Lm_b:
	.local Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF
	.type Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF,@function
Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF:

	.byte 72,131,236,40,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,137,84,36,32,76,139,239,76
	.byte 139,246,76,139,250,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 69,51,228,233,90,0,0,0,72,141,173,0,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 69,133,228,126,20,73,139,69,16,72,139,248,190,44,0,0,0,131,56,0
call .Lp_5

	.byte 72,139,124,36,32
call .Lp_28

	.byte 76,139,208,73,139,254,73,139,244,73,139,6,255,80,176,72,139,240,73,139,255,65,255,87,24,65,255,196,72,139,124,36
	.byte 32
call .Lp_29

	.byte 76,139,208,73,139,254,73,139,6,255,144,104,255,255,255,68,59,224,124,143,76,139,36,36,76,139,108,36,8,76,139,116
	.byte 36,16,76,139,124,36,24,72,131,196,40,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF,.-Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF
.Lme_b:
.text 0
	.balign 16
.Lm_c:
	.local Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char
	.type Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char,@function
Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char:

	.byte 72,131,236,24,76,137,44,36,76,137,116,36,8,76,139,239,76,139,246,72,137,84,36,16,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,73,139,6,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 380
	.byte 255,80,160,72,139,240,73,139,253
call .Lp_16

	.byte 73,139,69,16,72,139,248,15,183,116,36,16,131,56,0
call .Lp_5

	.byte 73,139,254,73,139,6,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 388
	.byte 255,80,128,72,139,240,73,139,253
call .Lp_16

	.byte 76,139,44,36,76,139,116,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char,.-Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char
.Lme_c:
.text 0
	.balign 16
.Lm_d:
	.local Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType
	.type Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType,@function
Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,70,16,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 396
	.byte 72,139,248,131,56,0
call .Lp_30

	.byte 73,139,255,65,131,63,0
call .Lp_31

	.byte 72,139,240,73,139,254
call .Lp_16

	.byte 73,139,255,65,131,63,0
call .Lp_32

	.byte 72,15,182,192,133,192,15,132,23,0,0,0,73,139,255,65,131,63,0
call .Lp_33

	.byte 72,139,240,73,139,254
call .Lp_8

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType,.-Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType
.Lme_d:
.text 0
	.balign 16
.Lm_e:
	.local Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType
	.type Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType,@function
Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,73,139,119,96,73,139,254
call .Lp_16

	.byte 73,139,255,65,131,63,0
call .Lp_34

	.byte 72,15,182,192,133,192,15,132,27,0,0,0,73,139,70,16,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 404
	.byte 72,139,248,131,56,0
call .Lp_30

	.byte 233,194,0,0,0,73,139,70,16,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 412
	.byte 72,139,248,131,56,0
call .Lp_30

	.byte 73,139,255,65,131,63,0
call .Lp_35

	.byte 72,137,68,36,16,77,133,246,15,132,175,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 420
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,208,72,139,116,36,16,77,133,246,15,132,126,0,0,0,76,137,114,32,72,139,194,72,131,192,32,193,232,9,72
	.byte 37,255,255,127,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 428
	.byte 72,137,66,40,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 436
	.byte 72,137,66,64,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 444
	.byte 72,139,72,40,72,137,74,24,72,139,64,32,72,137,66,16,198,66,112,0,73,139,254
call .Lp_36

	.byte 73,139,70,16,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 452
	.byte 72,139,248,131,56,0
call .Lp_30

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195,190,147,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,196,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType,.-Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType
.Lme_e:
.text 0
	.balign 16
.Lm_f:
	.local Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition
	.type Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition,@function
Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition:

	.byte 72,131,236,24,76,137,44,36,76,137,124,36,8,76,139,239,72,137,116,36,16,76,139,250,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,69,16,72,139,248,15,183,116,36,16,131,56,0
call .Lp_5

	.byte 72,139,248,190,58,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,255,73,139,7,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 460
	.byte 255,80,176,72,139,240,73,139,253,51,210
call .Lp_6

	.byte 73,139,69,16,72,139,248,190,46,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,255,73,139,7,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 468
	.byte 255,144,120,255,255,255,72,139,240,73,139,253
call .Lp_37

	.byte 76,139,44,36,76,139,124,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition,.-Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition
.Lme_f:
.text 0
	.balign 16
.Lm_10:
	.local Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool
	.type Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool,@function
Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool:

	.byte 72,131,236,40,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,139,239,76,139,246,76,139,250
	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,73,139,6,255,144,160,0,0,0,72,133,192,15,132,45,0,0,0,73,139,254,73,139,6,255,144,160,0,0
	.byte 0,72,139,240,73,139,253,51,210
call .Lp_6

	.byte 73,139,69,16,72,139,248,190,46,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,254,73,139,6,255,144,176,1,0,0,76,139,224,77,133,228,116,16,51,192,73,99,76,36,16,59,193,115,5,69
	.byte 51,228,235,6,65,188,1,0,0,0,73,15,182,196,133,192,15,133,60,0,0,0,73,139,69,16,72,137,68,36,32,73
	.byte 139,254,73,139,6,255,144,176,1,0,0,72,139,240,72,139,68,36,32,72,139,248,131,56,0
call .Lp_30

	.byte 73,139,69,16,72,139,248,190,46,0,0,0,131,56,0
call .Lp_5

	.byte 73,139,254,73,139,6,255,144,184,0,0,0,76,139,240,69,133,255,15,132,44,0,0,0,73,139,254,190,96,0,0,0
	.byte 65,131,62,0
call .Lp_38

	.byte 76,139,248,133,192,126,20,73,139,254,51,246,73,139,215,65,131,62,0
call .Lp_39

	.byte 76,139,240,73,139,69,16,72,139,248,73,139,246,131,56,0
call .Lp_30

	.byte 76,139,36,36,76,139,108,36,8,76,139,116,36,16,76,139,124,36,24,72,131,196,40,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool,.-Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool
.Lme_10:
.text 0
	.balign 16
.Lm_11:
	.local Mono_Cecil_Rocks_DocCommentId_WriteItemName_string
	.type Mono_Cecil_Rocks_DocCommentId_WriteItemName_string,@function
Mono_Cecil_Rocks_DocCommentId_WriteItemName_string:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,64,16,72,137,68,36,16,72,139,124,36,8,190,46,0,0,0,186,35,0,0,0,72,139,68,36
	.byte 8,131,56,0
call .Lp_40

	.byte 72,139,248,190,60,0,0,0,186,123,0,0,0,131,56,0
call .Lp_40

	.byte 72,139,248,190,62,0,0,0,186,125,0,0,0,131,56,0
call .Lp_40

	.byte 72,139,240,72,139,68,36,16,72,139,248,131,56,0
call .Lp_30

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId_WriteItemName_string,.-Mono_Cecil_Rocks_DocCommentId_WriteItemName_string
.Lme_11:
.text 0
	.balign 16
.Lm_12:
	.local Mono_Cecil_Rocks_DocCommentId_ToString
	.type Mono_Cecil_Rocks_DocCommentId_ToString,@function
Mono_Cecil_Rocks_DocCommentId_ToString:

	.byte 72,131,236,8,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,64,16,72,139,248,72,139,0,255,80,72,72,131,196,8,195

	.size Mono_Cecil_Rocks_DocCommentId_ToString,.-Mono_Cecil_Rocks_DocCommentId_ToString
.Lme_12:
.text 0
	.balign 16
.Lm_13:
	.local Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition
	.type Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition,@function
Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition:

	.byte 72,131,236,40,76,137,44,36,76,137,116,36,8,76,137,124,36,16,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 199,68,36,24,0,0,0,0,77,133,255,15,132,200,1,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 476
	.byte 190,24,0,0,0
call .Lp_2

	.byte 72,137,68,36,32,72,139,248
call .Lp_41

	.byte 72,139,68,36,32,76,139,240,73,139,255,73,139,7,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 484
	.byte 255,80,128,137,68,36,24,139,68,36,24,76,139,232,65,129,229,0,0,0,255,73,139,197,61,0,0,0,4,15,135,28
	.byte 0,0,0,65,129,253,0,0,0,2,15,132,169,0,0,0,65,129,253,0,0,0,4,15,133,126,1,0,0,235,44,65
	.byte 129,253,0,0,0,6,15,132,86,0,0,0,65,129,253,0,0,0,20,15,132,183,0,0,0,65,129,253,0,0,0,23
	.byte 15,133,85,1,0,0,233,220,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139
	.byte 13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 492
	.byte 72,59,193,15,133,121,1,0,0,73,139,254,73,139,247,65,131,62,0
call .Lp_42

	.byte 233,215,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 500
	.byte 72,59,193,15,133,59,1,0,0,73,139,254,73,139,247,65,131,62,0
call .Lp_43

	.byte 233,160,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 508
	.byte 72,59,193,15,133,253,0,0,0,73,139,254,73,139,247,65,131,62,0
call .Lp_44

	.byte 233,105,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 516
	.byte 72,59,193,15,133,191,0,0,0,73,139,254,73,139,247,65,131,62,0
call .Lp_45

	.byte 233,50,0,0,0,77,133,255,116,30,73,139,7,72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 524
	.byte 72,59,193,15,133,121,0,0,0,73,139,254,73,139,247,65,131,62,0
call .Lp_46

	.byte 73,139,254,73,139,6,255,80,72,76,139,44,36,76,139,116,36,8,76,139,124,36,16,72,131,196,40,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,87,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 73,139,255,73,139,7,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 532
	.byte 255,144,120,255,255,255,72,139,240,191,41,1,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,142,0,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,197,0,0,0,235,239,190,252,0,0,0,235,232,190,51,1,0,0,235,225,190,106,1,0,0,235,218

	.size Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition,.-Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition
.Lme_13:
.text 0
	.balign 16
.Lm_14:
	.local Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition
	.type Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition,@function
Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition:

	.byte 72,131,236,24,76,137,60,36,72,137,124,36,8,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,73,139,119,24,72,139,124,36,8
call .Lp_16

	.byte 76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition,.-Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition
.Lme_14:
.text 0
	.balign 16
.Lm_15:
	.local Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension
	.type Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension,@function
Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension:

	.byte 72,131,236,40,76,137,60,36,76,139,255,72,137,116,36,16,72,137,84,36,24,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 199,68,36,8,0,0,0,0,199,68,36,12,0,0,0,0,72,141,68,36,16,72,99,8,137,76,36,8,72,99,64,4
	.byte 137,68,36,12,15,182,68,36,8,72,15,182,192,133,192,15,132,58,0,0,0,73,139,71,16,72,137,68,36,32,72,141
	.byte 68,36,16,72,99,8,137,76,36,8,72,99,64,4,137,68,36,12,72,141,124,36,8
call .Lp_47

	.byte 72,139,240,72,139,68,36,32,72,139,248,131,56,0
call .Lp_7

	.byte 73,139,71,16,72,139,248,190,58,0,0,0,131,56,0
call .Lp_5

	.byte 72,141,68,36,16,72,131,192,8,72,99,8,137,76,36,8,72,99,64,4,137,68,36,12,15,182,68,36,8,72,15,182
	.byte 192,133,192,15,132,86,0,0,0,73,139,71,16,72,137,68,36,32,72,141,68,36,16,72,131,192,8,72,99,8,137,76
	.byte 36,8,72,99,64,4,137,68,36,12,72,141,124,36,8
call .Lp_47

	.byte 72,139,240,72,139,68,36,32,72,141,76,36,16,72,99,17,137,84,36,8,72,99,73,4,137,76,36,12,255,193,43,241
	.byte 72,139,248,131,56,0
call .Lp_7

	.byte 76,139,60,36,72,131,196,40,195

	.size Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension,.-Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension
.Lme_15:
.text 0
	.balign 16
.Lm_16:
	.local Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF
	.type Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF,@function
Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF:

	.byte 72,131,236,56,76,137,60,36,76,137,84,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,124,36,8
call .Lp_48

	.byte 72,139,248,190,24,0,0,0
call .Lp_2

	.byte 72,137,68,36,48,72,139,248
call .Lp_49

	.byte 72,139,76,36,48,72,139,193,72,139,208,72,199,65,16,0,0,0,0,72,137,68,36,40,72,133,192,15,132,227,0,0
	.byte 0,72,139,124,36,8
call .Lp_50

	.byte 72,139,248,190,128,0,0,0
call .Lp_2

	.byte 72,139,200,72,139,68,36,40,72,133,192,15,132,172,0,0,0,72,137,65,32,72,137,76,36,32,72,131,193,32,193,233
	.byte 9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,137,68,36,16,72,139,124,36,8
call .Lp_51

	.byte 72,139,200,72,139,68,36,32,72,137,72,64,72,137,68,36,24,72,139,124,36,8
call .Lp_52

	.byte 72,139,116,36,24,72,139,72,8,72,137,78,40,72,139,72,40,72,137,78,24,72,139,64,32,72,137,70,16,198,70,112
	.byte 0,73,139,255,65,255,87,24,72,139,200,72,139,68,36,16,72,139,208,72,131,194,16,72,137,10,193,234,9,72,129,226
	.byte 255,255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,72,139,64,16,76,139,60,36,72,131,196,56,195,190,193,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,248,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF,.-Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF
.Lme_16:
.text 0
	.balign 16
.Lm_17:
	.local Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
	.type Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,@function
Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF:

	.byte 72,131,236,24,76,137,20,36,72,137,124,36,8,72,137,116,36,16,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,68,36,8,72,133,192,15,132,32,0,0,0,72,139,60,36
call .Lp_53

	.byte 76,139,208,72,139,124,36,8,72,139,116,36,16
call .Lp_54

	.byte 72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,101,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,.-Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
.Lme_17:
.text 0
	.balign 16
.Lm_18:
	.local Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
	.type Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,@function
Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF:

	.byte 72,131,236,40,76,137,20,36,72,137,124,36,8,72,137,116,36,16,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,60,36
call .Lp_55

	.byte 72,139,248,190,72,0,0,0
call .Lp_2

	.byte 72,137,68,36,24,72,139,248,72,190,254,255,255,255,255,255,255,255
call .Lp_56

	.byte 72,139,84,36,24,72,139,194,72,131,194,48,72,139,76,36,8,72,137,10,193,234,9,72,129,226,255,255,127,0,73,139
	.byte 53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,72,139,208,72,131,194,32,72,139,76,36,16,72,137,10,193,234,9,72,129,226,255,255,127,0,73
	.byte 139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,72,131,196,40,195

	.size Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,.-Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
.Lme_18:
.text 0
	.balign 16
.Lm_29:
	.local Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.type Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,@function
Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor:

	.byte 72,131,236,40,76,137,44,36,76,137,116,36,8,76,139,247,72,137,116,36,16,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 540
	.byte 190,24,0,0,0
call .Lp_2

	.byte 72,139,200,76,139,233,72,131,193,16,72,139,68,36,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,77,133,246,15,132,32,1,0,0,73,139,69,16,72,133,192,15,132,219,0,0,0,73,139,254,65
	.byte 131,62,0
call .Lp_57

	.byte 72,15,182,192,133,192,15,132,233,0,0,0,73,139,254,65,131,62,0
call .Lp_58

	.byte 72,15,182,192,133,192,15,132,209,0,0,0,73,139,254,73,139,6,255,144,144,0,0,0,72,137,68,36,24,77,133,237
	.byte 15,132,254,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 548
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,208,72,139,68,36,24,77,133,237,15,132,205,0,0,0,76,137,106,32,72,139,202,72,131,193,32,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,206,198,1,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 556
	.byte 72,137,74,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 564
	.byte 72,137,74,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 572
	.byte 72,139,113,40,72,137,114,24,72,139,73,32,72,137,74,16,198,66,112,0,72,139,248,73,139,246,131,56,0
call .Lp_59

	.byte 76,139,44,36,76,139,116,36,8,72,131,196,40,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,129,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 191,187,0,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,115,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,226,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,19,1,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,.-Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
.Lme_29:
.text 0
	.balign 16
.Lm_2a:
	.local Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.type Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,@function
Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor:

	.byte 72,131,236,40,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,73,139,247
call .Lp_60

	.byte 76,139,248,72,139,200,131,57,0,76,139,112,16,73,139,198,72,139,248,72,139,0,255,144,8,1,0,0,72,15,182,192
	.byte 76,15,182,232,73,139,197,76,139,224,65,131,228,3,73,139,196,131,248,2,116,12,65,131,252,3,15,133,92,0,0,0
	.byte 235,16,73,139,253,193,255,2,73,139,247
call .Lp_61

	.byte 235,30,73,139,254,72,190,255,255,255,255,255,255,255,255,65,131,62,0
call .Lp_62

	.byte 73,139,255
call .Lp_63

	.byte 65,131,63,0,73,99,119,48,73,139,254,65,131,62,0
call .Lp_64

	.byte 76,139,36,36,76,139,108,36,8,76,139,116,36,16,76,139,124,36,24,72,131,196,40,195,191,41,1,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,.-Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
.Lme_2a:
.text 0
	.balign 16
.Lm_2b:
	.local Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.type Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,@function
Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor:

	.byte 72,131,236,56,72,137,28,36,76,137,108,36,8,76,137,116,36,16,76,139,247,72,137,116,36,32,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,73,139,6,255,144,144,0,0,0,72,139,208,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 580
	.byte 72,139,0,72,139,200,76,139,234,76,137,116,36,24,72,139,217,72,133,192,15,133,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 588
	.byte 72,139,0,72,137,68,36,40,72,133,192,15,132,94,1,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 596
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,40,72,133,201,15,132,48,1,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 604
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 612
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 620
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 580
	.byte 72,137,1,72,139,216,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 628
	.byte 65,131,125,0,0,73,139,253,72,139,116,36,24,72,139,211
call .Lp_65

	.byte 76,139,232,72,139,248,73,139,246,131,56,0
call .Lp_66

	.byte 76,139,240,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 636
	.byte 190,56,0,0,0
call .Lp_2

	.byte 131,56,0,72,139,200,72,131,193,16,76,137,41,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,131,56,0,68,137,112,48,73,139,77,72,131,56,0,72,139,208,72,131,194,24,72,137,10,193,234
	.byte 9,72,129,226,255,255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,131,56,0,72,139,208,72,131,194,40,72,139,76,36,32,72,137,10,193,234,9,72,129,226,255,255
	.byte 127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,72,139,28,36,76,139,108,36,8,76,139,116,36,16,72,131,196,56,195,190,69,1,0,0,191,42
	.byte 1,0,0
call .Lp_19

	.byte 190,115,1,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,.-Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
.Lme_2b:
.text 0
	.balign 16
.Lm_2c:
	.local Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext
	.type Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext,@function
Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext:

	.byte 72,131,236,72,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,77,139,119,16,73,139,198,72,139,248,190,4,0,0,0,131,56,0
call .Lp_62

	.byte 73,139,254,73,139,6,255,144,224,0,0,0,72,137,68,36,64,73,139,254,65,131,62,0
call .Lp_67

	.byte 72,139,76,36,64,137,68,36,48,137,68,36,24,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 644
	.byte 72,99,0,137,68,36,16,72,99,68,36,24,137,68,36,40,72,99,68,36,16,137,68,36,32,139,68,36,40,139,84,36
	.byte 32,59,194,64,15,148,192,72,15,182,192,133,192,64,15,148,192,72,15,182,192,72,15,182,192,137,76,36,56,133,192,15
	.byte 132,51,0,0,0,73,139,254,72,139,116,36,48,65,131,62,0
call .Lp_68

	.byte 65,131,63,0,73,141,79,32,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,99,124,36,56,73,139,247
call .Lp_61

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,72,195

	.size Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext,.-Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext
.Lme_2c:
.text 0
	.balign 16
.Lm_2d:
	.local Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext
	.type Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext,@function
Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext:

	.byte 72,129,236,72,1,0,0,72,137,28,36,72,137,108,36,8,76,137,100,36,16,76,137,108,36,24,76,137,116,36,32,76
	.byte 137,124,36,40,76,139,247,72,137,180,36,56,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 198,132,36,16,1,0,0,0,198,132,36,17,1,0,0,0,198,132,36,18,1,0,0,0,198,132,36,19,1,0,0,0
	.byte 198,132,36,20,1,0,0,0,198,132,36,21,1,0,0,0,198,132,36,22,1,0,0,0,198,132,36,23,1,0,0,0
	.byte 199,132,36,8,1,0,0,0,0,0,0,72,139,132,36,56,1,0,0,131,56,0,76,139,104,16,131,56,0,76,139,96
	.byte 24,131,56,0,72,139,88,40,73,139,253,65,131,125,0,0
call .Lp_69

	.byte 72,139,232,65,3,238,233,215,19,0,0,72,141,100,36,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,253,73,139,69,0,255,144,8,1,0,0,72,15,182,192,76,15,182,240,73,139,198,61,254,0,0,0,15,133,171
	.byte 0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 652
	.byte 72,139,0,72,137,132,36,64,1,0,0,73,139,253,73,139,69,0,255,144,8,1,0,0,72,139,200,72,139,132,36,64
	.byte 1,0,0,72,15,182,201,72,99,201,57,72,24,15,134,206,19,0,0,72,141,68,200,32,72,15,190,8,64,136,140,36
	.byte 0,1,0,0,72,15,190,72,1,64,136,140,36,1,1,0,0,72,15,190,72,2,64,136,140,36,2,1,0,0,72,15
	.byte 190,72,3,64,136,140,36,3,1,0,0,72,15,190,72,4,64,136,140,36,4,1,0,0,72,15,190,72,5,64,136,140
	.byte 36,5,1,0,0,72,15,190,72,6,64,136,140,36,6,1,0,0,72,15,190,64,7,64,136,132,36,7,1,0,0,233
	.byte 130,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 660
	.byte 72,139,0,73,99,206,57,72,24,15,134,64,19,0,0,72,141,68,200,32,72,15,190,8,64,136,140,36,0,1,0,0
	.byte 72,15,190,72,1,64,136,140,36,1,1,0,0,72,15,190,72,2,64,136,140,36,2,1,0,0,72,15,190,72,3,64
	.byte 136,140,36,3,1,0,0,72,15,190,72,4,64,136,140,36,4,1,0,0,72,15,190,72,5,64,136,140,36,5,1,0
	.byte 0,72,15,190,72,6,64,136,140,36,6,1,0,0,72,15,190,64,7,64,136,132,36,7,1,0,0,72,15,190,132,36
	.byte 0,1,0,0,64,136,132,36,16,1,0,0,72,15,190,132,36,1,1,0,0,64,136,132,36,17,1,0,0,72,15,190
	.byte 132,36,2,1,0,0,64,136,132,36,18,1,0,0,72,15,190,132,36,3,1,0,0,64,136,132,36,19,1,0,0,72
	.byte 15,190,132,36,4,1,0,0,64,136,132,36,20,1,0,0,72,15,190,132,36,5,1,0,0,64,136,132,36,21,1,0
	.byte 0,72,15,190,132,36,6,1,0,0,64,136,132,36,22,1,0,0,72,15,190,132,36,7,1,0,0,64,136,132,36,23
	.byte 1,0,0,68,15,182,180,36,21,1,0,0,76,137,180,36,24,1,0,0,73,139,198,131,248,20,15,131,201,17,0,0
	.byte 72,139,132,36,24,1,0,0,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 668
	.byte 72,3,193,72,139,0,255,224,72,15,190,132,36,16,1,0,0,64,136,132,36,224,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,225,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,226,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,227,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,228,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,229,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,230,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,231,0,0,0,72,139,251,72,139,180,36,224,0,0,0,72,139,3,77,139
	.byte 21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 676
	.byte 255,80,184,233,7,17,0,0,73,139,253,73,139,69,0,255,144,224,0,0,0,76,139,248,73,139,247,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 684
call .Lp_70

	.byte 76,139,240,199,132,36,48,1,0,0,0,0,0,0,233,84,0,0,0,102,102,144,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,253,73,139,69,0,255,144,224,0,0,0,72,139,200,72,99,132,36,48,1,0,0,72,99,192,65,57,70,24,15
	.byte 134,240,16,0,0,73,141,68,134,32,137,8,72,99,132,36,48,1,0,0,255,192,137,132,36,48,1,0,0,68,57,188
	.byte 36,48,1,0,0,124,165,72,15,190,132,36,16,1,0,0,64,136,132,36,216,0,0,0,72,15,190,132,36,17,1,0
	.byte 0,64,136,132,36,217,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,218,0,0,0,72,15,190,132,36,19
	.byte 1,0,0,64,136,132,36,219,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,220,0,0,0,72,15,190,132
	.byte 36,21,1,0,0,64,136,132,36,221,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,222,0,0,0,72,15
	.byte 190,132,36,23,1,0,0,64,136,132,36,223,0,0,0,72,139,251,73,139,214,72,139,180,36,216,0,0,0,72,139,3
	.byte 77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 692
	.byte 255,80,136,233,207,15,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,208,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,209,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,210,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,211,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,212,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,213,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,214,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,215,0,0,0,73,139,253,73,139,69,0,255,144,0,1,0,0,72,15,190
	.byte 208,72,139,251,72,139,180,36,208,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 700
	.byte 255,80,224,233,25,15,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,200,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,201,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,202,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,203,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,204,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,205,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,206,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,207,0,0,0,73,139,253,73,139,69,0,255,144,224,0,0,0,72,139,208
	.byte 72,139,251,72,139,180,36,200,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 700
	.byte 255,80,224,233,100,14,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,192,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,193,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,194,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,195,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,196,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,197,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,198,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,199,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 708
	.byte 72,15,190,8,64,136,140,36,184,0,0,0,72,15,190,72,1,64,136,140,36,185,0,0,0,72,15,190,72,2,64,136
	.byte 140,36,186,0,0,0,72,15,190,72,3,64,136,140,36,187,0,0,0,72,15,190,72,4,64,136,140,36,188,0,0,0
	.byte 72,15,190,72,5,64,136,140,36,189,0,0,0,72,15,190,72,6,64,136,140,36,190,0,0,0,72,15,190,64,7,64
	.byte 136,132,36,191,0,0,0,72,139,180,36,184,0,0,0,72,139,188,36,192,0,0,0
call .Lp_71

	.byte 72,15,182,192,133,192,15,132,182,0,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,176,0,0,0,72,15,190
	.byte 132,36,17,1,0,0,64,136,132,36,177,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,178,0,0,0,72
	.byte 15,190,132,36,19,1,0,0,64,136,132,36,179,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,180,0,0
	.byte 0,72,15,190,132,36,21,1,0,0,64,136,132,36,181,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,182
	.byte 0,0,0,72,15,190,132,36,23,1,0,0,64,136,132,36,183,0,0,0,73,139,253,73,139,69,0,255,144,0,1,0
	.byte 0,72,15,190,208,72,139,251,72,139,180,36,176,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 716
	.byte 255,80,224,233,151,12,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,168,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,169,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,170,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,171,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,172,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,173,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,174,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,175,0,0,0,73,139,253,73,139,69,0,255,144,8,1,0,0,72,15,182
	.byte 208,72,139,251,72,139,180,36,168,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 724
	.byte 255,80,200,233,225,11,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,160,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,161,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,162,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,163,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,164,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,165,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,166,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,167,0,0,0,73,139,253,73,139,69,0,255,144,224,0,0,0,72,139,208
	.byte 72,139,251,72,139,180,36,160,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 732
	.byte 255,80,224,233,44,11,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,152,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,153,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,154,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,155,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,156,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,157,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,158,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,159,0,0,0,73,139,253,73,139,69,0,255,144,208,0,0,0,72,139,208
	.byte 72,139,251,72,139,180,36,152,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 740
	.byte 255,80,248,233,119,10,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,144,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,145,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,146,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,147,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,148,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,149,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,150,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,151,0,0,0,73,139,253,73,139,69,0,255,144,192,0,0,0,72,139,251
	.byte 72,139,180,36,144,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 748
	.byte 255,80,192,233,197,9,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,136,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,137,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,138,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,139,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,140,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,141,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,142,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,143,0,0,0,73,139,253,73,139,69,0,255,144,184,0,0,0,72,139,251
	.byte 72,139,180,36,136,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 756
	.byte 255,80,232,233,19,9,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,128,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,129,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,130,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,131,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,132,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,133,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,134,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,135,0,0,0,73,139,253,65,131,125,0,0
call .Lp_67

	.byte 137,68,36,120,73,139,253,72,139,116,36,120,65,131,125,0,0
call .Lp_72

	.byte 72,139,208,72,139,251,72,139,180,36,128,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 764
	.byte 255,80,240,233,72,8,0,0,72,15,190,132,36,16,1,0,0,64,136,68,36,112,72,15,190,132,36,17,1,0,0,64
	.byte 136,68,36,113,72,15,190,132,36,18,1,0,0,64,136,68,36,114,72,15,190,132,36,19,1,0,0,64,136,68,36,115
	.byte 72,15,190,132,36,20,1,0,0,64,136,68,36,116,72,15,190,132,36,21,1,0,0,64,136,68,36,117,72,15,190,132
	.byte 36,22,1,0,0,64,136,68,36,118,72,15,190,132,36,23,1,0,0,64,136,68,36,119,73,139,253,65,131,125,0,0
call .Lp_67

	.byte 137,68,36,104,73,139,253,72,139,116,36,104,65,131,125,0,0
call .Lp_73

	.byte 72,139,208,72,139,251,72,139,116,36,112,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 772
	.byte 255,144,104,255,255,255,233,149,7,0,0,72,15,190,132,36,16,1,0,0,64,136,68,36,96,72,15,190,132,36,17,1
	.byte 0,0,64,136,68,36,97,72,15,190,132,36,18,1,0,0,64,136,68,36,98,72,15,190,132,36,19,1,0,0,64,136
	.byte 68,36,99,72,15,190,132,36,20,1,0,0,64,136,68,36,100,72,15,190,132,36,21,1,0,0,64,136,68,36,101,72
	.byte 15,190,132,36,22,1,0,0,64,136,68,36,102,72,15,190,132,36,23,1,0,0,64,136,68,36,103,73,139,253,73,139
	.byte 69,0,255,144,8,1,0,0,72,15,182,240,73,139,253,65,131,125,0,0
call .Lp_74

	.byte 72,139,208,72,139,251,72,139,116,36,96,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 780
	.byte 255,80,192,233,234,6,0,0,72,15,190,132,36,16,1,0,0,64,136,68,36,88,72,15,190,132,36,17,1,0,0,64
	.byte 136,68,36,89,72,15,190,132,36,18,1,0,0,64,136,68,36,90,72,15,190,132,36,19,1,0,0,64,136,68,36,91
	.byte 72,15,190,132,36,20,1,0,0,64,136,68,36,92,72,15,190,132,36,21,1,0,0,64,136,68,36,93,72,15,190,132
	.byte 36,22,1,0,0,64,136,68,36,94,72,15,190,132,36,23,1,0,0,64,136,68,36,95,73,139,253,73,139,69,0,255
	.byte 144,240,0,0,0,72,15,191,240,73,139,253,65,131,125,0,0
call .Lp_74

	.byte 72,139,208,72,139,251,72,139,116,36,88,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 780
	.byte 255,80,192,233,63,6,0,0,72,15,190,132,36,16,1,0,0,64,136,68,36,80,72,15,190,132,36,17,1,0,0,64
	.byte 136,68,36,81,72,15,190,132,36,18,1,0,0,64,136,68,36,82,72,15,190,132,36,19,1,0,0,64,136,68,36,83
	.byte 72,15,190,132,36,20,1,0,0,64,136,68,36,84,72,15,190,132,36,21,1,0,0,64,136,68,36,85,72,15,190,132
	.byte 36,22,1,0,0,64,136,68,36,86,72,15,190,132,36,23,1,0,0,64,136,68,36,87,73,139,253,73,139,69,0,255
	.byte 144,8,1,0,0,72,15,182,240,72,139,188,36,56,1,0,0
call .Lp_75

	.byte 72,139,208,72,139,251,72,139,116,36,80,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 788
	.byte 255,80,144,233,148,5,0,0,72,15,190,132,36,16,1,0,0,64,136,68,36,72,72,15,190,132,36,17,1,0,0,64
	.byte 136,68,36,73,72,15,190,132,36,18,1,0,0,64,136,68,36,74,72,15,190,132,36,19,1,0,0,64,136,68,36,75
	.byte 72,15,190,132,36,20,1,0,0,64,136,68,36,76,72,15,190,132,36,21,1,0,0,64,136,68,36,77,72,15,190,132
	.byte 36,22,1,0,0,64,136,68,36,78,72,15,190,132,36,23,1,0,0,64,136,68,36,79,73,139,253,73,139,69,0,255
	.byte 144,240,0,0,0,72,15,191,240,72,139,188,36,56,1,0,0
call .Lp_75

	.byte 72,139,208,72,139,251,72,139,116,36,72,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 788
	.byte 255,80,144,233,233,4,0,0,73,139,253,65,131,125,0,0
call .Lp_67

	.byte 137,68,36,64,73,139,252,72,139,116,36,64,65,131,60,36,0
call .Lp_76

	.byte 76,139,240,72,139,248,72,139,0,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 484
	.byte 255,80,128,137,132,36,8,1,0,0,139,132,36,8,1,0,0,37,0,0,0,255,137,132,36,32,1,0,0,61,0,0
	.byte 0,4,15,135,56,0,0,0,129,188,36,32,1,0,0,0,0,0,1,15,132,126,0,0,0,129,188,36,32,1,0,0
	.byte 0,0,0,2,15,132,109,0,0,0,129,188,36,32,1,0,0,0,0,0,4,15,132,245,1,0,0,233,86,4,0,0
	.byte 129,188,36,32,1,0,0,0,0,0,10,119,39,129,188,36,32,1,0,0,0,0,0,6,15,132,7,1,0,0,129,188
	.byte 36,32,1,0,0,0,0,0,10,15,132,140,2,0,0,233,34,4,0,0,129,188,36,32,1,0,0,0,0,0,27,116
	.byte 22,129,188,36,32,1,0,0,0,0,0,43,15,132,211,0,0,0,233,255,3,0,0,72,15,190,132,36,16,1,0,0
	.byte 64,136,132,36,248,0,0,0,72,15,190,132,36,17,1,0,0,64,136,132,36,249,0,0,0,72,15,190,132,36,18,1
	.byte 0,0,64,136,132,36,250,0,0,0,72,15,190,132,36,19,1,0,0,64,136,132,36,251,0,0,0,72,15,190,132,36
	.byte 20,1,0,0,64,136,132,36,252,0,0,0,72,15,190,132,36,21,1,0,0,64,136,132,36,253,0,0,0,72,15,190
	.byte 132,36,22,1,0,0,64,136,132,36,254,0,0,0,72,15,190,132,36,23,1,0,0,64,136,132,36,255,0,0,0,77
	.byte 133,246,116,30,73,139,6,72,139,0,72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 796
	.byte 72,59,193,15,133,164,3,0,0,72,139,251,73,139,214,72,139,180,36,248,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 804
	.byte 255,144,112,255,255,255,233,49,3,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,240,0,0,0,72,15,190,132
	.byte 36,17,1,0,0,64,136,132,36,241,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,242,0,0,0,72,15
	.byte 190,132,36,19,1,0,0,64,136,132,36,243,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,244,0,0,0
	.byte 72,15,190,132,36,21,1,0,0,64,136,132,36,245,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,246,0
	.byte 0,0,72,15,190,132,36,23,1,0,0,64,136,132,36,247,0,0,0,77,133,246,116,30,73,139,6,72,139,0,72,139
	.byte 64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 812
	.byte 72,59,193,15,133,207,2,0,0,72,139,251,73,139,214,72,139,180,36,240,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 820
	.byte 255,80,168,233,102,2,0,0,72,15,190,132,36,16,1,0,0,64,136,132,36,232,0,0,0,72,15,190,132,36,17,1
	.byte 0,0,64,136,132,36,233,0,0,0,72,15,190,132,36,18,1,0,0,64,136,132,36,234,0,0,0,72,15,190,132,36
	.byte 19,1,0,0,64,136,132,36,235,0,0,0,72,15,190,132,36,20,1,0,0,64,136,132,36,236,0,0,0,72,15,190
	.byte 132,36,21,1,0,0,64,136,132,36,237,0,0,0,72,15,190,132,36,22,1,0,0,64,136,132,36,238,0,0,0,72
	.byte 15,190,132,36,23,1,0,0,64,136,132,36,239,0,0,0,77,133,246,116,30,73,139,6,72,139,0,72,139,64,16,72
	.byte 139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 828
	.byte 72,59,193,15,133,245,1,0,0,72,139,251,73,139,214,72,139,180,36,232,0,0,0,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 836
	.byte 255,80,200,233,155,1,0,0,77,139,254,77,133,246,116,29,73,139,6,72,139,0,72,139,64,16,72,139,64,16,73,139
	.byte 13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 828
	.byte 72,59,193,116,3,69,51,255,76,137,188,36,40,1,0,0,73,139,199,72,133,192,15,132,146,0,0,0,72,15,190,132
	.byte 36,16,1,0,0,64,136,68,36,56,72,15,190,132,36,17,1,0,0,64,136,68,36,57,72,15,190,132,36,18,1,0
	.byte 0,64,136,68,36,58,72,15,190,132,36,19,1,0,0,64,136,68,36,59,72,15,190,132,36,20,1,0,0,64,136,68
	.byte 36,60,72,15,190,132,36,21,1,0,0,64,136,68,36,61,72,15,190,132,36,22,1,0,0,64,136,68,36,62,72,15
	.byte 190,132,36,23,1,0,0,64,136,68,36,63,72,139,251,72,139,148,36,40,1,0,0,72,139,116,36,56,72,139,3,77
	.byte 139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 836
	.byte 255,80,200,233,208,0,0,0,77,139,254,77,133,246,116,29,73,139,6,72,139,0,72,139,64,16,72,139,64,16,73,139
	.byte 13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 812
	.byte 72,59,193,116,3,69,51,255,77,139,247,77,133,255,15,132,141,0,0,0,72,15,190,132,36,16,1,0,0,64,136,68
	.byte 36,48,72,15,190,132,36,17,1,0,0,64,136,68,36,49,72,15,190,132,36,18,1,0,0,64,136,68,36,50,72,15
	.byte 190,132,36,19,1,0,0,64,136,68,36,51,72,15,190,132,36,20,1,0,0,64,136,68,36,52,72,15,190,132,36,21
	.byte 1,0,0,64,136,68,36,53,72,15,190,132,36,22,1,0,0,64,136,68,36,54,72,15,190,132,36,23,1,0,0,64
	.byte 136,68,36,55,72,139,251,73,139,214,72,139,116,36,48,72,139,3,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 820
	.byte 255,80,168,233,18,0,0,0,191,20,1,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 73,139,253,65,131,125,0,0
call .Lp_69

	.byte 59,197,15,140,25,236,255,255,72,139,28,36,72,139,108,36,8,76,139,100,36,16,76,139,108,36,24,76,139,116,36,32
	.byte 76,139,124,36,40,72,129,196,72,1,0,0,195,190,10,2,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,213,2,0,0,235,239,190,163,3,0,0,235,232,190,5,17,0,0,191,14,1,0,0
call .Lp_19

	.byte 190,70,19,0,0,235,239,190,205,19,0,0,235,232

	.size Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext,.-Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext
.Lme_2d:
.text 0
	.balign 16
.Lm_2e:
	.local Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int
	.type Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int,@function
Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int:

	.byte 72,131,236,24,76,137,52,36,76,139,247,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,62,0,73,139,70,32,72,139,248,72,99,116,36,8,131,56,0
call .Lp_77

	.byte 76,139,52,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int,.-Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int
.Lme_2e:
.text 0
	.balign 16
.Lm_2f:
	.local Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody:

	.byte 85,72,139,236,72,129,236,192,1,0,0,76,137,101,224,76,137,109,232,76,137,117,240,76,137,125,248,76,139,255,73,139
	.byte 5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,133,104,254,255,255,72,137,133,112,254,255,255,72,137,133,120,254,255,255,198,133,128,254,255,255,0,198,133
	.byte 129,254,255,255,0,198,133,130,254,255,255,0,198,133,131,254,255,255,0,198,133,132,254,255,255,0,198,133,133,254,255,255
	.byte 0,198,133,134,254,255,255,0,198,133,135,254,255,255,0,77,133,255,15,132,108,40,0,0,73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,245,72,129,198,104,254,255,255,72,139,248,131,56,0
call .Lp_79

	.byte 233,166,39,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 76,139,181,112,254,255,255,73,139,198,72,139,200,131,57,0,72,131,192,44,72,15,190,8,64,136,141,128,254,255,255,72
	.byte 15,190,72,1,64,136,141,129,254,255,255,72,15,190,72,2,64,136,141,130,254,255,255,72,15,190,72,3,64,136,141,131
	.byte 254,255,255,72,15,190,72,4,64,136,141,132,254,255,255,72,15,190,72,5,64,136,141,133,254,255,255,72,15,190,72,6
	.byte 64,136,141,134,254,255,255,72,15,190,64,7,64,136,133,135,254,255,255,15,182,133,132,254,255,255,131,248,1,15,133,8
	.byte 39,0,0,65,131,62,0,73,141,70,44,72,15,190,8,64,136,141,128,254,255,255,72,15,190,72,1,64,136,141,129,254
	.byte 255,255,72,15,190,72,2,64,136,141,130,254,255,255,72,15,190,72,3,64,136,141,131,254,255,255,72,15,190,72,4,64
	.byte 136,141,132,254,255,255,72,15,190,72,5,64,136,141,133,254,255,255,72,15,190,72,6,64,136,141,134,254,255,255,72,15
	.byte 190,64,7,64,136,133,135,254,255,255,68,15,182,173,130,254,255,255,73,139,197,76,139,224,65,131,236,2,65,131,252,53
	.byte 115,24,73,139,196,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 852
	.byte 72,3,193,72,139,0,255,224,65,129,253,188,0,0,0,15,132,199,37,0,0,233,95,38,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 860
	.byte 72,15,190,8,64,136,141,136,254,255,255,72,15,190,72,1,64,136,141,137,254,255,255,72,15,190,72,2,64,136,141,138
	.byte 254,255,255,72,15,190,72,3,64,136,141,139,254,255,255,72,15,190,72,4,64,136,141,140,254,255,255,72,15,190,72,5
	.byte 64,136,141,141,254,255,255,72,15,190,72,6,64,136,141,142,254,255,255,72,15,190,64,7,64,136,133,143,254,255,255,73
	.byte 139,255,51,246
call .Lp_80

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,136,254,255,255,64,136,17,72,15,190,149,137,254,255,255,64,136,81,1,72
	.byte 15,190,149,138,254,255,255,64,136,81,2,72,15,190,149,139,254,255,255,64,136,81,3,72,15,190,149,140,254,255,255,64
	.byte 136,81,4,72,15,190,149,141,254,255,255,64,136,81,5,72,15,190,149,142,254,255,255,64,136,81,6,72,15,190,149,143
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,97,37,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 860
	.byte 72,15,190,8,64,136,141,144,254,255,255,72,15,190,72,1,64,136,141,145,254,255,255,72,15,190,72,2,64,136,141,146
	.byte 254,255,255,72,15,190,72,3,64,136,141,147,254,255,255,72,15,190,72,4,64,136,141,148,254,255,255,72,15,190,72,5
	.byte 64,136,141,149,254,255,255,72,15,190,72,6,64,136,141,150,254,255,255,72,15,190,64,7,64,136,133,151,254,255,255,73
	.byte 139,255,190,1,0,0,0
call .Lp_80

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,144,254,255,255,64,136,17,72,15,190,149,145,254,255,255,64,136,81,1,72
	.byte 15,190,149,146,254,255,255,64,136,81,2,72,15,190,149,147,254,255,255,64,136,81,3,72,15,190,149,148,254,255,255,64
	.byte 136,81,4,72,15,190,149,149,254,255,255,64,136,81,5,72,15,190,149,150,254,255,255,64,136,81,6,72,15,190,149,151
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,96,36,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 860
	.byte 72,15,190,8,64,136,141,152,254,255,255,72,15,190,72,1,64,136,141,153,254,255,255,72,15,190,72,2,64,136,141,154
	.byte 254,255,255,72,15,190,72,3,64,136,141,155,254,255,255,72,15,190,72,4,64,136,141,156,254,255,255,72,15,190,72,5
	.byte 64,136,141,157,254,255,255,72,15,190,72,6,64,136,141,158,254,255,255,72,15,190,64,7,64,136,133,159,254,255,255,73
	.byte 139,255,190,2,0,0,0
call .Lp_80

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,152,254,255,255,64,136,17,72,15,190,149,153,254,255,255,64,136,81,1,72
	.byte 15,190,149,154,254,255,255,64,136,81,2,72,15,190,149,155,254,255,255,64,136,81,3,72,15,190,149,156,254,255,255,64
	.byte 136,81,4,72,15,190,149,157,254,255,255,64,136,81,5,72,15,190,149,158,254,255,255,64,136,81,6,72,15,190,149,159
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,95,35,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 860
	.byte 72,15,190,8,64,136,141,160,254,255,255,72,15,190,72,1,64,136,141,161,254,255,255,72,15,190,72,2,64,136,141,162
	.byte 254,255,255,72,15,190,72,3,64,136,141,163,254,255,255,72,15,190,72,4,64,136,141,164,254,255,255,72,15,190,72,5
	.byte 64,136,141,165,254,255,255,72,15,190,72,6,64,136,141,166,254,255,255,72,15,190,64,7,64,136,133,167,254,255,255,73
	.byte 139,255,190,3,0,0,0
call .Lp_80

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,160,254,255,255,64,136,17,72,15,190,149,161,254,255,255,64,136,81,1,72
	.byte 15,190,149,162,254,255,255,64,136,81,2,72,15,190,149,163,254,255,255,64,136,81,3,72,15,190,149,164,254,255,255,64
	.byte 136,81,4,72,15,190,149,165,254,255,255,64,136,81,5,72,15,190,149,166,254,255,255,64,136,81,6,72,15,190,149,167
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,94,34,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 868
	.byte 72,15,190,8,64,136,141,168,254,255,255,72,15,190,72,1,64,136,141,169,254,255,255,72,15,190,72,2,64,136,141,170
	.byte 254,255,255,72,15,190,72,3,64,136,141,171,254,255,255,72,15,190,72,4,64,136,141,172,254,255,255,72,15,190,72,5
	.byte 64,136,141,173,254,255,255,72,15,190,72,6,64,136,141,174,254,255,255,72,15,190,64,7,64,136,133,175,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,51,246,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,168,254,255,255,64,136,17,72,15,190,149,169,254,255,255,64,136,81,1,72
	.byte 15,190,149,170,254,255,255,64,136,81,2,72,15,190,149,171,254,255,255,64,136,81,3,72,15,190,149,172,254,255,255,64
	.byte 136,81,4,72,15,190,149,173,254,255,255,64,136,81,5,72,15,190,149,174,254,255,255,64,136,81,6,72,15,190,149,175
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,81,33,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 868
	.byte 72,15,190,8,64,136,141,176,254,255,255,72,15,190,72,1,64,136,141,177,254,255,255,72,15,190,72,2,64,136,141,178
	.byte 254,255,255,72,15,190,72,3,64,136,141,179,254,255,255,72,15,190,72,4,64,136,141,180,254,255,255,72,15,190,72,5
	.byte 64,136,141,181,254,255,255,72,15,190,72,6,64,136,141,182,254,255,255,72,15,190,64,7,64,136,133,183,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,1,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,176,254,255,255,64,136,17,72,15,190,149,177,254,255,255,64,136,81,1,72
	.byte 15,190,149,178,254,255,255,64,136,81,2,72,15,190,149,179,254,255,255,64,136,81,3,72,15,190,149,180,254,255,255,64
	.byte 136,81,4,72,15,190,149,181,254,255,255,64,136,81,5,72,15,190,149,182,254,255,255,64,136,81,6,72,15,190,149,183
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,65,32,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 868
	.byte 72,15,190,8,64,136,141,184,254,255,255,72,15,190,72,1,64,136,141,185,254,255,255,72,15,190,72,2,64,136,141,186
	.byte 254,255,255,72,15,190,72,3,64,136,141,187,254,255,255,72,15,190,72,4,64,136,141,188,254,255,255,72,15,190,72,5
	.byte 64,136,141,189,254,255,255,72,15,190,72,6,64,136,141,190,254,255,255,72,15,190,64,7,64,136,133,191,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,2,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,184,254,255,255,64,136,17,72,15,190,149,185,254,255,255,64,136,81,1,72
	.byte 15,190,149,186,254,255,255,64,136,81,2,72,15,190,149,187,254,255,255,64,136,81,3,72,15,190,149,188,254,255,255,64
	.byte 136,81,4,72,15,190,149,189,254,255,255,64,136,81,5,72,15,190,149,190,254,255,255,64,136,81,6,72,15,190,149,191
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,49,31,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 868
	.byte 72,15,190,8,64,136,141,192,254,255,255,72,15,190,72,1,64,136,141,193,254,255,255,72,15,190,72,2,64,136,141,194
	.byte 254,255,255,72,15,190,72,3,64,136,141,195,254,255,255,72,15,190,72,4,64,136,141,196,254,255,255,72,15,190,72,5
	.byte 64,136,141,197,254,255,255,72,15,190,72,6,64,136,141,198,254,255,255,72,15,190,64,7,64,136,133,199,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,3,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,192,254,255,255,64,136,17,72,15,190,149,193,254,255,255,64,136,81,1,72
	.byte 15,190,149,194,254,255,255,64,136,81,2,72,15,190,149,195,254,255,255,64,136,81,3,72,15,190,149,196,254,255,255,64
	.byte 136,81,4,72,15,190,149,197,254,255,255,64,136,81,5,72,15,190,149,198,254,255,255,64,136,81,6,72,15,190,149,199
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,33,30,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 876
	.byte 72,15,190,8,64,136,141,200,254,255,255,72,15,190,72,1,64,136,141,201,254,255,255,72,15,190,72,2,64,136,141,202
	.byte 254,255,255,72,15,190,72,3,64,136,141,203,254,255,255,72,15,190,72,4,64,136,141,204,254,255,255,72,15,190,72,5
	.byte 64,136,141,205,254,255,255,72,15,190,72,6,64,136,141,206,254,255,255,72,15,190,64,7,64,136,133,207,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,51,246,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,200,254,255,255,64,136,17,72,15,190,149,201,254,255,255,64,136,81,1,72
	.byte 15,190,149,202,254,255,255,64,136,81,2,72,15,190,149,203,254,255,255,64,136,81,3,72,15,190,149,204,254,255,255,64
	.byte 136,81,4,72,15,190,149,205,254,255,255,64,136,81,5,72,15,190,149,206,254,255,255,64,136,81,6,72,15,190,149,207
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,20,29,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 876
	.byte 72,15,190,8,64,136,141,208,254,255,255,72,15,190,72,1,64,136,141,209,254,255,255,72,15,190,72,2,64,136,141,210
	.byte 254,255,255,72,15,190,72,3,64,136,141,211,254,255,255,72,15,190,72,4,64,136,141,212,254,255,255,72,15,190,72,5
	.byte 64,136,141,213,254,255,255,72,15,190,72,6,64,136,141,214,254,255,255,72,15,190,64,7,64,136,133,215,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,1,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,208,254,255,255,64,136,17,72,15,190,149,209,254,255,255,64,136,81,1,72
	.byte 15,190,149,210,254,255,255,64,136,81,2,72,15,190,149,211,254,255,255,64,136,81,3,72,15,190,149,212,254,255,255,64
	.byte 136,81,4,72,15,190,149,213,254,255,255,64,136,81,5,72,15,190,149,214,254,255,255,64,136,81,6,72,15,190,149,215
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,4,28,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 876
	.byte 72,15,190,8,64,136,141,216,254,255,255,72,15,190,72,1,64,136,141,217,254,255,255,72,15,190,72,2,64,136,141,218
	.byte 254,255,255,72,15,190,72,3,64,136,141,219,254,255,255,72,15,190,72,4,64,136,141,220,254,255,255,72,15,190,72,5
	.byte 64,136,141,221,254,255,255,72,15,190,72,6,64,136,141,222,254,255,255,72,15,190,64,7,64,136,133,223,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,2,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,216,254,255,255,64,136,17,72,15,190,149,217,254,255,255,64,136,81,1,72
	.byte 15,190,149,218,254,255,255,64,136,81,2,72,15,190,149,219,254,255,255,64,136,81,3,72,15,190,149,220,254,255,255,64
	.byte 136,81,4,72,15,190,149,221,254,255,255,64,136,81,5,72,15,190,149,222,254,255,255,64,136,81,6,72,15,190,149,223
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,244,26,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 876
	.byte 72,15,190,8,64,136,141,224,254,255,255,72,15,190,72,1,64,136,141,225,254,255,255,72,15,190,72,2,64,136,141,226
	.byte 254,255,255,72,15,190,72,3,64,136,141,227,254,255,255,72,15,190,72,4,64,136,141,228,254,255,255,72,15,190,72,5
	.byte 64,136,141,229,254,255,255,72,15,190,72,6,64,136,141,230,254,255,255,72,15,190,64,7,64,136,133,231,254,255,255,73
	.byte 139,255,65,131,63,0
call .Lp_81

	.byte 72,139,248,190,3,0,0,0,131,56,0
call .Lp_77

	.byte 65,131,62,0,73,141,78,44,72,15,190,149,224,254,255,255,64,136,17,72,15,190,149,225,254,255,255,64,136,81,1,72
	.byte 15,190,149,226,254,255,255,64,136,81,2,72,15,190,149,227,254,255,255,64,136,81,3,72,15,190,149,228,254,255,255,64
	.byte 136,81,4,72,15,190,149,229,254,255,255,64,136,81,5,72,15,190,149,230,254,255,255,64,136,81,6,72,15,190,149,231
	.byte 254,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,228,25,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 860
	.byte 72,15,190,8,64,136,141,232,254,255,255,72,15,190,72,1,64,136,141,233,254,255,255,72,15,190,72,2,64,136,141,234
	.byte 254,255,255,72,15,190,72,3,64,136,141,235,254,255,255,72,15,190,72,4,64,136,141,236,254,255,255,72,15,190,72,5
	.byte 64,136,141,237,254,255,255,72,15,190,72,6,64,136,141,238,254,255,255,72,15,190,64,7,64,136,133,239,254,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,232,254,255,255,64,136,8,72,15,190,141,233,254,255,255,64,136,72,1,72,15
	.byte 190,141,234,254,255,255,64,136,72,2,72,15,190,141,235,254,255,255,64,136,72,3,72,15,190,141,236,254,255,255,64,136
	.byte 72,4,72,15,190,141,237,254,255,255,64,136,72,5,72,15,190,141,238,254,255,255,64,136,72,6,72,15,190,141,239,254
	.byte 255,255,64,136,72,7,233,18,25,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 884
	.byte 72,15,190,8,64,136,141,240,254,255,255,72,15,190,72,1,64,136,141,241,254,255,255,72,15,190,72,2,64,136,141,242
	.byte 254,255,255,72,15,190,72,3,64,136,141,243,254,255,255,72,15,190,72,4,64,136,141,244,254,255,255,72,15,190,72,5
	.byte 64,136,141,245,254,255,255,72,15,190,72,6,64,136,141,246,254,255,255,72,15,190,64,7,64,136,133,247,254,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,240,254,255,255,64,136,8,72,15,190,141,241,254,255,255,64,136,72,1,72,15
	.byte 190,141,242,254,255,255,64,136,72,2,72,15,190,141,243,254,255,255,64,136,72,3,72,15,190,141,244,254,255,255,64,136
	.byte 72,4,72,15,190,141,245,254,255,255,64,136,72,5,72,15,190,141,246,254,255,255,64,136,72,6,72,15,190,141,247,254
	.byte 255,255,64,136,72,7,233,64,24,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 892
	.byte 72,15,190,8,64,136,141,248,254,255,255,72,15,190,72,1,64,136,141,249,254,255,255,72,15,190,72,2,64,136,141,250
	.byte 254,255,255,72,15,190,72,3,64,136,141,251,254,255,255,72,15,190,72,4,64,136,141,252,254,255,255,72,15,190,72,5
	.byte 64,136,141,253,254,255,255,72,15,190,72,6,64,136,141,254,254,255,255,72,15,190,64,7,64,136,133,255,254,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,248,254,255,255,64,136,8,72,15,190,141,249,254,255,255,64,136,72,1,72,15
	.byte 190,141,250,254,255,255,64,136,72,2,72,15,190,141,251,254,255,255,64,136,72,3,72,15,190,141,252,254,255,255,64,136
	.byte 72,4,72,15,190,141,253,254,255,255,64,136,72,5,72,15,190,141,254,254,255,255,64,136,72,6,72,15,190,141,255,254
	.byte 255,255,64,136,72,7,233,110,23,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 868
	.byte 72,15,190,8,64,136,141,0,255,255,255,72,15,190,72,1,64,136,141,1,255,255,255,72,15,190,72,2,64,136,141,2
	.byte 255,255,255,72,15,190,72,3,64,136,141,3,255,255,255,72,15,190,72,4,64,136,141,4,255,255,255,72,15,190,72,5
	.byte 64,136,141,5,255,255,255,72,15,190,72,6,64,136,141,6,255,255,255,72,15,190,64,7,64,136,133,7,255,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,0,255,255,255,64,136,8,72,15,190,141,1,255,255,255,64,136,72,1,72,15
	.byte 190,141,2,255,255,255,64,136,72,2,72,15,190,141,3,255,255,255,64,136,72,3,72,15,190,141,4,255,255,255,64,136
	.byte 72,4,72,15,190,141,5,255,255,255,64,136,72,5,72,15,190,141,6,255,255,255,64,136,72,6,72,15,190,141,7,255
	.byte 255,255,64,136,72,7,233,156,22,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 900
	.byte 72,15,190,8,64,136,141,8,255,255,255,72,15,190,72,1,64,136,141,9,255,255,255,72,15,190,72,2,64,136,141,10
	.byte 255,255,255,72,15,190,72,3,64,136,141,11,255,255,255,72,15,190,72,4,64,136,141,12,255,255,255,72,15,190,72,5
	.byte 64,136,141,13,255,255,255,72,15,190,72,6,64,136,141,14,255,255,255,72,15,190,64,7,64,136,133,15,255,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,8,255,255,255,64,136,8,72,15,190,141,9,255,255,255,64,136,72,1,72,15
	.byte 190,141,10,255,255,255,64,136,72,2,72,15,190,141,11,255,255,255,64,136,72,3,72,15,190,141,12,255,255,255,64,136
	.byte 72,4,72,15,190,141,13,255,255,255,64,136,72,5,72,15,190,141,14,255,255,255,64,136,72,6,72,15,190,141,15,255
	.byte 255,255,64,136,72,7,233,202,21,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 876
	.byte 72,15,190,8,64,136,141,16,255,255,255,72,15,190,72,1,64,136,141,17,255,255,255,72,15,190,72,2,64,136,141,18
	.byte 255,255,255,72,15,190,72,3,64,136,141,19,255,255,255,72,15,190,72,4,64,136,141,20,255,255,255,72,15,190,72,5
	.byte 64,136,141,21,255,255,255,72,15,190,72,6,64,136,141,22,255,255,255,72,15,190,64,7,64,136,133,23,255,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,16,255,255,255,64,136,8,72,15,190,141,17,255,255,255,64,136,72,1,72,15
	.byte 190,141,18,255,255,255,64,136,72,2,72,15,190,141,19,255,255,255,64,136,72,3,72,15,190,141,20,255,255,255,64,136
	.byte 72,4,72,15,190,141,21,255,255,255,64,136,72,5,72,15,190,141,22,255,255,255,64,136,72,6,72,15,190,141,23,255
	.byte 255,255,64,136,72,7,233,248,20,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,24,255,255,255,72,15,190,72,1,64,136,141,25,255,255,255,72,15,190,72,2,64,136,141,26
	.byte 255,255,255,72,15,190,72,3,64,136,141,27,255,255,255,72,15,190,72,4,64,136,141,28,255,255,255,72,15,190,72,5
	.byte 64,136,141,29,255,255,255,72,15,190,72,6,64,136,141,30,255,255,255,72,15,190,64,7,64,136,133,31,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,255,255,255,255,65,131,62,0,73,141,78,44,72,15,190,149,24,255,255,255,64,136,17,72,15,190,149,25,255
	.byte 255,255,64,136,81,1,72,15,190,149,26,255,255,255,64,136,81,2,72,15,190,149,27,255,255,255,64,136,81,3,72,15
	.byte 190,149,28,255,255,255,64,136,81,4,72,15,190,149,29,255,255,255,64,136,81,5,72,15,190,149,30,255,255,255,64,136
	.byte 81,6,72,15,190,149,31,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,236,19,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,32,255,255,255,72,15,190,72,1,64,136,141,33,255,255,255,72,15,190,72,2,64,136,141,34
	.byte 255,255,255,72,15,190,72,3,64,136,141,35,255,255,255,72,15,190,72,4,64,136,141,36,255,255,255,72,15,190,72,5
	.byte 64,136,141,37,255,255,255,72,15,190,72,6,64,136,141,38,255,255,255,72,15,190,64,7,64,136,133,39,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,0,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,32,255,255,255,64,136,17,72,15,190,149,33,255
	.byte 255,255,64,136,81,1,72,15,190,149,34,255,255,255,64,136,81,2,72,15,190,149,35,255,255,255,64,136,81,3,72,15
	.byte 190,149,36,255,255,255,64,136,81,4,72,15,190,149,37,255,255,255,64,136,81,5,72,15,190,149,38,255,255,255,64,136
	.byte 81,6,72,15,190,149,39,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,224,18,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,40,255,255,255,72,15,190,72,1,64,136,141,41,255,255,255,72,15,190,72,2,64,136,141,42
	.byte 255,255,255,72,15,190,72,3,64,136,141,43,255,255,255,72,15,190,72,4,64,136,141,44,255,255,255,72,15,190,72,5
	.byte 64,136,141,45,255,255,255,72,15,190,72,6,64,136,141,46,255,255,255,72,15,190,64,7,64,136,133,47,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,1,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,40,255,255,255,64,136,17,72,15,190,149,41,255
	.byte 255,255,64,136,81,1,72,15,190,149,42,255,255,255,64,136,81,2,72,15,190,149,43,255,255,255,64,136,81,3,72,15
	.byte 190,149,44,255,255,255,64,136,81,4,72,15,190,149,45,255,255,255,64,136,81,5,72,15,190,149,46,255,255,255,64,136
	.byte 81,6,72,15,190,149,47,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,212,17,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,48,255,255,255,72,15,190,72,1,64,136,141,49,255,255,255,72,15,190,72,2,64,136,141,50
	.byte 255,255,255,72,15,190,72,3,64,136,141,51,255,255,255,72,15,190,72,4,64,136,141,52,255,255,255,72,15,190,72,5
	.byte 64,136,141,53,255,255,255,72,15,190,72,6,64,136,141,54,255,255,255,72,15,190,64,7,64,136,133,55,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,2,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,48,255,255,255,64,136,17,72,15,190,149,49,255
	.byte 255,255,64,136,81,1,72,15,190,149,50,255,255,255,64,136,81,2,72,15,190,149,51,255,255,255,64,136,81,3,72,15
	.byte 190,149,52,255,255,255,64,136,81,4,72,15,190,149,53,255,255,255,64,136,81,5,72,15,190,149,54,255,255,255,64,136
	.byte 81,6,72,15,190,149,55,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,200,16,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,56,255,255,255,72,15,190,72,1,64,136,141,57,255,255,255,72,15,190,72,2,64,136,141,58
	.byte 255,255,255,72,15,190,72,3,64,136,141,59,255,255,255,72,15,190,72,4,64,136,141,60,255,255,255,72,15,190,72,5
	.byte 64,136,141,61,255,255,255,72,15,190,72,6,64,136,141,62,255,255,255,72,15,190,64,7,64,136,133,63,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,3,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,56,255,255,255,64,136,17,72,15,190,149,57,255
	.byte 255,255,64,136,81,1,72,15,190,149,58,255,255,255,64,136,81,2,72,15,190,149,59,255,255,255,64,136,81,3,72,15
	.byte 190,149,60,255,255,255,64,136,81,4,72,15,190,149,61,255,255,255,64,136,81,5,72,15,190,149,62,255,255,255,64,136
	.byte 81,6,72,15,190,149,63,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,188,15,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,64,255,255,255,72,15,190,72,1,64,136,141,65,255,255,255,72,15,190,72,2,64,136,141,66
	.byte 255,255,255,72,15,190,72,3,64,136,141,67,255,255,255,72,15,190,72,4,64,136,141,68,255,255,255,72,15,190,72,5
	.byte 64,136,141,69,255,255,255,72,15,190,72,6,64,136,141,70,255,255,255,72,15,190,64,7,64,136,133,71,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,4,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,64,255,255,255,64,136,17,72,15,190,149,65,255
	.byte 255,255,64,136,81,1,72,15,190,149,66,255,255,255,64,136,81,2,72,15,190,149,67,255,255,255,64,136,81,3,72,15
	.byte 190,149,68,255,255,255,64,136,81,4,72,15,190,149,69,255,255,255,64,136,81,5,72,15,190,149,70,255,255,255,64,136
	.byte 81,6,72,15,190,149,71,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,176,14,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,72,255,255,255,72,15,190,72,1,64,136,141,73,255,255,255,72,15,190,72,2,64,136,141,74
	.byte 255,255,255,72,15,190,72,3,64,136,141,75,255,255,255,72,15,190,72,4,64,136,141,76,255,255,255,72,15,190,72,5
	.byte 64,136,141,77,255,255,255,72,15,190,72,6,64,136,141,78,255,255,255,72,15,190,64,7,64,136,133,79,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,5,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,72,255,255,255,64,136,17,72,15,190,149,73,255
	.byte 255,255,64,136,81,1,72,15,190,149,74,255,255,255,64,136,81,2,72,15,190,149,75,255,255,255,64,136,81,3,72,15
	.byte 190,149,76,255,255,255,64,136,81,4,72,15,190,149,77,255,255,255,64,136,81,5,72,15,190,149,78,255,255,255,64,136
	.byte 81,6,72,15,190,149,79,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,164,13,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,80,255,255,255,72,15,190,72,1,64,136,141,81,255,255,255,72,15,190,72,2,64,136,141,82
	.byte 255,255,255,72,15,190,72,3,64,136,141,83,255,255,255,72,15,190,72,4,64,136,141,84,255,255,255,72,15,190,72,5
	.byte 64,136,141,85,255,255,255,72,15,190,72,6,64,136,141,86,255,255,255,72,15,190,64,7,64,136,133,87,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,6,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,80,255,255,255,64,136,17,72,15,190,149,81,255
	.byte 255,255,64,136,81,1,72,15,190,149,82,255,255,255,64,136,81,2,72,15,190,149,83,255,255,255,64,136,81,3,72,15
	.byte 190,149,84,255,255,255,64,136,81,4,72,15,190,149,85,255,255,255,64,136,81,5,72,15,190,149,86,255,255,255,64,136
	.byte 81,6,72,15,190,149,87,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,152,12,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,88,255,255,255,72,15,190,72,1,64,136,141,89,255,255,255,72,15,190,72,2,64,136,141,90
	.byte 255,255,255,72,15,190,72,3,64,136,141,91,255,255,255,72,15,190,72,4,64,136,141,92,255,255,255,72,15,190,72,5
	.byte 64,136,141,93,255,255,255,72,15,190,72,6,64,136,141,94,255,255,255,72,15,190,64,7,64,136,133,95,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,7,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,88,255,255,255,64,136,17,72,15,190,149,89,255
	.byte 255,255,64,136,81,1,72,15,190,149,90,255,255,255,64,136,81,2,72,15,190,149,91,255,255,255,64,136,81,3,72,15
	.byte 190,149,92,255,255,255,64,136,81,4,72,15,190,149,93,255,255,255,64,136,81,5,72,15,190,149,94,255,255,255,64,136
	.byte 81,6,72,15,190,149,95,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,140,11,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,96,255,255,255,72,15,190,72,1,64,136,141,97,255,255,255,72,15,190,72,2,64,136,141,98
	.byte 255,255,255,72,15,190,72,3,64,136,141,99,255,255,255,72,15,190,72,4,64,136,141,100,255,255,255,72,15,190,72,5
	.byte 64,136,141,101,255,255,255,72,15,190,72,6,64,136,141,102,255,255,255,72,15,190,64,7,64,136,133,103,255,255,255,73
	.byte 139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 199,64,16,8,0,0,0,65,131,62,0,73,141,78,44,72,15,190,149,96,255,255,255,64,136,17,72,15,190,149,97,255
	.byte 255,255,64,136,81,1,72,15,190,149,98,255,255,255,64,136,81,2,72,15,190,149,99,255,255,255,64,136,81,3,72,15
	.byte 190,149,100,255,255,255,64,136,81,4,72,15,190,149,101,255,255,255,64,136,81,5,72,15,190,149,102,255,255,255,64,136
	.byte 81,6,72,15,190,149,103,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,128,10,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,141,104,255,255,255,72,15,190,72,1,64,136,141,105,255,255,255,72,15,190,72,2,64,136,141,106
	.byte 255,255,255,72,15,190,72,3,64,136,141,107,255,255,255,72,15,190,72,4,64,136,141,108,255,255,255,72,15,190,72,5
	.byte 64,136,141,109,255,255,255,72,15,190,72,6,64,136,141,110,255,255,255,72,15,190,64,7,64,136,133,111,255,255,255,65
	.byte 131,62,0,73,139,70,16,72,139,8,15,182,81,44,72,133,210,15,133,215,10,0,0,72,139,9,72,139,9,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 924
	.byte 72,59,202,15,133,178,10,0,0,72,15,190,64,16,72,137,133,64,254,255,255,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 72,139,141,64,254,255,255,137,72,16,65,131,62,0,73,141,78,44,72,15,190,149,104,255,255,255,64,136,17,72,15,190
	.byte 149,105,255,255,255,64,136,81,1,72,15,190,149,106,255,255,255,64,136,81,2,72,15,190,149,107,255,255,255,64,136,81
	.byte 3,72,15,190,149,108,255,255,255,64,136,81,4,72,15,190,149,109,255,255,255,64,136,81,5,72,15,190,149,110,255,255
	.byte 255,64,136,81,6,72,15,190,149,111,255,255,255,64,136,81,7,65,131,62,0,73,141,78,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,55,9,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 932
	.byte 72,15,190,8,64,136,141,112,255,255,255,72,15,190,72,1,64,136,141,113,255,255,255,72,15,190,72,2,64,136,141,114
	.byte 255,255,255,72,15,190,72,3,64,136,141,115,255,255,255,72,15,190,72,4,64,136,141,116,255,255,255,72,15,190,72,5
	.byte 64,136,141,117,255,255,255,72,15,190,72,6,64,136,141,118,255,255,255,72,15,190,64,7,64,136,133,119,255,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,112,255,255,255,64,136,8,72,15,190,141,113,255,255,255,64,136,72,1,72,15
	.byte 190,141,114,255,255,255,64,136,72,2,72,15,190,141,115,255,255,255,64,136,72,3,72,15,190,141,116,255,255,255,64,136
	.byte 72,4,72,15,190,141,117,255,255,255,64,136,72,5,72,15,190,141,118,255,255,255,64,136,72,6,72,15,190,141,119,255
	.byte 255,255,64,136,72,7,233,101,8,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 940
	.byte 72,15,190,8,64,136,141,120,255,255,255,72,15,190,72,1,64,136,141,121,255,255,255,72,15,190,72,2,64,136,141,122
	.byte 255,255,255,72,15,190,72,3,64,136,141,123,255,255,255,72,15,190,72,4,64,136,141,124,255,255,255,72,15,190,72,5
	.byte 64,136,141,125,255,255,255,72,15,190,72,6,64,136,141,126,255,255,255,72,15,190,64,7,64,136,133,127,255,255,255,65
	.byte 131,62,0,73,141,70,44,72,15,190,141,120,255,255,255,64,136,8,72,15,190,141,121,255,255,255,64,136,72,1,72,15
	.byte 190,141,122,255,255,255,64,136,72,2,72,15,190,141,123,255,255,255,64,136,72,3,72,15,190,141,124,255,255,255,64,136
	.byte 72,4,72,15,190,141,125,255,255,255,64,136,72,5,72,15,190,141,126,255,255,255,64,136,72,6,72,15,190,141,127,255
	.byte 255,255,64,136,72,7,233,147,7,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 948
	.byte 72,15,190,8,64,136,77,128,72,15,190,72,1,64,136,77,129,72,15,190,72,2,64,136,77,130,72,15,190,72,3,64
	.byte 136,77,131,72,15,190,72,4,64,136,77,132,72,15,190,72,5,64,136,77,133,72,15,190,72,6,64,136,77,134,72,15
	.byte 190,64,7,64,136,69,135,65,131,62,0,73,141,70,44,72,15,190,77,128,64,136,8,72,15,190,77,129,64,136,72,1
	.byte 72,15,190,77,130,64,136,72,2,72,15,190,77,131,64,136,72,3,72,15,190,77,132,64,136,72,4,72,15,190,77,133
	.byte 64,136,72,5,72,15,190,77,134,64,136,72,6,72,15,190,77,135,64,136,72,7,233,241,6,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 956
	.byte 72,15,190,8,64,136,77,136,72,15,190,72,1,64,136,77,137,72,15,190,72,2,64,136,77,138,72,15,190,72,3,64
	.byte 136,77,139,72,15,190,72,4,64,136,77,140,72,15,190,72,5,64,136,77,141,72,15,190,72,6,64,136,77,142,72,15
	.byte 190,64,7,64,136,69,143,65,131,62,0,73,141,70,44,72,15,190,77,136,64,136,8,72,15,190,77,137,64,136,72,1
	.byte 72,15,190,77,138,64,136,72,2,72,15,190,77,139,64,136,72,3,72,15,190,77,140,64,136,72,4,72,15,190,77,141
	.byte 64,136,72,5,72,15,190,77,142,64,136,72,6,72,15,190,77,143,64,136,72,7,233,79,6,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 964
	.byte 72,15,190,8,64,136,77,144,72,15,190,72,1,64,136,77,145,72,15,190,72,2,64,136,77,146,72,15,190,72,3,64
	.byte 136,77,147,72,15,190,72,4,64,136,77,148,72,15,190,72,5,64,136,77,149,72,15,190,72,6,64,136,77,150,72,15
	.byte 190,64,7,64,136,69,151,65,131,62,0,73,141,70,44,72,15,190,77,144,64,136,8,72,15,190,77,145,64,136,72,1
	.byte 72,15,190,77,146,64,136,72,2,72,15,190,77,147,64,136,72,3,72,15,190,77,148,64,136,72,4,72,15,190,77,149
	.byte 64,136,72,5,72,15,190,77,150,64,136,72,6,72,15,190,77,151,64,136,72,7,233,173,5,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 972
	.byte 72,15,190,8,64,136,77,152,72,15,190,72,1,64,136,77,153,72,15,190,72,2,64,136,77,154,72,15,190,72,3,64
	.byte 136,77,155,72,15,190,72,4,64,136,77,156,72,15,190,72,5,64,136,77,157,72,15,190,72,6,64,136,77,158,72,15
	.byte 190,64,7,64,136,69,159,65,131,62,0,73,141,70,44,72,15,190,77,152,64,136,8,72,15,190,77,153,64,136,72,1
	.byte 72,15,190,77,154,64,136,72,2,72,15,190,77,155,64,136,72,3,72,15,190,77,156,64,136,72,4,72,15,190,77,157
	.byte 64,136,72,5,72,15,190,77,158,64,136,72,6,72,15,190,77,159,64,136,72,7,233,11,5,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 980
	.byte 72,15,190,8,64,136,77,160,72,15,190,72,1,64,136,77,161,72,15,190,72,2,64,136,77,162,72,15,190,72,3,64
	.byte 136,77,163,72,15,190,72,4,64,136,77,164,72,15,190,72,5,64,136,77,165,72,15,190,72,6,64,136,77,166,72,15
	.byte 190,64,7,64,136,69,167,65,131,62,0,73,141,70,44,72,15,190,77,160,64,136,8,72,15,190,77,161,64,136,72,1
	.byte 72,15,190,77,162,64,136,72,2,72,15,190,77,163,64,136,72,3,72,15,190,77,164,64,136,72,4,72,15,190,77,165
	.byte 64,136,72,5,72,15,190,77,166,64,136,72,6,72,15,190,77,167,64,136,72,7,233,105,4,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 988
	.byte 72,15,190,8,64,136,77,168,72,15,190,72,1,64,136,77,169,72,15,190,72,2,64,136,77,170,72,15,190,72,3,64
	.byte 136,77,171,72,15,190,72,4,64,136,77,172,72,15,190,72,5,64,136,77,173,72,15,190,72,6,64,136,77,174,72,15
	.byte 190,64,7,64,136,69,175,65,131,62,0,73,141,70,44,72,15,190,77,168,64,136,8,72,15,190,77,169,64,136,72,1
	.byte 72,15,190,77,170,64,136,72,2,72,15,190,77,171,64,136,72,3,72,15,190,77,172,64,136,72,4,72,15,190,77,173
	.byte 64,136,72,5,72,15,190,77,174,64,136,72,6,72,15,190,77,175,64,136,72,7,233,199,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 996
	.byte 72,15,190,8,64,136,77,176,72,15,190,72,1,64,136,77,177,72,15,190,72,2,64,136,77,178,72,15,190,72,3,64
	.byte 136,77,179,72,15,190,72,4,64,136,77,180,72,15,190,72,5,64,136,77,181,72,15,190,72,6,64,136,77,182,72,15
	.byte 190,64,7,64,136,69,183,65,131,62,0,73,141,70,44,72,15,190,77,176,64,136,8,72,15,190,77,177,64,136,72,1
	.byte 72,15,190,77,178,64,136,72,2,72,15,190,77,179,64,136,72,3,72,15,190,77,180,64,136,72,4,72,15,190,77,181
	.byte 64,136,72,5,72,15,190,77,182,64,136,72,6,72,15,190,77,183,64,136,72,7,233,37,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1004
	.byte 72,15,190,8,64,136,77,184,72,15,190,72,1,64,136,77,185,72,15,190,72,2,64,136,77,186,72,15,190,72,3,64
	.byte 136,77,187,72,15,190,72,4,64,136,77,188,72,15,190,72,5,64,136,77,189,72,15,190,72,6,64,136,77,190,72,15
	.byte 190,64,7,64,136,69,191,65,131,62,0,73,141,70,44,72,15,190,77,184,64,136,8,72,15,190,77,185,64,136,72,1
	.byte 72,15,190,77,186,64,136,72,2,72,15,190,77,187,64,136,72,3,72,15,190,77,188,64,136,72,4,72,15,190,77,189
	.byte 64,136,72,5,72,15,190,77,190,64,136,72,6,72,15,190,77,191,64,136,72,7,233,131,2,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1012
	.byte 72,15,190,8,64,136,77,192,72,15,190,72,1,64,136,77,193,72,15,190,72,2,64,136,77,194,72,15,190,72,3,64
	.byte 136,77,195,72,15,190,72,4,64,136,77,196,72,15,190,72,5,64,136,77,197,72,15,190,72,6,64,136,77,198,72,15
	.byte 190,64,7,64,136,69,199,65,131,62,0,73,141,70,44,72,15,190,77,192,64,136,8,72,15,190,77,193,64,136,72,1
	.byte 72,15,190,77,194,64,136,72,2,72,15,190,77,195,64,136,72,3,72,15,190,77,196,64,136,72,4,72,15,190,77,197
	.byte 64,136,72,5,72,15,190,77,198,64,136,72,6,72,15,190,77,199,64,136,72,7,233,225,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1020
	.byte 72,15,190,8,64,136,77,200,72,15,190,72,1,64,136,77,201,72,15,190,72,2,64,136,77,202,72,15,190,72,3,64
	.byte 136,77,203,72,15,190,72,4,64,136,77,204,72,15,190,72,5,64,136,77,205,72,15,190,72,6,64,136,77,206,72,15
	.byte 190,64,7,64,136,69,207,65,131,62,0,73,141,70,44,72,15,190,77,200,64,136,8,72,15,190,77,201,64,136,72,1
	.byte 72,15,190,77,202,64,136,72,2,72,15,190,77,203,64,136,72,3,72,15,190,77,204,64,136,72,4,72,15,190,77,205
	.byte 64,136,72,5,72,15,190,77,206,64,136,72,6,72,15,190,77,207,64,136,72,7,233,63,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1028
	.byte 72,15,190,8,64,136,77,208,72,15,190,72,1,64,136,77,209,72,15,190,72,2,64,136,77,210,72,15,190,72,3,64
	.byte 136,77,211,72,15,190,72,4,64,136,77,212,72,15,190,72,5,64,136,77,213,72,15,190,72,6,64,136,77,214,72,15
	.byte 190,64,7,64,136,69,215,65,131,62,0,73,141,70,44,72,15,190,77,208,64,136,8,72,15,190,77,209,64,136,72,1
	.byte 72,15,190,77,210,64,136,72,2,72,15,190,77,211,64,136,72,3,72,15,190,77,212,64,136,72,4,72,15,190,77,213
	.byte 64,136,72,5,72,15,190,77,214,64,136,72,6,72,15,190,77,215,64,136,72,7,233,157,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1036
	.byte 72,15,190,8,64,136,77,216,72,15,190,72,1,64,136,77,217,72,15,190,72,2,64,136,77,218,72,15,190,72,3,64
	.byte 136,77,219,72,15,190,72,4,64,136,77,220,72,15,190,72,5,64,136,77,221,72,15,190,72,6,64,136,77,222,72,15
	.byte 190,64,7,64,136,69,223,65,131,62,0,73,141,70,44,72,15,190,77,216,64,136,8,72,15,190,77,217,64,136,72,1
	.byte 72,15,190,77,218,64,136,72,2,72,15,190,77,219,64,136,72,3,72,15,190,77,220,64,136,72,4,72,15,190,77,221
	.byte 64,136,72,5,72,15,190,77,222,64,136,72,6,72,15,190,77,223,64,136,72,7,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,253,72,129,199,104,254,255,255
call .Lp_82

	.byte 72,15,182,192,133,192,15,133,56,216,255,255,72,199,133,96,254,255,255,0,0,0,0,72,131,236,8,232,23,0,0,0
	.byte 72,131,196,8,72,139,133,96,254,255,255,72,133,192,116,5
call .Lp_83

	.byte 235,65,72,137,165,80,254,255,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,197,72,5,104,254,255,255,72,137,133,88,254,255,255,72,199,0,0,0,0,0,72,139,165,80,254,255,255,195,76
	.byte 139,101,224,76,139,109,232,76,139,117,240,76,139,125,248,201,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,199,10,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,221,10,0,0,235,239

	.size Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody
.Lme_2f:
.text 0
	.balign 16
.Lm_30:
	.local Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object
	.type Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object,@function
Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object:

	.byte 72,131,236,24,76,137,52,36,76,139,247,72,137,116,36,8,72,137,84,36,16,65,131,62,0,73,141,70,44,72,15,190
	.byte 76,36,8,64,136,8,72,15,190,76,36,9,64,136,72,1,72,15,190,76,36,10,64,136,72,2,72,15,190,76,36,11
	.byte 64,136,72,3,72,15,190,76,36,12,64,136,72,4,72,15,190,76,36,13,64,136,72,5,72,15,190,76,36,14,64,136
	.byte 72,6,72,15,190,76,36,15,64,136,72,7,65,131,62,0,73,141,78,16,72,139,68,36,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,76,139,52,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object,.-Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object
.Lme_30:
.text 0
	.balign 16
.Lm_31:
	.local Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode
	.type Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode,@function
Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode:

	.byte 72,131,236,24,76,137,60,36,76,139,255,72,137,116,36,8,65,131,63,0,73,141,71,44,72,15,190,76,36,8,64,136
	.byte 8,72,15,190,76,36,9,64,136,72,1,72,15,190,76,36,10,64,136,72,2,72,15,190,76,36,11,64,136,72,3,72
	.byte 15,190,76,36,12,64,136,72,4,72,15,190,76,36,13,64,136,72,5,72,15,190,76,36,14,64,136,72,6,72,15,190
	.byte 76,36,15,64,136,72,7,65,131,63,0,51,192,73,141,79,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255
	.byte 127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode,.-Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode
.Lme_31:
.text 0
	.balign 16
.Lm_32:
	.local Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody:

	.byte 72,131,236,8,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,133,192,15,132,23,0,0,0,72,139,60,36
call .Lp_84

	.byte 72,139,60,36
call .Lp_85

	.byte 72,131,196,8,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody
.Lme_32:
.text 0
	.balign 16
.Lm_33:
	.local Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody:

	.byte 72,131,236,88,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 198,68,36,48,0,198,68,36,49,0,198,68,36,50,0,198,68,36,51,0,198,68,36,52,0,198,68,36,53,0,198,68
	.byte 36,54,0,198,68,36,55,0,69,51,246,233,118,2,0,0,102,144,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,248,73,139,246,131,56,0
call .Lp_86

	.byte 76,139,232,72,139,200,131,57,0,72,131,192,44,72,15,190,8,64,136,76,36,48,72,15,190,72,1,64,136,76,36,49
	.byte 72,15,190,72,2,64,136,76,36,50,72,15,190,72,3,64,136,76,36,51,72,15,190,72,4,64,136,76,36,52,72,15
	.byte 190,72,5,64,136,76,36,53,72,15,190,72,6,64,136,76,36,54,72,15,190,64,7,64,136,68,36,55,15,182,68,36
	.byte 50,131,248,33,15,133,217,1,0,0,65,131,125,0,0,73,139,69,16,72,139,8,15,182,81,44,72,133,210,15,133,9
	.byte 2,0,0,72,139,9,72,139,9,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1044
	.byte 72,59,202,15,133,228,1,0,0,76,139,96,16,73,139,196,72,61,255,255,255,127,15,141,151,1,0,0,73,129,252,0
	.byte 0,0,128,15,142,138,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 908
	.byte 72,15,190,8,64,136,76,36,40,72,15,190,72,1,64,136,76,36,41,72,15,190,72,2,64,136,76,36,42,72,15,190
	.byte 72,3,64,136,76,36,43,72,15,190,72,4,64,136,76,36,44,72,15,190,72,5,64,136,76,36,45,72,15,190,72,6
	.byte 64,136,76,36,46,72,15,190,64,7,64,136,68,36,47,73,99,196,72,137,68,36,72,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 916
	.byte 190,20,0,0,0
call .Lp_2

	.byte 72,139,76,36,72,137,72,16,65,131,125,0,0,73,141,77,44,72,15,190,84,36,40,64,136,17,72,15,190,84,36,41
	.byte 64,136,81,1,72,15,190,84,36,42,64,136,81,2,72,15,190,84,36,43,64,136,81,3,72,15,190,84,36,44,64,136
	.byte 81,4,72,15,190,84,36,45,64,136,81,5,72,15,190,84,36,46,64,136,81,6,72,15,190,84,36,47,64,136,81,7
	.byte 65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,73,139,255,65,131,63,0
call .Lp_78

	.byte 72,137,68,36,56,65,141,70,1,72,139,200,72,137,76,36,64,76,139,240,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1052
	.byte 72,15,190,8,64,136,76,36,32,72,15,190,72,1,64,136,76,36,33,72,15,190,72,2,64,136,76,36,34,72,15,190
	.byte 72,3,64,136,76,36,35,72,15,190,72,4,64,136,76,36,36,72,15,190,72,5,64,136,76,36,37,72,15,190,72,6
	.byte 64,136,76,36,38,72,15,190,64,7,64,136,68,36,39,72,139,124,36,32
call .Lp_87

	.byte 72,139,208,72,139,68,36,56,72,139,116,36,64,72,139,248,131,56,0
call .Lp_88

	.byte 65,255,198,73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,200,131,57,0,72,99,64,24,68,59,240,15,140,109,253,255,255,76,139,36,36,76,139,108,36,8,76,139,116,36
	.byte 16,76,139,124,36,24,72,131,196,88,195,190,249,1,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,15,2,0,0,235,239

	.size Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody
.Lme_33:
.text 0
	.balign 16
.Lm_34:
	.local Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody:

	.byte 85,72,139,236,72,129,236,80,1,0,0,72,137,93,216,76,137,101,224,76,137,109,232,76,137,117,240,76,137,125,248,76
	.byte 139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,133,216,254,255,255,72,137,133,224,254,255,255,72,137,133,232,254,255,255,198,133,240,254,255,255,0,198,133
	.byte 241,254,255,255,0,198,133,242,254,255,255,0,198,133,243,254,255,255,0,198,133,244,254,255,255,0,198,133,245,254,255,255
	.byte 0,198,133,246,254,255,255,0,198,133,247,254,255,255,0,77,133,255,15,132,25,30,0,0,65,131,63,0,77,139,119,16
	.byte 73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,245,72,129,198,216,254,255,255,72,139,248,131,56,0
call .Lp_79

	.byte 233,63,29,0,0,72,141,109,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 76,139,173,224,254,255,255,73,139,197,72,139,200,131,57,0,72,131,192,44,72,15,190,8,64,136,141,240,254,255,255,72
	.byte 15,190,72,1,64,136,141,241,254,255,255,72,15,190,72,2,64,136,141,242,254,255,255,72,15,190,72,3,64,136,141,243
	.byte 254,255,255,72,15,190,72,4,64,136,141,244,254,255,255,72,15,190,72,5,64,136,141,245,254,255,255,72,15,190,72,6
	.byte 64,136,141,246,254,255,255,72,15,190,64,7,64,136,133,247,254,255,255,68,15,182,165,242,254,255,255,73,139,196,131,248
	.byte 32,15,132,86,19,0,0,73,139,220,129,235,199,0,0,0,131,251,6,115,24,72,139,195,72,193,224,3,139,200,73,139
	.byte 5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1060
	.byte 72,3,193,72,139,0,255,224,233,110,28,0,0,65,131,125,0,0,77,139,101,16,77,133,228,116,31,73,139,4,36,72
	.byte 139,0,72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1068
	.byte 72,59,193,15,133,69,29,0,0,65,131,60,36,0,77,99,100,36,32,73,139,196,131,248,255,117,48,65,131,125,0,0
	.byte 73,139,69,16,72,137,133,176,254,255,255,73,139,255,65,131,63,0
call .Lp_89

	.byte 72,139,200,72,139,133,176,254,255,255,72,59,193,117,5,69,51,228,235,23,73,139,254,73,139,6,255,144,200,1,0,0
	.byte 72,15,182,192,133,192,116,3,65,255,196,73,139,220,65,131,252,4,115,24,72,139,195,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1076
	.byte 72,3,193,72,139,0,255,224,233,240,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1084
	.byte 72,15,190,8,64,136,141,248,254,255,255,72,15,190,72,1,64,136,141,249,254,255,255,72,15,190,72,2,64,136,141,250
	.byte 254,255,255,72,15,190,72,3,64,136,141,251,254,255,255,72,15,190,72,4,64,136,141,252,254,255,255,72,15,190,72,5
	.byte 64,136,141,253,254,255,255,72,15,190,72,6,64,136,141,254,254,255,255,72,15,190,64,7,64,136,133,255,254,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,248,254,255,255,64,136,8,72,15,190,141,249,254,255,255,64,136,72,1,72
	.byte 15,190,141,250,254,255,255,64,136,72,2,72,15,190,141,251,254,255,255,64,136,72,3,72,15,190,141,252,254,255,255,64
	.byte 136,72,4,72,15,190,141,253,254,255,255,64,136,72,5,72,15,190,141,254,254,255,255,64,136,72,6,72,15,190,141,255
	.byte 254,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,198,26,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1092
	.byte 72,15,190,8,64,136,141,0,255,255,255,72,15,190,72,1,64,136,141,1,255,255,255,72,15,190,72,2,64,136,141,2
	.byte 255,255,255,72,15,190,72,3,64,136,141,3,255,255,255,72,15,190,72,4,64,136,141,4,255,255,255,72,15,190,72,5
	.byte 64,136,141,5,255,255,255,72,15,190,72,6,64,136,141,6,255,255,255,72,15,190,64,7,64,136,133,7,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,0,255,255,255,64,136,8,72,15,190,141,1,255,255,255,64,136,72,1,72
	.byte 15,190,141,2,255,255,255,64,136,72,2,72,15,190,141,3,255,255,255,64,136,72,3,72,15,190,141,4,255,255,255,64
	.byte 136,72,4,72,15,190,141,5,255,255,255,64,136,72,5,72,15,190,141,6,255,255,255,64,136,72,6,72,15,190,141,7
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,202,25,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1100
	.byte 72,15,190,8,64,136,141,8,255,255,255,72,15,190,72,1,64,136,141,9,255,255,255,72,15,190,72,2,64,136,141,10
	.byte 255,255,255,72,15,190,72,3,64,136,141,11,255,255,255,72,15,190,72,4,64,136,141,12,255,255,255,72,15,190,72,5
	.byte 64,136,141,13,255,255,255,72,15,190,72,6,64,136,141,14,255,255,255,72,15,190,64,7,64,136,133,15,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,8,255,255,255,64,136,8,72,15,190,141,9,255,255,255,64,136,72,1,72
	.byte 15,190,141,10,255,255,255,64,136,72,2,72,15,190,141,11,255,255,255,64,136,72,3,72,15,190,141,12,255,255,255,64
	.byte 136,72,4,72,15,190,141,13,255,255,255,64,136,72,5,72,15,190,141,14,255,255,255,64,136,72,6,72,15,190,141,15
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,206,24,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1108
	.byte 72,15,190,8,64,136,141,16,255,255,255,72,15,190,72,1,64,136,141,17,255,255,255,72,15,190,72,2,64,136,141,18
	.byte 255,255,255,72,15,190,72,3,64,136,141,19,255,255,255,72,15,190,72,4,64,136,141,20,255,255,255,72,15,190,72,5
	.byte 64,136,141,21,255,255,255,72,15,190,72,6,64,136,141,22,255,255,255,72,15,190,64,7,64,136,133,23,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,16,255,255,255,64,136,8,72,15,190,141,17,255,255,255,64,136,72,1,72
	.byte 15,190,141,18,255,255,255,64,136,72,2,72,15,190,141,19,255,255,255,64,136,72,3,72,15,190,141,20,255,255,255,64
	.byte 136,72,4,72,15,190,141,21,255,255,255,64,136,72,5,72,15,190,141,22,255,255,255,64,136,72,6,72,15,190,141,23
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,210,23,0,0,65,129,252,0,1,0,0,15,141,197,23,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1116
	.byte 72,15,190,8,64,136,141,24,255,255,255,72,15,190,72,1,64,136,141,25,255,255,255,72,15,190,72,2,64,136,141,26
	.byte 255,255,255,72,15,190,72,3,64,136,141,27,255,255,255,72,15,190,72,4,64,136,141,28,255,255,255,72,15,190,72,5
	.byte 64,136,141,29,255,255,255,72,15,190,72,6,64,136,141,30,255,255,255,72,15,190,64,7,64,136,133,31,255,255,255,65
	.byte 131,125,0,0,73,139,69,16,65,131,125,0,0,73,141,77,44,72,15,190,149,24,255,255,255,64,136,17,72,15,190,149
	.byte 25,255,255,255,64,136,81,1,72,15,190,149,26,255,255,255,64,136,81,2,72,15,190,149,27,255,255,255,64,136,81,3
	.byte 72,15,190,149,28,255,255,255,64,136,81,4,72,15,190,149,29,255,255,255,64,136,81,5,72,15,190,149,30,255,255,255
	.byte 64,136,81,6,72,15,190,149,31,255,255,255,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,198,22,0,0,65,131,125,0,0,77,139,101,16,77,133,228,116,31,73,139,4,36,72,139,0
	.byte 72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1124
	.byte 72,59,193,15,133,150,23,0,0,65,131,60,36,0,77,99,100,36,24,73,139,220,131,251,4,115,24,72,139,195,72,193
	.byte 224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1132
	.byte 72,3,193,72,139,0,255,224,233,240,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1140
	.byte 72,15,190,8,64,136,141,32,255,255,255,72,15,190,72,1,64,136,141,33,255,255,255,72,15,190,72,2,64,136,141,34
	.byte 255,255,255,72,15,190,72,3,64,136,141,35,255,255,255,72,15,190,72,4,64,136,141,36,255,255,255,72,15,190,72,5
	.byte 64,136,141,37,255,255,255,72,15,190,72,6,64,136,141,38,255,255,255,72,15,190,64,7,64,136,133,39,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,32,255,255,255,64,136,8,72,15,190,141,33,255,255,255,64,136,72,1,72
	.byte 15,190,141,34,255,255,255,64,136,72,2,72,15,190,141,35,255,255,255,64,136,72,3,72,15,190,141,36,255,255,255,64
	.byte 136,72,4,72,15,190,141,37,255,255,255,64,136,72,5,72,15,190,141,38,255,255,255,64,136,72,6,72,15,190,141,39
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,110,21,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1148
	.byte 72,15,190,8,64,136,141,40,255,255,255,72,15,190,72,1,64,136,141,41,255,255,255,72,15,190,72,2,64,136,141,42
	.byte 255,255,255,72,15,190,72,3,64,136,141,43,255,255,255,72,15,190,72,4,64,136,141,44,255,255,255,72,15,190,72,5
	.byte 64,136,141,45,255,255,255,72,15,190,72,6,64,136,141,46,255,255,255,72,15,190,64,7,64,136,133,47,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,40,255,255,255,64,136,8,72,15,190,141,41,255,255,255,64,136,72,1,72
	.byte 15,190,141,42,255,255,255,64,136,72,2,72,15,190,141,43,255,255,255,64,136,72,3,72,15,190,141,44,255,255,255,64
	.byte 136,72,4,72,15,190,141,45,255,255,255,64,136,72,5,72,15,190,141,46,255,255,255,64,136,72,6,72,15,190,141,47
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,114,20,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1156
	.byte 72,15,190,8,64,136,141,48,255,255,255,72,15,190,72,1,64,136,141,49,255,255,255,72,15,190,72,2,64,136,141,50
	.byte 255,255,255,72,15,190,72,3,64,136,141,51,255,255,255,72,15,190,72,4,64,136,141,52,255,255,255,72,15,190,72,5
	.byte 64,136,141,53,255,255,255,72,15,190,72,6,64,136,141,54,255,255,255,72,15,190,64,7,64,136,133,55,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,48,255,255,255,64,136,8,72,15,190,141,49,255,255,255,64,136,72,1,72
	.byte 15,190,141,50,255,255,255,64,136,72,2,72,15,190,141,51,255,255,255,64,136,72,3,72,15,190,141,52,255,255,255,64
	.byte 136,72,4,72,15,190,141,53,255,255,255,64,136,72,5,72,15,190,141,54,255,255,255,64,136,72,6,72,15,190,141,55
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,118,19,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1164
	.byte 72,15,190,8,64,136,141,56,255,255,255,72,15,190,72,1,64,136,141,57,255,255,255,72,15,190,72,2,64,136,141,58
	.byte 255,255,255,72,15,190,72,3,64,136,141,59,255,255,255,72,15,190,72,4,64,136,141,60,255,255,255,72,15,190,72,5
	.byte 64,136,141,61,255,255,255,72,15,190,72,6,64,136,141,62,255,255,255,72,15,190,64,7,64,136,133,63,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,56,255,255,255,64,136,8,72,15,190,141,57,255,255,255,64,136,72,1,72
	.byte 15,190,141,58,255,255,255,64,136,72,2,72,15,190,141,59,255,255,255,64,136,72,3,72,15,190,141,60,255,255,255,64
	.byte 136,72,4,72,15,190,141,61,255,255,255,64,136,72,5,72,15,190,141,62,255,255,255,64,136,72,6,72,15,190,141,63
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,122,18,0,0,65,129,252,0,1,0,0,15,141,109,18,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1172
	.byte 72,15,190,8,64,136,141,64,255,255,255,72,15,190,72,1,64,136,141,65,255,255,255,72,15,190,72,2,64,136,141,66
	.byte 255,255,255,72,15,190,72,3,64,136,141,67,255,255,255,72,15,190,72,4,64,136,141,68,255,255,255,72,15,190,72,5
	.byte 64,136,141,69,255,255,255,72,15,190,72,6,64,136,141,70,255,255,255,72,15,190,64,7,64,136,133,71,255,255,255,65
	.byte 131,125,0,0,73,139,69,16,65,131,125,0,0,73,141,77,44,72,15,190,149,64,255,255,255,64,136,17,72,15,190,149
	.byte 65,255,255,255,64,136,81,1,72,15,190,149,66,255,255,255,64,136,81,2,72,15,190,149,67,255,255,255,64,136,81,3
	.byte 72,15,190,149,68,255,255,255,64,136,81,4,72,15,190,149,69,255,255,255,64,136,81,5,72,15,190,149,70,255,255,255
	.byte 64,136,81,6,72,15,190,149,71,255,255,255,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,110,17,0,0,65,131,125,0,0,77,139,101,16,77,133,228,116,31,73,139,4,36,72,139,0
	.byte 72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1124
	.byte 72,59,193,15,133,55,18,0,0,65,131,60,36,0,77,99,100,36,24,73,139,220,131,251,4,115,24,72,139,195,72,193
	.byte 224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1180
	.byte 72,3,193,72,139,0,255,224,233,240,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1188
	.byte 72,15,190,8,64,136,141,72,255,255,255,72,15,190,72,1,64,136,141,73,255,255,255,72,15,190,72,2,64,136,141,74
	.byte 255,255,255,72,15,190,72,3,64,136,141,75,255,255,255,72,15,190,72,4,64,136,141,76,255,255,255,72,15,190,72,5
	.byte 64,136,141,77,255,255,255,72,15,190,72,6,64,136,141,78,255,255,255,72,15,190,64,7,64,136,133,79,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,72,255,255,255,64,136,8,72,15,190,141,73,255,255,255,64,136,72,1,72
	.byte 15,190,141,74,255,255,255,64,136,72,2,72,15,190,141,75,255,255,255,64,136,72,3,72,15,190,141,76,255,255,255,64
	.byte 136,72,4,72,15,190,141,77,255,255,255,64,136,72,5,72,15,190,141,78,255,255,255,64,136,72,6,72,15,190,141,79
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,22,16,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1196
	.byte 72,15,190,8,64,136,141,80,255,255,255,72,15,190,72,1,64,136,141,81,255,255,255,72,15,190,72,2,64,136,141,82
	.byte 255,255,255,72,15,190,72,3,64,136,141,83,255,255,255,72,15,190,72,4,64,136,141,84,255,255,255,72,15,190,72,5
	.byte 64,136,141,85,255,255,255,72,15,190,72,6,64,136,141,86,255,255,255,72,15,190,64,7,64,136,133,87,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,80,255,255,255,64,136,8,72,15,190,141,81,255,255,255,64,136,72,1,72
	.byte 15,190,141,82,255,255,255,64,136,72,2,72,15,190,141,83,255,255,255,64,136,72,3,72,15,190,141,84,255,255,255,64
	.byte 136,72,4,72,15,190,141,85,255,255,255,64,136,72,5,72,15,190,141,86,255,255,255,64,136,72,6,72,15,190,141,87
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,26,15,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1204
	.byte 72,15,190,8,64,136,141,88,255,255,255,72,15,190,72,1,64,136,141,89,255,255,255,72,15,190,72,2,64,136,141,90
	.byte 255,255,255,72,15,190,72,3,64,136,141,91,255,255,255,72,15,190,72,4,64,136,141,92,255,255,255,72,15,190,72,5
	.byte 64,136,141,93,255,255,255,72,15,190,72,6,64,136,141,94,255,255,255,72,15,190,64,7,64,136,133,95,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,88,255,255,255,64,136,8,72,15,190,141,89,255,255,255,64,136,72,1,72
	.byte 15,190,141,90,255,255,255,64,136,72,2,72,15,190,141,91,255,255,255,64,136,72,3,72,15,190,141,92,255,255,255,64
	.byte 136,72,4,72,15,190,141,93,255,255,255,64,136,72,5,72,15,190,141,94,255,255,255,64,136,72,6,72,15,190,141,95
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,30,14,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1212
	.byte 72,15,190,8,64,136,141,96,255,255,255,72,15,190,72,1,64,136,141,97,255,255,255,72,15,190,72,2,64,136,141,98
	.byte 255,255,255,72,15,190,72,3,64,136,141,99,255,255,255,72,15,190,72,4,64,136,141,100,255,255,255,72,15,190,72,5
	.byte 64,136,141,101,255,255,255,72,15,190,72,6,64,136,141,102,255,255,255,72,15,190,64,7,64,136,133,103,255,255,255,65
	.byte 131,125,0,0,73,141,69,44,72,15,190,141,96,255,255,255,64,136,8,72,15,190,141,97,255,255,255,64,136,72,1,72
	.byte 15,190,141,98,255,255,255,64,136,72,2,72,15,190,141,99,255,255,255,64,136,72,3,72,15,190,141,100,255,255,255,64
	.byte 136,72,4,72,15,190,141,101,255,255,255,64,136,72,5,72,15,190,141,102,255,255,255,64,136,72,6,72,15,190,141,103
	.byte 255,255,255,64,136,72,7,65,131,125,0,0,51,192,73,141,77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255
	.byte 255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,34,13,0,0,65,129,252,0,1,0,0,15,141,21,13,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1220
	.byte 72,15,190,8,64,136,141,104,255,255,255,72,15,190,72,1,64,136,141,105,255,255,255,72,15,190,72,2,64,136,141,106
	.byte 255,255,255,72,15,190,72,3,64,136,141,107,255,255,255,72,15,190,72,4,64,136,141,108,255,255,255,72,15,190,72,5
	.byte 64,136,141,109,255,255,255,72,15,190,72,6,64,136,141,110,255,255,255,72,15,190,64,7,64,136,133,111,255,255,255,65
	.byte 131,125,0,0,73,139,69,16,65,131,125,0,0,73,141,77,44,72,15,190,149,104,255,255,255,64,136,17,72,15,190,149
	.byte 105,255,255,255,64,136,81,1,72,15,190,149,106,255,255,255,64,136,81,2,72,15,190,149,107,255,255,255,64,136,81,3
	.byte 72,15,190,149,108,255,255,255,64,136,81,4,72,15,190,149,109,255,255,255,64,136,81,5,72,15,190,149,110,255,255,255
	.byte 64,136,81,6,72,15,190,149,111,255,255,255,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,22,12,0,0,65,131,125,0,0,77,139,101,16,77,133,228,116,31,73,139,4,36,72,139,0
	.byte 72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1068
	.byte 72,59,193,15,133,216,12,0,0,65,131,60,36,0,77,99,100,36,32,73,139,196,131,248,255,117,48,65,131,125,0,0
	.byte 73,139,69,16,72,137,133,176,254,255,255,73,139,255,65,131,63,0
call .Lp_89

	.byte 72,139,200,72,139,133,176,254,255,255,72,59,193,117,5,69,51,228,235,23,73,139,254,73,139,6,255,144,200,1,0,0
	.byte 72,15,182,192,133,192,116,3,65,255,196,65,129,252,0,1,0,0,15,141,131,11,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1228
	.byte 72,15,190,8,64,136,141,112,255,255,255,72,15,190,72,1,64,136,141,113,255,255,255,72,15,190,72,2,64,136,141,114
	.byte 255,255,255,72,15,190,72,3,64,136,141,115,255,255,255,72,15,190,72,4,64,136,141,116,255,255,255,72,15,190,72,5
	.byte 64,136,141,117,255,255,255,72,15,190,72,6,64,136,141,118,255,255,255,72,15,190,64,7,64,136,133,119,255,255,255,65
	.byte 131,125,0,0,73,139,69,16,65,131,125,0,0,73,141,77,44,72,15,190,149,112,255,255,255,64,136,17,72,15,190,149
	.byte 113,255,255,255,64,136,81,1,72,15,190,149,114,255,255,255,64,136,81,2,72,15,190,149,115,255,255,255,64,136,81,3
	.byte 72,15,190,149,116,255,255,255,64,136,81,4,72,15,190,149,117,255,255,255,64,136,81,5,72,15,190,149,118,255,255,255
	.byte 64,136,81,6,72,15,190,149,119,255,255,255,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,132,10,0,0,65,131,125,0,0,77,139,101,16,77,133,228,116,31,73,139,4,36,72,139,0
	.byte 72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1124
	.byte 72,59,193,15,133,63,11,0,0,65,131,60,36,0,73,99,68,36,24,61,0,1,0,0,15,141,66,10,0,0,73,139
	.byte 5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1236
	.byte 72,15,190,8,64,136,141,120,255,255,255,72,15,190,72,1,64,136,141,121,255,255,255,72,15,190,72,2,64,136,141,122
	.byte 255,255,255,72,15,190,72,3,64,136,141,123,255,255,255,72,15,190,72,4,64,136,141,124,255,255,255,72,15,190,72,5
	.byte 64,136,141,125,255,255,255,72,15,190,72,6,64,136,141,126,255,255,255,72,15,190,64,7,64,136,133,127,255,255,255,65
	.byte 131,125,0,0,73,139,69,16,65,131,125,0,0,73,141,77,44,72,15,190,149,120,255,255,255,64,136,17,72,15,190,149
	.byte 121,255,255,255,64,136,81,1,72,15,190,149,122,255,255,255,64,136,81,2,72,15,190,149,123,255,255,255,64,136,81,3
	.byte 72,15,190,149,124,255,255,255,64,136,81,4,72,15,190,149,125,255,255,255,64,136,81,5,72,15,190,149,126,255,255,255
	.byte 64,136,81,6,72,15,190,149,127,255,255,255,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,67,9,0,0,65,131,125,0,0,73,139,69,16,72,139,8,15,182,81,44,72,133,210,15,133
	.byte 11,10,0,0,72,139,9,72,139,9,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1244
	.byte 72,59,202,15,133,230,9,0,0,76,99,96,16,73,139,196,72,139,216,131,235,255,131,251,10,115,24,72,139,195,72,193
	.byte 224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1252
	.byte 72,3,193,72,139,0,255,224,233,248,7,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1260
	.byte 72,15,190,8,64,136,77,128,72,15,190,72,1,64,136,77,129,72,15,190,72,2,64,136,77,130,72,15,190,72,3,64
	.byte 136,77,131,72,15,190,72,4,64,136,77,132,72,15,190,72,5,64,136,77,133,72,15,190,72,6,64,136,77,134,72,15
	.byte 190,64,7,64,136,69,135,65,131,125,0,0,73,141,69,44,72,15,190,77,128,64,136,8,72,15,190,77,129,64,136,72
	.byte 1,72,15,190,77,130,64,136,72,2,72,15,190,77,131,64,136,72,3,72,15,190,77,132,64,136,72,4,72,15,190,77
	.byte 133,64,136,72,5,72,15,190,77,134,64,136,72,6,72,15,190,77,135,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,25,8,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1268
	.byte 72,15,190,8,64,136,77,136,72,15,190,72,1,64,136,77,137,72,15,190,72,2,64,136,77,138,72,15,190,72,3,64
	.byte 136,77,139,72,15,190,72,4,64,136,77,140,72,15,190,72,5,64,136,77,141,72,15,190,72,6,64,136,77,142,72,15
	.byte 190,64,7,64,136,69,143,65,131,125,0,0,73,141,69,44,72,15,190,77,136,64,136,8,72,15,190,77,137,64,136,72
	.byte 1,72,15,190,77,138,64,136,72,2,72,15,190,77,139,64,136,72,3,72,15,190,77,140,64,136,72,4,72,15,190,77
	.byte 141,64,136,72,5,72,15,190,77,142,64,136,72,6,72,15,190,77,143,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,77,7,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1276
	.byte 72,15,190,8,64,136,77,144,72,15,190,72,1,64,136,77,145,72,15,190,72,2,64,136,77,146,72,15,190,72,3,64
	.byte 136,77,147,72,15,190,72,4,64,136,77,148,72,15,190,72,5,64,136,77,149,72,15,190,72,6,64,136,77,150,72,15
	.byte 190,64,7,64,136,69,151,65,131,125,0,0,73,141,69,44,72,15,190,77,144,64,136,8,72,15,190,77,145,64,136,72
	.byte 1,72,15,190,77,146,64,136,72,2,72,15,190,77,147,64,136,72,3,72,15,190,77,148,64,136,72,4,72,15,190,77
	.byte 149,64,136,72,5,72,15,190,77,150,64,136,72,6,72,15,190,77,151,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,129,6,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1284
	.byte 72,15,190,8,64,136,77,152,72,15,190,72,1,64,136,77,153,72,15,190,72,2,64,136,77,154,72,15,190,72,3,64
	.byte 136,77,155,72,15,190,72,4,64,136,77,156,72,15,190,72,5,64,136,77,157,72,15,190,72,6,64,136,77,158,72,15
	.byte 190,64,7,64,136,69,159,65,131,125,0,0,73,141,69,44,72,15,190,77,152,64,136,8,72,15,190,77,153,64,136,72
	.byte 1,72,15,190,77,154,64,136,72,2,72,15,190,77,155,64,136,72,3,72,15,190,77,156,64,136,72,4,72,15,190,77
	.byte 157,64,136,72,5,72,15,190,77,158,64,136,72,6,72,15,190,77,159,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,181,5,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1292
	.byte 72,15,190,8,64,136,77,160,72,15,190,72,1,64,136,77,161,72,15,190,72,2,64,136,77,162,72,15,190,72,3,64
	.byte 136,77,163,72,15,190,72,4,64,136,77,164,72,15,190,72,5,64,136,77,165,72,15,190,72,6,64,136,77,166,72,15
	.byte 190,64,7,64,136,69,167,65,131,125,0,0,73,141,69,44,72,15,190,77,160,64,136,8,72,15,190,77,161,64,136,72
	.byte 1,72,15,190,77,162,64,136,72,2,72,15,190,77,163,64,136,72,3,72,15,190,77,164,64,136,72,4,72,15,190,77
	.byte 165,64,136,72,5,72,15,190,77,166,64,136,72,6,72,15,190,77,167,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,233,4,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1300
	.byte 72,15,190,8,64,136,77,168,72,15,190,72,1,64,136,77,169,72,15,190,72,2,64,136,77,170,72,15,190,72,3,64
	.byte 136,77,171,72,15,190,72,4,64,136,77,172,72,15,190,72,5,64,136,77,173,72,15,190,72,6,64,136,77,174,72,15
	.byte 190,64,7,64,136,69,175,65,131,125,0,0,73,141,69,44,72,15,190,77,168,64,136,8,72,15,190,77,169,64,136,72
	.byte 1,72,15,190,77,170,64,136,72,2,72,15,190,77,171,64,136,72,3,72,15,190,77,172,64,136,72,4,72,15,190,77
	.byte 173,64,136,72,5,72,15,190,77,174,64,136,72,6,72,15,190,77,175,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,29,4,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1308
	.byte 72,15,190,8,64,136,77,176,72,15,190,72,1,64,136,77,177,72,15,190,72,2,64,136,77,178,72,15,190,72,3,64
	.byte 136,77,179,72,15,190,72,4,64,136,77,180,72,15,190,72,5,64,136,77,181,72,15,190,72,6,64,136,77,182,72,15
	.byte 190,64,7,64,136,69,183,65,131,125,0,0,73,141,69,44,72,15,190,77,176,64,136,8,72,15,190,77,177,64,136,72
	.byte 1,72,15,190,77,178,64,136,72,2,72,15,190,77,179,64,136,72,3,72,15,190,77,180,64,136,72,4,72,15,190,77
	.byte 181,64,136,72,5,72,15,190,77,182,64,136,72,6,72,15,190,77,183,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,81,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1316
	.byte 72,15,190,8,64,136,77,184,72,15,190,72,1,64,136,77,185,72,15,190,72,2,64,136,77,186,72,15,190,72,3,64
	.byte 136,77,187,72,15,190,72,4,64,136,77,188,72,15,190,72,5,64,136,77,189,72,15,190,72,6,64,136,77,190,72,15
	.byte 190,64,7,64,136,69,191,65,131,125,0,0,73,141,69,44,72,15,190,77,184,64,136,8,72,15,190,77,185,64,136,72
	.byte 1,72,15,190,77,186,64,136,72,2,72,15,190,77,187,64,136,72,3,72,15,190,77,188,64,136,72,4,72,15,190,77
	.byte 189,64,136,72,5,72,15,190,77,190,64,136,72,6,72,15,190,77,191,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,133,2,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1324
	.byte 72,15,190,8,64,136,77,192,72,15,190,72,1,64,136,77,193,72,15,190,72,2,64,136,77,194,72,15,190,72,3,64
	.byte 136,77,195,72,15,190,72,4,64,136,77,196,72,15,190,72,5,64,136,77,197,72,15,190,72,6,64,136,77,198,72,15
	.byte 190,64,7,64,136,69,199,65,131,125,0,0,73,141,69,44,72,15,190,77,192,64,136,8,72,15,190,77,193,64,136,72
	.byte 1,72,15,190,77,194,64,136,72,2,72,15,190,77,195,64,136,72,3,72,15,190,77,196,64,136,72,4,72,15,190,77
	.byte 197,64,136,72,5,72,15,190,77,198,64,136,72,6,72,15,190,77,199,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,185,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1332
	.byte 72,15,190,8,64,136,77,200,72,15,190,72,1,64,136,77,201,72,15,190,72,2,64,136,77,202,72,15,190,72,3,64
	.byte 136,77,203,72,15,190,72,4,64,136,77,204,72,15,190,72,5,64,136,77,205,72,15,190,72,6,64,136,77,206,72,15
	.byte 190,64,7,64,136,69,207,65,131,125,0,0,73,141,69,44,72,15,190,77,200,64,136,8,72,15,190,77,201,64,136,72
	.byte 1,72,15,190,77,202,64,136,72,2,72,15,190,77,203,64,136,72,3,72,15,190,77,204,64,136,72,4,72,15,190,77
	.byte 205,64,136,72,5,72,15,190,77,206,64,136,72,6,72,15,190,77,207,64,136,72,7,65,131,125,0,0,51,192,73,141
	.byte 77,16,72,199,1,0,0,0,0,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,233,237,0,0,0,65,131,252,128,15,140,227,0,0,0,65,129,252,128,0,0,0,15,141,214,0
	.byte 0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 708
	.byte 72,15,190,8,64,136,77,208,72,15,190,72,1,64,136,77,209,72,15,190,72,2,64,136,77,210,72,15,190,72,3,64
	.byte 136,77,211,72,15,190,72,4,64,136,77,212,72,15,190,72,5,64,136,77,213,72,15,190,72,6,64,136,77,214,72,15
	.byte 190,64,7,64,136,69,215,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1340
	.byte 190,17,0,0,0
call .Lp_2

	.byte 68,136,96,16,65,131,125,0,0,73,141,77,44,72,15,190,85,208,64,136,17,72,15,190,85,209,64,136,81,1,72,15
	.byte 190,85,210,64,136,81,2,72,15,190,85,211,64,136,81,3,72,15,190,85,212,64,136,81,4,72,15,190,85,213,64,136
	.byte 81,5,72,15,190,85,214,64,136,81,6,72,15,190,85,215,64,136,81,7,65,131,125,0,0,73,141,77,16,72,137,1
	.byte 193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,253,72,129,199,216,254,255,255
call .Lp_82

	.byte 72,15,182,192,133,192,15,133,163,226,255,255,72,199,133,208,254,255,255,0,0,0,0,72,131,236,8,232,23,0,0,0
	.byte 72,131,196,8,72,139,133,208,254,255,255,72,133,192,116,5
call .Lp_83

	.byte 235,65,72,137,165,192,254,255,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,197,72,5,216,254,255,255,72,137,133,200,254,255,255,72,199,0,0,0,0,0,72,139,165,192,254,255,255,195,73
	.byte 139,255
call .Lp_90

	.byte 72,139,93,216,76,139,101,224,76,139,109,232,76,139,117,240,76,139,125,248,201,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,251,9,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,17,10,0,0,235,239,190,62,11,0,0,235,232,190,208,12,0,0,235,225,190,40,18,0,0,235,218,190,128,23,0
	.byte 0,235,211,190,40,29,0,0,235,204

	.size Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody
.Lme_34:
.text 0
	.balign 16
.Lm_35:
	.local Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody:

	.byte 85,72,139,236,72,131,236,80,76,137,117,240,76,137,125,248,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,69,208,72,137,69,216,72,137,69,224,198,69,232,0,198,69,233,0,198,69,234,0,198,69,235,0,198,69
	.byte 236,0,198,69,237,0,198,69,238,0,198,69,239,0,73,139,255
call .Lp_91

	.byte 73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,245,72,131,198,208,72,139,248,131,56,0
call .Lp_79

	.byte 233,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 76,139,117,216,73,139,198,72,139,200,131,57,0,72,131,192,44,72,15,190,8,64,136,77,232,72,15,190,72,1,64,136
	.byte 77,233,72,15,190,72,2,64,136,77,234,72,15,190,72,3,64,136,77,235,72,15,190,72,4,64,136,77,236,72,15,190
	.byte 72,5,64,136,77,237,72,15,190,72,6,64,136,77,238,72,15,190,64,7,64,136,69,239,15,182,69,237,133,192,15,133
	.byte 24,0,0,0,73,139,254
call .Lp_92

	.byte 72,15,182,192,133,192,116,8,73,139,255
call .Lp_91

	.byte 77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,253,72,131,199,208
call .Lp_82

	.byte 72,15,182,192,133,192,15,133,74,255,255,255,72,199,69,200,0,0,0,0,72,131,236,8,232,20,0,0,0,72,131,196
	.byte 8,72,139,69,200,72,133,192,116,5
call .Lp_83

	.byte 235,54,72,137,101,184,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,197,72,131,192,208,72,137,69,192,72,199,0,0,0,0,0,72,139,101,184,195,76,139,117,240,76,139,125,248,201
	.byte 195

	.size Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody
.Lme_35:
.text 0
	.balign 16
.Lm_36:
	.local Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction
	.type Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction,@function
Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction:

	.byte 72,129,236,152,0,0,0,76,137,44,36,76,137,116,36,8,76,137,124,36,16,76,139,255,198,132,36,136,0,0,0,0
	.byte 198,132,36,137,0,0,0,0,198,132,36,138,0,0,0,0,198,132,36,139,0,0,0,0,198,132,36,140,0,0,0,0
	.byte 198,132,36,141,0,0,0,0,198,132,36,142,0,0,0,0,198,132,36,143,0,0,0,0,65,131,63,0,77,139,119,16
	.byte 77,133,246,116,30,73,139,6,72,139,0,72,139,64,16,72,139,64,8,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1348
	.byte 72,59,193,15,133,111,11,0,0,65,131,62,0,73,99,70,40,65,131,63,0,73,99,79,40,65,131,63,0,73,141,87
	.byte 44,72,15,190,50,64,136,180,36,136,0,0,0,72,15,190,114,1,64,136,180,36,137,0,0,0,72,15,190,114,2,64
	.byte 136,180,36,138,0,0,0,72,15,190,114,3,64,136,180,36,139,0,0,0,72,15,190,114,4,64,136,180,36,140,0,0
	.byte 0,72,15,190,114,5,64,136,180,36,141,0,0,0,72,15,190,114,6,64,136,180,36,142,0,0,0,72,15,190,82,7
	.byte 64,136,148,36,143,0,0,0,15,182,188,36,136,0,0,0,190,1,0,0,0,186,2,0,0,0,129,255,255,0,0,0
	.byte 72,15,68,214,3,202,131,193,4,76,139,240,68,43,241,73,139,198,131,248,128,124,6,65,131,254,127,126,7,51,192,233
	.byte 158,10,0,0,65,131,63,0,73,141,71,44,72,15,190,8,64,136,140,36,136,0,0,0,72,15,190,72,1,64,136,140
	.byte 36,137,0,0,0,72,15,190,72,2,64,136,140,36,138,0,0,0,72,15,190,72,3,64,136,140,36,139,0,0,0,72
	.byte 15,190,72,4,64,136,140,36,140,0,0,0,72,15,190,72,5,64,136,140,36,141,0,0,0,72,15,190,72,6,64,136
	.byte 140,36,142,0,0,0,72,15,190,64,7,64,136,132,36,143,0,0,0,68,15,182,180,36,138,0,0,0,73,139,198,76
	.byte 139,232,65,131,237,55,65,131,253,13,115,24,73,139,197,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1356
	.byte 72,3,193,72,139,0,255,224,65,129,254,187,0,0,0,15,132,63,9,0,0,233,231,9,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1364
	.byte 72,15,190,8,64,136,140,36,128,0,0,0,72,15,190,72,1,64,136,140,36,129,0,0,0,72,15,190,72,2,64,136
	.byte 140,36,130,0,0,0,72,15,190,72,3,64,136,140,36,131,0,0,0,72,15,190,72,4,64,136,140,36,132,0,0,0
	.byte 72,15,190,72,5,64,136,140,36,133,0,0,0,72,15,190,72,6,64,136,140,36,134,0,0,0,72,15,190,64,7,64
	.byte 136,132,36,135,0,0,0,65,131,63,0,73,141,71,44,72,15,190,140,36,128,0,0,0,64,136,8,72,15,190,140,36
	.byte 129,0,0,0,64,136,72,1,72,15,190,140,36,130,0,0,0,64,136,72,2,72,15,190,140,36,131,0,0,0,64,136
	.byte 72,3,72,15,190,140,36,132,0,0,0,64,136,72,4,72,15,190,140,36,133,0,0,0,64,136,72,5,72,15,190,140
	.byte 36,134,0,0,0,64,136,72,6,72,15,190,140,36,135,0,0,0,64,136,72,7,233,5,9,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1372
	.byte 72,15,190,8,64,136,76,36,120,72,15,190,72,1,64,136,76,36,121,72,15,190,72,2,64,136,76,36,122,72,15,190
	.byte 72,3,64,136,76,36,123,72,15,190,72,4,64,136,76,36,124,72,15,190,72,5,64,136,76,36,125,72,15,190,72,6
	.byte 64,136,76,36,126,72,15,190,64,7,64,136,68,36,127,65,131,63,0,73,141,71,44,72,15,190,76,36,120,64,136,8
	.byte 72,15,190,76,36,121,64,136,72,1,72,15,190,76,36,122,64,136,72,2,72,15,190,76,36,123,64,136,72,3,72,15
	.byte 190,76,36,124,64,136,72,4,72,15,190,76,36,125,64,136,72,5,72,15,190,76,36,126,64,136,72,6,72,15,190,76
	.byte 36,127,64,136,72,7,233,83,8,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1380
	.byte 72,15,190,8,64,136,76,36,112,72,15,190,72,1,64,136,76,36,113,72,15,190,72,2,64,136,76,36,114,72,15,190
	.byte 72,3,64,136,76,36,115,72,15,190,72,4,64,136,76,36,116,72,15,190,72,5,64,136,76,36,117,72,15,190,72,6
	.byte 64,136,76,36,118,72,15,190,64,7,64,136,68,36,119,65,131,63,0,73,141,71,44,72,15,190,76,36,112,64,136,8
	.byte 72,15,190,76,36,113,64,136,72,1,72,15,190,76,36,114,64,136,72,2,72,15,190,76,36,115,64,136,72,3,72,15
	.byte 190,76,36,116,64,136,72,4,72,15,190,76,36,117,64,136,72,5,72,15,190,76,36,118,64,136,72,6,72,15,190,76
	.byte 36,119,64,136,72,7,233,161,7,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1388
	.byte 72,15,190,8,64,136,76,36,104,72,15,190,72,1,64,136,76,36,105,72,15,190,72,2,64,136,76,36,106,72,15,190
	.byte 72,3,64,136,76,36,107,72,15,190,72,4,64,136,76,36,108,72,15,190,72,5,64,136,76,36,109,72,15,190,72,6
	.byte 64,136,76,36,110,72,15,190,64,7,64,136,68,36,111,65,131,63,0,73,141,71,44,72,15,190,76,36,104,64,136,8
	.byte 72,15,190,76,36,105,64,136,72,1,72,15,190,76,36,106,64,136,72,2,72,15,190,76,36,107,64,136,72,3,72,15
	.byte 190,76,36,108,64,136,72,4,72,15,190,76,36,109,64,136,72,5,72,15,190,76,36,110,64,136,72,6,72,15,190,76
	.byte 36,111,64,136,72,7,233,239,6,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1396
	.byte 72,15,190,8,64,136,76,36,96,72,15,190,72,1,64,136,76,36,97,72,15,190,72,2,64,136,76,36,98,72,15,190
	.byte 72,3,64,136,76,36,99,72,15,190,72,4,64,136,76,36,100,72,15,190,72,5,64,136,76,36,101,72,15,190,72,6
	.byte 64,136,76,36,102,72,15,190,64,7,64,136,68,36,103,65,131,63,0,73,141,71,44,72,15,190,76,36,96,64,136,8
	.byte 72,15,190,76,36,97,64,136,72,1,72,15,190,76,36,98,64,136,72,2,72,15,190,76,36,99,64,136,72,3,72,15
	.byte 190,76,36,100,64,136,72,4,72,15,190,76,36,101,64,136,72,5,72,15,190,76,36,102,64,136,72,6,72,15,190,76
	.byte 36,103,64,136,72,7,233,61,6,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1404
	.byte 72,15,190,8,64,136,76,36,88,72,15,190,72,1,64,136,76,36,89,72,15,190,72,2,64,136,76,36,90,72,15,190
	.byte 72,3,64,136,76,36,91,72,15,190,72,4,64,136,76,36,92,72,15,190,72,5,64,136,76,36,93,72,15,190,72,6
	.byte 64,136,76,36,94,72,15,190,64,7,64,136,68,36,95,65,131,63,0,73,141,71,44,72,15,190,76,36,88,64,136,8
	.byte 72,15,190,76,36,89,64,136,72,1,72,15,190,76,36,90,64,136,72,2,72,15,190,76,36,91,64,136,72,3,72,15
	.byte 190,76,36,92,64,136,72,4,72,15,190,76,36,93,64,136,72,5,72,15,190,76,36,94,64,136,72,6,72,15,190,76
	.byte 36,95,64,136,72,7,233,139,5,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1412
	.byte 72,15,190,8,64,136,76,36,80,72,15,190,72,1,64,136,76,36,81,72,15,190,72,2,64,136,76,36,82,72,15,190
	.byte 72,3,64,136,76,36,83,72,15,190,72,4,64,136,76,36,84,72,15,190,72,5,64,136,76,36,85,72,15,190,72,6
	.byte 64,136,76,36,86,72,15,190,64,7,64,136,68,36,87,65,131,63,0,73,141,71,44,72,15,190,76,36,80,64,136,8
	.byte 72,15,190,76,36,81,64,136,72,1,72,15,190,76,36,82,64,136,72,2,72,15,190,76,36,83,64,136,72,3,72,15
	.byte 190,76,36,84,64,136,72,4,72,15,190,76,36,85,64,136,72,5,72,15,190,76,36,86,64,136,72,6,72,15,190,76
	.byte 36,87,64,136,72,7,233,217,4,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1420
	.byte 72,15,190,8,64,136,76,36,72,72,15,190,72,1,64,136,76,36,73,72,15,190,72,2,64,136,76,36,74,72,15,190
	.byte 72,3,64,136,76,36,75,72,15,190,72,4,64,136,76,36,76,72,15,190,72,5,64,136,76,36,77,72,15,190,72,6
	.byte 64,136,76,36,78,72,15,190,64,7,64,136,68,36,79,65,131,63,0,73,141,71,44,72,15,190,76,36,72,64,136,8
	.byte 72,15,190,76,36,73,64,136,72,1,72,15,190,76,36,74,64,136,72,2,72,15,190,76,36,75,64,136,72,3,72,15
	.byte 190,76,36,76,64,136,72,4,72,15,190,76,36,77,64,136,72,5,72,15,190,76,36,78,64,136,72,6,72,15,190,76
	.byte 36,79,64,136,72,7,233,39,4,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1428
	.byte 72,15,190,8,64,136,76,36,64,72,15,190,72,1,64,136,76,36,65,72,15,190,72,2,64,136,76,36,66,72,15,190
	.byte 72,3,64,136,76,36,67,72,15,190,72,4,64,136,76,36,68,72,15,190,72,5,64,136,76,36,69,72,15,190,72,6
	.byte 64,136,76,36,70,72,15,190,64,7,64,136,68,36,71,65,131,63,0,73,141,71,44,72,15,190,76,36,64,64,136,8
	.byte 72,15,190,76,36,65,64,136,72,1,72,15,190,76,36,66,64,136,72,2,72,15,190,76,36,67,64,136,72,3,72,15
	.byte 190,76,36,68,64,136,72,4,72,15,190,76,36,69,64,136,72,5,72,15,190,76,36,70,64,136,72,6,72,15,190,76
	.byte 36,71,64,136,72,7,233,117,3,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1436
	.byte 72,15,190,8,64,136,76,36,56,72,15,190,72,1,64,136,76,36,57,72,15,190,72,2,64,136,76,36,58,72,15,190
	.byte 72,3,64,136,76,36,59,72,15,190,72,4,64,136,76,36,60,72,15,190,72,5,64,136,76,36,61,72,15,190,72,6
	.byte 64,136,76,36,62,72,15,190,64,7,64,136,68,36,63,65,131,63,0,73,141,71,44,72,15,190,76,36,56,64,136,8
	.byte 72,15,190,76,36,57,64,136,72,1,72,15,190,76,36,58,64,136,72,2,72,15,190,76,36,59,64,136,72,3,72,15
	.byte 190,76,36,60,64,136,72,4,72,15,190,76,36,61,64,136,72,5,72,15,190,76,36,62,64,136,72,6,72,15,190,76
	.byte 36,63,64,136,72,7,233,195,2,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1444
	.byte 72,15,190,8,64,136,76,36,48,72,15,190,72,1,64,136,76,36,49,72,15,190,72,2,64,136,76,36,50,72,15,190
	.byte 72,3,64,136,76,36,51,72,15,190,72,4,64,136,76,36,52,72,15,190,72,5,64,136,76,36,53,72,15,190,72,6
	.byte 64,136,76,36,54,72,15,190,64,7,64,136,68,36,55,65,131,63,0,73,141,71,44,72,15,190,76,36,48,64,136,8
	.byte 72,15,190,76,36,49,64,136,72,1,72,15,190,76,36,50,64,136,72,2,72,15,190,76,36,51,64,136,72,3,72,15
	.byte 190,76,36,52,64,136,72,4,72,15,190,76,36,53,64,136,72,5,72,15,190,76,36,54,64,136,72,6,72,15,190,76
	.byte 36,55,64,136,72,7,233,17,2,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1452
	.byte 72,15,190,8,64,136,76,36,40,72,15,190,72,1,64,136,76,36,41,72,15,190,72,2,64,136,76,36,42,72,15,190
	.byte 72,3,64,136,76,36,43,72,15,190,72,4,64,136,76,36,44,72,15,190,72,5,64,136,76,36,45,72,15,190,72,6
	.byte 64,136,76,36,46,72,15,190,64,7,64,136,68,36,47,65,131,63,0,73,141,71,44,72,15,190,76,36,40,64,136,8
	.byte 72,15,190,76,36,41,64,136,72,1,72,15,190,76,36,42,64,136,72,2,72,15,190,76,36,43,64,136,72,3,72,15
	.byte 190,76,36,44,64,136,72,4,72,15,190,76,36,45,64,136,72,5,72,15,190,76,36,46,64,136,72,6,72,15,190,76
	.byte 36,47,64,136,72,7,233,95,1,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1460
	.byte 72,15,190,8,64,136,76,36,32,72,15,190,72,1,64,136,76,36,33,72,15,190,72,2,64,136,76,36,34,72,15,190
	.byte 72,3,64,136,76,36,35,72,15,190,72,4,64,136,76,36,36,72,15,190,72,5,64,136,76,36,37,72,15,190,72,6
	.byte 64,136,76,36,38,72,15,190,64,7,64,136,68,36,39,65,131,63,0,73,141,71,44,72,15,190,76,36,32,64,136,8
	.byte 72,15,190,76,36,33,64,136,72,1,72,15,190,76,36,34,64,136,72,2,72,15,190,76,36,35,64,136,72,3,72,15
	.byte 190,76,36,36,64,136,72,4,72,15,190,76,36,37,64,136,72,5,72,15,190,76,36,38,64,136,72,6,72,15,190,76
	.byte 36,39,64,136,72,7,233,173,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1468
	.byte 72,15,190,8,64,136,76,36,24,72,15,190,72,1,64,136,76,36,25,72,15,190,72,2,64,136,76,36,26,72,15,190
	.byte 72,3,64,136,76,36,27,72,15,190,72,4,64,136,76,36,28,72,15,190,72,5,64,136,76,36,29,72,15,190,72,6
	.byte 64,136,76,36,30,72,15,190,64,7,64,136,68,36,31,65,131,63,0,73,141,71,44,72,15,190,76,36,24,64,136,8
	.byte 72,15,190,76,36,25,64,136,72,1,72,15,190,76,36,26,64,136,72,2,72,15,190,76,36,27,64,136,72,3,72,15
	.byte 190,76,36,28,64,136,72,4,72,15,190,76,36,29,64,136,72,5,72,15,190,76,36,30,64,136,72,6,72,15,190,76
	.byte 36,31,64,136,72,7,184,1,0,0,0,76,139,44,36,76,139,116,36,8,76,139,124,36,16,72,129,196,152,0,0,0
	.byte 195,190,132,11,0,0,191,19,1,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction,.-Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction
.Lme_36:
.text 0
	.balign 16
.Lm_37:
	.local Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody
	.type Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody,@function
Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody:

	.byte 85,72,139,236,72,131,236,80,76,137,117,240,76,137,125,248,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,69,216,72,137,69,224,72,137,69,232,69,51,246,73,139,255,65,131,63,0
call .Lp_78

	.byte 72,139,245,72,131,198,216,72,139,248,131,56,0
call .Lp_79

	.byte 233,61,0,0,0,72,141,100,36,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 76,139,125,224,73,139,199,131,56,0,69,137,119,40,73,139,255,65,131,63,0
call .Lp_93

	.byte 68,3,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,253,72,131,199,216
call .Lp_82

	.byte 72,15,182,192,133,192,117,173,72,199,69,208,0,0,0,0,72,131,236,8,232,20,0,0,0,72,131,196,8,72,139,69
	.byte 208,72,133,192,116,5
call .Lp_83

	.byte 235,54,72,137,101,192,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 844
	.byte 72,139,197,72,131,192,216,72,137,69,200,72,199,0,0,0,0,0,72,139,101,192,195,76,139,117,240,76,139,125,248,201
	.byte 195

	.size Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody,.-Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody
.Lme_37:
.text 0
	.balign 16
.Lm_38:
	.local Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,76,137,44,36,76,137,116,36,8,76,137,124,36,16,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,216,0,0,0,65,131,63,0,65,15,183,135,136,0,0,0,131,224,64,133,192,64,15,151,192,72,15
	.byte 182,192,72,15,182,192,72,15,182,192,133,192,117,8,73,139,199,233,152,0,0,0,73,139,255,65,131,63,0
call .Lp_94

	.byte 72,15,182,192,133,192,116,8,73,139,199,233,124,0,0,0,65,131,63,0,77,139,119,24,77,133,246,116,30,73,139,6
	.byte 72,139,0,72,139,64,16,72,139,64,24,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 508
	.byte 72,59,193,15,133,138,0,0,0,73,139,254
call .Lp_95

	.byte 76,139,240,233,57,0,0,0,102,144,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,73,139,247
call .Lp_96

	.byte 76,139,232,72,133,192,116,5,73,139,197,235,19,73,139,254
call .Lp_95

	.byte 76,139,240,77,133,246,117,196,73,139,199,76,139,44,36,76,139,116,36,8,76,139,124,36,16,72,131,196,24,195,73,139
	.byte 61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,159,0,0,0,191,19,1,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition
.Lme_38:
.text 0
	.balign 16
.Lm_39:
	.local Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,63,0,0,0,102,102,144,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,255
call .Lp_97

	.byte 76,139,240,73,59,199,117,5,73,139,199,235,5,77,139,254,235,210,76,139,52,36,76,139,124,36,8,72,131,196,24,195
	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition
.Lme_39:
.text 0
	.balign 16
.Lm_3a:
	.local Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,117,4,51,192,235,32,65,131,63,0,77,139,119,96,73,139,198,72,133,192,117,4,51,192,235,12,73,139,254
	.byte 73,139,6,255,144,0,1,0,0,76,139,52,36,76,139,124,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition
.Lme_3a:
.text 0
	.balign 16
.Lm_3b:
	.local Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,60,36,72,139,199,131,56,0
call .Lp_98

	.byte 72,139,248,72,139,116,36,8
call .Lp_99

	.byte 72,131,196,24,195

	.size Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition
.Lme_3b:
.text 0
	.balign 16
.Lm_3c:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,241,0,0,0,73,139,255,65,131,63,0
call .Lp_100

	.byte 72,139,208,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1476
	.byte 72,139,0,72,139,200,76,139,250,76,139,241,72,133,192,15,133,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1484
	.byte 72,139,0,72,137,68,36,16,72,133,192,15,132,227,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1492
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,16,72,133,201,15,132,181,0,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1500
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1508
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1516
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1476
	.byte 72,137,1,76,139,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1524
	.byte 73,139,254
call .Lp_101

	.byte 72,139,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1532
	.byte 73,139,255
call .Lp_102

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,202,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,248,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition,.-Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition
.Lme_3c:
.text 0
	.balign 16
.Lm_3d:
	.local Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference
	.type Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference,@function
Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference:

	.byte 72,131,236,8,76,137,60,36,76,139,255,65,131,63,0,73,99,71,32,255,192,76,139,60,36,72,131,196,8,195

	.size Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference,.-Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference
.Lme_3d:
.text 0
	.balign 16
.Lm_3e:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration:

	.byte 72,131,236,24,72,137,124,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,199,4,36,0,0,0,0,72,139,68,36,8,72,133,192,15,132,42,0,0,0,72,139,124,36,8,72,139,244
call .Lp_103

	.byte 72,15,182,192,133,192,116,6,72,139,4,36,235,10,72,139,124,36,8
call .Lp_104

	.byte 72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration
.Lme_3e:
.text 0
	.balign 16
.Lm_3f:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_:

	.byte 72,131,236,88,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,139,247,72,137,116,36,64,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,68,36,40,72,137,68,36,48,72,137,68,36,56,72,137,68,36,24,72,137,68,36,32,72,139,68,36,64
	.byte 72,199,0,0,0,0,0,73,139,254,65,131,62,0
call .Lp_105

	.byte 72,15,182,192,133,192,15,133,34,0,0,0,73,139,254,65,131,62,0
call .Lp_106

	.byte 72,139,200,131,57,0,72,99,64,24,131,248,1,116,7,51,192,233,152,1,0,0,73,139,254,65,131,62,0
call .Lp_106

	.byte 72,139,248,51,246,131,56,0
call .Lp_107

	.byte 76,139,232,72,139,200,131,57,0,72,139,120,16,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1540
	.byte 73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1548
call .Lp_108

	.byte 72,15,182,192,133,192,117,7,51,192,233,80,1,0,0,65,131,62,0,65,15,183,70,46,72,15,183,192,72,137,68,36
	.byte 72,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1556
	.byte 190,64,0,0,0
call .Lp_2

	.byte 72,139,76,36,72,137,72,16,76,139,240,73,139,253,65,131,125,0,0
call .Lp_109

	.byte 72,141,116,36,40,72,139,248,51,210,131,56,0
call .Lp_110

	.byte 72,141,68,36,40,72,131,192,8,72,139,8,72,137,76,36,24,72,139,64,8,72,137,68,36,32,76,139,108,36,32,77
	.byte 133,237,15,132,31,0,0,0,73,139,69,0,72,139,0,72,139,64,16,72,139,64,8,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1564
	.byte 72,59,193,15,133,230,0,0,0,77,139,229,76,139,108,36,40,73,139,197,72,133,192,15,132,187,0,0,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1572
	.byte 73,139,253
call .Lp_11

	.byte 72,15,182,192,133,192,117,29,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1580
	.byte 73,139,253
call .Lp_11

	.byte 72,15,182,192,133,192,15,132,137,0,0,0,235,35,65,131,62,0,73,141,70,40,76,137,32,193,232,9,72,37,255,255
	.byte 127,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,235,33,65,131,62,0,73,141,70,32,76,137,32,193,232,9,72,37,255,255,127,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,73,139,254,65,131,62,0
call .Lp_111

	.byte 72,139,76,36,64,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,184,1,0,0,0,76,139,36,36,76,139,108,36,8,76,139,116,36,16,72,131,196,88,195,72,139
	.byte 116,36,40,191,40,1,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,251,0,0,0,191,19,1,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_
.Lme_3f:
.text 0
	.balign 16
.Lm_40:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration:

	.byte 85,72,139,236,72,131,236,96,76,137,109,232,76,137,117,240,76,137,125,248,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,69,208,72,137,69,216,72,137,69,224,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1588
	.byte 190,48,0,0,0
call .Lp_2

	.byte 72,137,69,168,72,139,248,51,246
call .Lp_112

	.byte 72,139,69,168,76,139,240,73,139,255,65,131,63,0
call .Lp_106

	.byte 72,139,245,72,131,198,208,72,139,248,131,56,0
call .Lp_113

	.byte 233,66,0,0,0,72,141,100,36,0,144,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1596
	.byte 76,139,109,216,73,139,255,73,139,245
call .Lp_114

	.byte 76,139,232,73,139,254,73,139,245,65,131,62,0
call .Lp_115

	.byte 77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1596
	.byte 72,139,253,72,131,199,208
call .Lp_116

	.byte 72,15,182,192,133,192,117,169,72,199,69,200,0,0,0,0,72,131,236,8,232,20,0,0,0,72,131,196,8,72,139,69
	.byte 200,72,133,192,116,5
call .Lp_83

	.byte 235,54,72,137,101,184,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1596
	.byte 72,139,197,72,131,192,208,72,137,69,192,72,199,0,0,0,0,0,72,139,101,184,195,73,139,198,76,139,109,232,76,139
	.byte 117,240,76,139,125,248,201,195

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration
.Lme_40:
.text 0
	.balign 16
.Lm_41:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute:

	.byte 72,131,236,24,76,137,44,36,76,137,124,36,8,72,137,124,36,16,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,73,139,71,16,72,139,248,72,139,0,255,144,168,0,0,0,72,139,248
call .Lp_117

	.byte 72,139,200,72,133,192,64,15,148,192,72,15,182,192,76,139,233,133,192,15,133,63,0,0,0,73,139,253,72,139,116,36
	.byte 16
call .Lp_118

	.byte 76,139,232,72,133,192,15,132,76,0,0,0,73,139,253,73,139,247
call .Lp_119

	.byte 73,139,253,73,139,69,0,255,144,160,0,0,0,76,139,44,36,76,139,124,36,8,72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,9,1,0,0
call .Lp_12

	.byte 72,139,240,191,187,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 191,20,1,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute
.Lme_41:
.text 0
	.balign 16
.Lm_42:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:

	.byte 72,131,236,24,76,137,44,36,76,137,124,36,8,72,137,124,36,16,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 65,131,63,0,77,139,111,24,77,133,237,116,16,73,99,69,24,133,192,65,15,148,197,77,15,182,237,235,6,65,189,1
	.byte 0,0,0,73,15,182,197,133,192,64,15,148,192,72,15,182,192,72,15,182,192,133,192,116,13,72,139,124,36,16,73,139
	.byte 247
call .Lp_120

	.byte 65,131,63,0,77,139,111,32,77,133,237,116,16,73,99,69,24,133,192,65,15,148,197,77,15,182,237,235,6,65,189,1
	.byte 0,0,0,73,15,182,197,133,192,64,15,148,192,72,15,182,192,72,15,182,192,133,192,116,13,72,139,124,36,16,73,139
	.byte 247
call .Lp_121

	.byte 76,139,44,36,76,139,124,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
.Lme_42:
.text 0
	.balign 16
.Lm_43:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:

	.byte 85,72,139,236,72,129,236,144,0,0,0,76,137,109,240,76,137,117,248,76,139,247,72,137,181,120,255,255,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,69,160,72,137,69,168,72,137,69,176,72,137,69,184,72,137,69,192,72,137,69,200,72,137,69,208,72,137
	.byte 69,216,72,137,69,224,72,137,69,232,73,139,6,76,139,104,24,72,139,189,120,255,255,255,72,139,199,131,56,0
call .Lp_122

	.byte 72,139,245,72,131,198,160,72,139,248,131,56,0
call .Lp_123

	.byte 233,120,0,0,0,72,141,100,36,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,197,72,131,192,160,72,131,192,8,72,139,8,72,137,77,200,72,139,72,8,72,137,77,208,72,139,64,16,72,137
	.byte 69,216,72,139,117,200,73,139,253,65,131,125,0,0
call .Lp_124

	.byte 72,139,205,72,131,193,200,72,131,193,8,72,139,17,72,137,85,224,72,139,73,8,72,137,77,232,72,139,85,232,72,139
	.byte 248,73,139,246,131,56,0
call .Lp_125

	.byte 72,139,253,72,131,199,160
call .Lp_126

	.byte 72,15,182,192,133,192,15,133,117,255,255,255,72,199,69,152,0,0,0,0,72,131,236,8,232,20,0,0,0,72,131,196
	.byte 8,72,139,69,152,72,133,192,116,5
call .Lp_83

	.byte 235,47,72,137,101,136,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,197,72,131,192,160,72,137,69,144,72,199,0,0,0,0,0,72,139,101,136,195,76,139,109,240,76,139,117,248,201
	.byte 195

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
.Lme_43:
.text 0
	.balign 16
.Lm_44:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:

	.byte 85,72,139,236,72,129,236,144,0,0,0,76,137,109,240,76,137,117,248,76,139,247,72,137,181,120,255,255,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 51,192,72,137,69,160,72,137,69,168,72,137,69,176,72,137,69,184,72,137,69,192,72,137,69,200,72,137,69,208,72,137
	.byte 69,216,72,137,69,224,72,137,69,232,73,139,6,76,139,104,24,72,139,189,120,255,255,255,72,139,199,131,56,0
call .Lp_109

	.byte 72,139,245,72,131,198,160,72,139,248,131,56,0
call .Lp_123

	.byte 233,123,0,0,0,72,141,100,36,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,197,72,131,192,160,72,131,192,8,72,139,8,72,137,77,200,72,139,72,8,72,137,77,208,72,139,64,16,72,137
	.byte 69,216,72,139,117,200,73,139,253,65,131,125,0,0
call .Lp_127

	.byte 72,139,205,72,131,193,200,72,131,193,8,72,139,17,72,137,85,224,72,139,73,8,72,137,77,232,72,139,85,232,72,139
	.byte 248,73,139,246,51,201,72,139,0,255,144,240,0,0,0,72,139,253,72,131,199,160
call .Lp_126

	.byte 72,15,182,192,133,192,15,133,114,255,255,255,72,199,69,152,0,0,0,0,72,131,236,8,232,20,0,0,0,72,131,196
	.byte 8,72,139,69,152,72,133,192,116,5
call .Lp_83

	.byte 235,47,72,137,101,136,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,197,72,131,192,160,72,137,69,144,72,199,0,0,0,0,0,72,139,101,136,195,76,139,109,240,76,139,117,248,201
	.byte 195

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
.Lme_44:
.text 0
	.balign 16
.Lm_45:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration:

	.byte 85,72,139,236,72,131,236,96,76,137,125,248,72,137,125,192,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,199,69,240,0,0,0,0,72,139,69,192,72,137,69,176,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1604
	.byte 190,1,0,0,0
call .Lp_70

	.byte 72,137,69,168,72,137,69,184,65,131,63,0,65,15,183,71,46,72,15,183,192,72,137,69,160,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1612
	.byte 190,20,0,0,0
call .Lp_2

	.byte 72,139,208,72,139,69,168,72,139,77,160,137,74,16,72,139,248,51,246,72,139,0,255,144,8,1,0,0,72,139,117,184
	.byte 72,139,125,176
call .Lp_128

	.byte 76,139,248,77,133,255,15,132,30,0,0,0,73,139,7,72,139,0,72,139,64,16,72,139,64,16,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1620
	.byte 72,59,193,15,133,175,0,0,0,76,137,125,240,233,141,0,0,0,72,137,69,232,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,69,192,72,137,69,184,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1604
	.byte 51,246
call .Lp_70

	.byte 72,139,240,72,139,125,184
call .Lp_128

	.byte 72,137,69,208,72,133,192,15,132,34,0,0,0,72,139,69,208,72,139,0,72,139,0,72,139,64,16,72,139,64,16,73
	.byte 139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1620
	.byte 72,59,193,15,133,46,0,0,0,72,139,69,208,72,137,69,240
call .Lp_129

	.byte 72,137,69,200,72,133,192,116,12,72,139,69,200,72,139,248
call .Lp_14

	.byte 235,0,72,139,69,240,76,139,125,248,201,195,190,67,0,0,0,191,19,1,0,0
call .Lp_19

	.byte 190,181,0,0,0,235,239

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration
.Lme_45:
.text 0
	.balign 16
.Lm_46:
	.local Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition
	.type Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition,@function
Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition:

	.byte 85,72,139,236,72,129,236,192,0,0,0,76,137,109,232,76,137,117,240,76,137,125,248,76,139,239,72,137,117,144,76,139
	.byte 250,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,237,15,132,221,1,0,0,77,133,255,15,132,174,1,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1628
	.byte 190,48,0,0,0
call .Lp_2

	.byte 72,137,69,128,72,139,248,15,183,117,144
call .Lp_130

	.byte 73,139,255,65,131,63,0
call .Lp_131

	.byte 73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1540
	.byte 73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1548
	.byte 72,139,248,72,139,0,255,80,104,72,137,133,96,255,255,255,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1636
	.byte 190,40,0,0,0
call .Lp_2

	.byte 72,139,141,96,255,255,255,72,139,208,72,131,194,16,72,137,10,193,234,9,72,129,226,255,255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,76,139,240,72,139,248,131,56,0
call .Lp_109

	.byte 72,137,133,120,255,255,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1572
	.byte 72,137,133,112,255,255,255,73,139,255,65,131,63,0
call .Lp_131

	.byte 72,139,248,131,56,0
call .Lp_132

	.byte 72,137,133,104,255,255,255,73,139,253,73,139,69,0,255,144,232,0,0,0,72,139,248,72,139,0,255,80,72,72,139,208
	.byte 72,139,181,104,255,255,255,51,192,72,137,69,152,72,137,69,160,72,139,253,72,131,199,152
call .Lp_133

	.byte 72,139,181,112,255,255,255,72,139,69,152,72,137,69,192,72,139,69,160,72,137,69,200,51,192,72,137,69,168,72,137,69
	.byte 176,72,137,69,184,72,139,253,72,131,199,168,72,139,85,192,72,139,77,200
call .Lp_134

	.byte 72,139,133,120,255,255,255,72,139,77,168,72,137,77,208,72,139,77,176,72,137,77,216,72,139,77,184,72,137,77,224,72
	.byte 139,248,72,139,77,208,72,137,12,36,72,139,77,216,72,137,76,36,8,72,139,77,224,72,137,76,36,16,131,56,0
call .Lp_135

	.byte 72,139,69,128,72,139,200,72,137,77,136,72,139,248,131,56,0
call .Lp_106

	.byte 72,139,248,73,139,246,131,56,0
call .Lp_136

	.byte 72,139,69,136,76,139,109,232,76,139,117,240,76,139,125,248,201,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,29,1,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition,.-Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition
.Lme_46:
.text 0
	.balign 16
.Lm_47:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,5,1,0,0,73,139,255,65,131,63,0
call .Lp_137

	.byte 72,15,182,192,133,192,117,15,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1644
	.byte 72,139,0,233,212,0,0,0,73,139,255,65,131,63,0
call .Lp_98

	.byte 72,139,208,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1652
	.byte 72,139,0,72,139,200,76,139,250,76,139,241,72,133,192,15,133,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1660
	.byte 72,139,0,72,137,68,36,16,72,133,192,15,132,212,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1668
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,16,72,133,201,15,132,166,0,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1676
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1684
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1692
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1652
	.byte 72,137,1,76,139,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1700
	.byte 73,139,255,73,139,246
call .Lp_138

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,187,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,233,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition
.Lme_47:
.text 0
	.balign 16
.Lm_48:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,40,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,249,0,0,0,73,139,255,65,131,63,0
call .Lp_137

	.byte 72,15,182,192,133,192,117,7,51,192,233,208,0,0,0,73,139,255
call .Lp_139

	.byte 72,139,208,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1708
	.byte 72,139,0,72,139,200,76,139,250,76,139,241,72,133,192,15,133,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1660
	.byte 72,139,0,72,137,68,36,24,72,133,192,15,132,212,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1668
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,24,72,133,201,15,132,166,0,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1716
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1724
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1732
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1708
	.byte 72,137,1,76,139,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1740
	.byte 73,139,255,73,139,246
call .Lp_140

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,40,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,187,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,233,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition
.Lme_48:
.text 0
	.balign 16
.Lm_49:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,76,137,52,36,76,137,124,36,8,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,5,1,0,0,73,139,255,65,131,63,0
call .Lp_137

	.byte 72,15,182,192,133,192,117,15,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1644
	.byte 72,139,0,233,212,0,0,0,73,139,255,65,131,63,0
call .Lp_98

	.byte 72,139,208,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1748
	.byte 72,139,0,72,139,200,76,139,250,76,139,241,72,133,192,15,133,151,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1660
	.byte 72,139,0,72,137,68,36,16,72,133,192,15,132,212,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1668
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,16,72,133,201,15,132,166,0,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1756
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1764
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1772
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1748
	.byte 72,137,1,76,139,240,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1700
	.byte 73,139,255,73,139,246
call .Lp_138

	.byte 76,139,52,36,76,139,124,36,8,72,131,196,24,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,187,0,0,0,191,42,1,0,0
call .Lp_19

	.byte 190,233,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition
.Lme_49:
.text 0
	.balign 16
.Lm_4a:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,8,76,137,60,36,76,139,255,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,255,15,132,41,0,0,0,73,139,255,65,131,63,0
call .Lp_141

	.byte 72,15,182,192,133,192,15,132,55,0,0,0,73,139,255
call .Lp_142

	.byte 76,139,60,36,72,131,196,8,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 191,187,0,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition
.Lme_4a:
.text 0
	.balign 16
.Lm_4b:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1780
	.byte 190,112,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248,72,139,52,36
call .Lp_143

	.byte 72,139,68,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference
.Lme_4b:
.text 0
	.balign 16
.Lm_4c:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int:

	.byte 72,131,236,72,76,137,44,36,76,137,116,36,8,76,137,124,36,16,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 199,68,36,40,0,0,0,0,199,68,36,44,0,0,0,0,199,68,36,48,0,0,0,0,199,68,36,52,0,0,0,0
	.byte 69,133,255,15,132,214,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1780
	.byte 190,112,0,0,0
call .Lp_2

	.byte 72,137,68,36,56,72,139,248,73,139,246
call .Lp_143

	.byte 72,139,68,36,56,76,139,240,65,189,1,0,0,0,233,131,0,0,0,72,141,173,0,0,0,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,254,65,131,62,0
call .Lp_35

	.byte 199,68,36,40,0,0,0,0,199,68,36,44,0,0,0,0,199,68,36,48,0,0,0,0,199,68,36,52,0,0,0,0
	.byte 72,99,76,36,40,137,76,36,24,72,99,76,36,44,137,76,36,28,72,99,76,36,48,137,76,36,32,72,99,76,36,52
	.byte 137,76,36,36,72,139,248,72,139,116,36,24,72,139,84,36,32,131,56,0
call .Lp_144

	.byte 65,255,197,69,59,239,15,140,123,255,255,255,73,139,198,76,139,44,36,76,139,116,36,8,76,139,124,36,16,72,131,196
	.byte 72,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,43,1,0,0
call .Lp_12

	.byte 72,139,240,191,189,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int
.Lme_4c:
.text 0
	.balign 16
.Lm_4d:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1788
	.byte 190,104,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248,72,139,52,36
call .Lp_145

	.byte 72,139,68,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference
.Lme_4d:
.text 0
	.balign 16
.Lm_4e:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1796
	.byte 190,104,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248,72,139,52,36
call .Lp_146

	.byte 72,139,68,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference
.Lme_4e:
.text 0
	.balign 16
.Lm_4f:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1804
	.byte 190,112,0,0,0
call .Lp_2

	.byte 72,137,68,36,16,72,139,248,72,139,116,36,8,72,139,20,36
call .Lp_147

	.byte 72,139,68,36,16,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
.Lme_4f:
.text 0
	.balign 16
.Lm_50:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1812
	.byte 190,112,0,0,0
call .Lp_2

	.byte 72,137,68,36,16,72,139,248,72,139,116,36,8,72,139,20,36
call .Lp_148

	.byte 72,139,68,36,16,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
.Lme_50:
.text 0
	.balign 16
.Lm_51:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__:

	.byte 72,131,236,56,76,137,36,36,76,137,108,36,8,76,137,116,36,16,76,137,124,36,24,76,139,247,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 77,133,246,15,132,50,1,0,0,77,133,255,15,132,223,0,0,0,73,99,71,24,133,192,15,132,249,0,0,0,73,139
	.byte 254,73,139,6,255,144,136,1,0,0,72,139,200,131,57,0,72,99,64,24,73,99,79,24,59,193,15,133,233,0,0,0
	.byte 73,99,71,24,72,137,68,36,40,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1820
	.byte 190,112,0,0,0
call .Lp_2

	.byte 72,139,84,36,40,72,137,68,36,32,72,139,248,73,139,246
call .Lp_149

	.byte 72,139,68,36,32,76,139,240,77,139,239,69,51,255,233,75,0,0,0,72,141,100,36,0,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,99,199,65,57,69,24,15,134,185,0,0,0,73,141,68,197,32,76,139,32,73,139,254,65,131,62,0
call .Lp_25

	.byte 72,139,248,73,139,244,131,56,0
call .Lp_150

	.byte 65,255,199,73,99,69,24,68,59,248,124,177,73,139,198,76,139,36,36,76,139,108,36,8,76,139,116,36,16,76,139,124
	.byte 36,24,72,131,196,56,195,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,53,1,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 191,187,0,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 191,187,0,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . -4
	.byte 190,1,0,0,0
call .Lp_12

	.byte 72,139,240,191,188,0,0,2
call .Lp_13

	.byte 72,139,248
call .Lp_14

	.byte 190,206,0,0,0,191,14,1,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__
.Lme_51:
.text 0
	.balign 16
.Lm_52:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1828
	.byte 190,104,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248,72,139,52,36
call .Lp_151

	.byte 72,139,68,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference
.Lme_52:
.text 0
	.balign 16
.Lm_53:
	.local Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference
	.type Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference,@function
Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference:

	.byte 72,131,236,24,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1836
	.byte 190,104,0,0,0
call .Lp_2

	.byte 72,137,68,36,8,72,139,248,72,139,52,36
call .Lp_152

	.byte 72,139,68,36,8,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference,.-Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference
.Lme_53:
.text 0
	.balign 16
.Lm_54:
	.local Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor
	.type Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor,@function
Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor:

	.byte 72,131,236,8,72,137,60,36,72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor,.-Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor
.Lme_54:
.text 0
	.balign 16
.Lm_55:
	.local Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF
	.type Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF,@function
Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,64,16,72,139,248,72,139,116,36,8,72,137,68,36,16,255,80,24,72,139,76,36,16,72,131,196
	.byte 24,195

	.size Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF,.-Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF
.Lme_55:
.text 0
	.balign 16
.Lm_56:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,99,76,36,8,137,72,64,72,139,4,36,72,137,68,36,16
call .Lp_153

	.byte 72,139,248,131,56,0
call .Lp_154

	.byte 72,139,200,72,139,68,36,16,137,72,68,72,131,196,24,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int
.Lme_56:
.text 0
	.balign 16
.Lm_57:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose:

	.byte 85,72,139,236,72,131,236,48,76,137,125,248,72,137,125,216,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,69,216,76,99,120,64,73,139,199,131,248,253,116,10,65,131,255,2,15,133,75,0,0,0,72,199,69,240,0,0
	.byte 0,0,72,131,236,8,232,20,0,0,0,72,131,196,8,72,139,69,240,72,133,192,116,5
call .Lp_83

	.byte 235,38,72,137,101,232,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,125,216
call .Lp_155

	.byte 72,139,101,232,195,76,139,125,248,201,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose
.Lme_57:
.text 0
	.balign 16
.Lm_58:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext:

	.byte 85,72,139,236,72,131,236,64,76,137,117,240,76,137,125,248,72,137,125,216,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,69,216,76,99,120,64,77,139,247,65,131,254,3,115,24,73,139,198,72,193,224,3,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1844
	.byte 72,3,193,72,139,0,255,224,51,192,76,15,182,248,233,144,1,0,0,72,139,69,216,199,64,64,255,255,255,255,72,139
	.byte 77,216,72,139,193,72,139,64,24,72,131,193,16,72,137,1,193,233,9,72,129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,139,69,216,199,64,64,1,0,0,0,184,1,0,0,0,76,15,182,248,233,67,1,0,0,72
	.byte 139,69,216,199,64,64,255,255,255,255,72,139,69,216,72,137,69,208,72,139,64,40,72,137,69,200,72,139,69,216,72,139
	.byte 56
call .Lp_156

	.byte 76,139,208,72,139,69,200,72,139,248,72,139,0,255,80,160,72,139,77,208,72,131,193,56,72,137,1,193,233,9,72,129
	.byte 225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,139,69,216,199,64,64,253,255,255,255,233,112,0,0,0,72,139,69,216,72,139,64,56,72,137
	.byte 69,208,72,139,69,216,72,139,56
call .Lp_157

	.byte 76,139,208,72,139,69,208,72,139,248,72,139,0,255,80,152,76,139,248,72,139,69,216,72,131,192,16,76,137,56,193,232
	.byte 9,72,37,255,255,127,0,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,193,198,0,1,72,139,69,216,199,64,64,2,0,0,0,184,1,0,0,0,76,15,182,248,233,117,0,0,0,72
	.byte 139,69,216,199,64,64,253,255,255,255,72,139,69,216,72,139,64,56,72,139,248,72,139,0,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1852
	.byte 255,80,136,72,15,182,192,133,192,15,133,108,255,255,255,72,139,125,216
call .Lp_155

	.byte 72,139,69,216,72,199,64,56,0,0,0,0,51,192,76,15,182,248,233,38,0,0,0,72,137,101,232,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,125,216
call .Lp_158

	.byte 72,139,101,232,195,73,139,199,76,139,117,240,76,139,125,248,201,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext
.Lme_58:
.text 0
	.balign 16
.Lm_59:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1:

	.byte 72,131,236,8,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,199,64,64,255,255,255,255,72,139,4,36,72,139,64,56,72,133,192,116,24,72,139,4,36,72,139,64,56
	.byte 72,139,248,72,139,0,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1860
	.byte 255,80,216,72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1
.Lme_59:
.text 0
	.balign 16
.Lm_5a:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,16,72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current
.Lme_5a:
.text 0
	.balign 16
.Lm_5b:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset:

	.byte 72,131,236,8,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 191,41,1,0,2
call .Lp_27

	.byte 72,139,248
call .Lp_14

	.byte 72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset
.Lme_5b:
.text 0
	.balign 16
.Lm_5c:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,16,72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current
.Lme_5c:
.text 0
	.balign 16
.Lm_5d:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator:

	.byte 72,131,236,24,76,137,60,36,72,137,124,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,68,36,8,72,99,64,64,131,248,254,15,133,64,0,0,0,72,139,68,36,8,72,99,64,68,72,137,68,36,16
call .Lp_153

	.byte 72,139,248,131,56,0
call .Lp_154

	.byte 72,139,200,72,139,68,36,16,59,193,117,22,72,139,68,36,8,199,64,64,0,0,0,0,76,139,124,36,8,233,49,0
	.byte 0,0,72,139,68,36,8,72,139,56
call .Lp_159

	.byte 72,139,248,190,72,0,0,0
call .Lp_2

	.byte 72,137,68,36,16,72,139,248,51,246
call .Lp_160

	.byte 72,139,68,36,16,76,139,248,72,139,68,36,8,72,139,64,48,73,141,79,40,72,137,1,193,233,9,72,129,225,255,255
	.byte 127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,139,68,36,8,72,139,64,32,73,141,79,24,72,137,1,193,233,9,72,129,225,255,255,127,0
	.byte 73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,73,139,199,76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator
.Lme_5d:
.text 0
	.balign 16
.Lm_5e:
	.local Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator
	.type Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator,@function
Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator:

	.byte 72,131,236,8,72,137,60,36,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,60,36
call .Lp_161

	.byte 72,131,196,8,195

	.size Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator,.-Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator
.Lme_5e:
.text 0
	.balign 16
.Lm_5f:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_get_Code
	.type Mono_Cecil_Rocks_ILParser_ParseContext_get_Code,@function
Mono_Cecil_Rocks_ILParser_ParseContext_get_Code:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,16,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_get_Code,.-Mono_Cecil_Rocks_ILParser_ParseContext_get_Code
.Lme_5f:
.text 0
	.balign 16
.Lm_60:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader
	.type Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader,@function
Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,72,139,207,72,131,193,16,72,139,68,36,8,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader,.-Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader
.Lme_60:
.text 0
	.balign 16
.Lm_61:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_get_Position
	.type Mono_Cecil_Rocks_ILParser_ParseContext_get_Position,@function
Mono_Cecil_Rocks_ILParser_ParseContext_get_Position:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,99,64,48,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_get_Position,.-Mono_Cecil_Rocks_ILParser_ParseContext_get_Position
.Lme_61:
.text 0
	.balign 16
.Lm_62:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int
	.type Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int,@function
Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,72,139,199,72,99,76,36,8,137,72,48,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int,.-Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int
.Lme_62:
.text 0
	.balign 16
.Lm_63:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata
	.type Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata,@function
Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,24,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata,.-Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata
.Lme_63:
.text 0
	.balign 16
.Lm_64:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader
	.type Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader,@function
Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,72,139,207,72,131,193,24,72,139,68,36,8,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader,.-Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader
.Lme_64:
.text 0
	.balign 16
.Lm_65:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables
	.type Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables,@function
Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,32,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables,.-Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables
.Lme_65:
.text 0
	.balign 16
.Lm_66:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition
	.type Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition,@function
Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,72,139,207,72,131,193,32,72,139,68,36,8,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition,.-Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition
.Lme_66:
.text 0
	.balign 16
.Lm_67:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor
	.type Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor,@function
Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor:

	.byte 72,131,236,8,72,137,60,36,72,139,199,72,139,64,40,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor,.-Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor
.Lme_67:
.text 0
	.balign 16
.Lm_68:
	.local Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor
	.type Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor,@function
Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,72,139,207,72,131,193,40,72,139,68,36,8,72,137,1,193,233,9,72
	.byte 129,225,255,255,127,0,73,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,202,198,1,1,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor,.-Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor
.Lme_68:
.text 0
	.balign 16
.Lm_69:
	.local Mono_Cecil_Rocks_ILParser_ParseContext__ctor
	.type Mono_Cecil_Rocks_ILParser_ParseContext__ctor,@function
Mono_Cecil_Rocks_ILParser_ParseContext__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser_ParseContext__ctor,.-Mono_Cecil_Rocks_ILParser_ParseContext__ctor
.Lme_69:
.text 0
	.balign 16
.Lm_6a:
	.local Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor
	.type Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor,@function
Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor,.-Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor
.Lme_6a:
.text 0
	.balign 16
.Lm_6b:
	.local Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader
	.type Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader,@function
Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader:

	.byte 72,131,236,24,72,137,60,36,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,4,36,72,139,112,16,72,139,124,36,8
call .Lp_162

	.byte 184,1,0,0,0,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader,.-Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader
.Lme_6b:
.text 0
	.balign 16
.Lm_6c:
	.local Mono_Cecil_Rocks_ILParser__c__cctor
	.type Mono_Cecil_Rocks_ILParser__c__cctor,@function
Mono_Cecil_Rocks_ILParser__c__cctor:

	.byte 72,131,236,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1868
	.byte 190,16,0,0,0
call .Lp_2

	.byte 72,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 588
	.byte 72,137,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser__c__cctor,.-Mono_Cecil_Rocks_ILParser__c__cctor
.Lme_6c:
.text 0
	.balign 16
.Lm_6d:
	.local Mono_Cecil_Rocks_ILParser__c__ctor
	.type Mono_Cecil_Rocks_ILParser__c__ctor,@function
Mono_Cecil_Rocks_ILParser__c__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ILParser__c__ctor,.-Mono_Cecil_Rocks_ILParser__c__ctor
.Lme_6d:
.text 0
	.balign 16
.Lm_6e:
	.local Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader
	.type Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader,@function
Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader:

	.byte 72,131,236,24,72,137,84,36,16,72,139,194,72,139,64,56,72,131,196,24,195

	.size Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader,.-Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader
.Lme_6e:
.text 0
	.balign 16
.Lm_6f:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor,.-Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor
.Lme_6f:
.text 0
	.balign 16
.Lm_70:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,76,137,60,36,72,137,124,36,8,76,139,254,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,255,65,131,63,0
call .Lp_163

	.byte 72,139,248,72,139,68,36,8,72,139,112,16,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1532
call .Lp_102

	.byte 72,139,248,77,139,21
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1876
	.byte 73,139,247
call .Lp_164

	.byte 76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition
.Lme_70:
.text 0
	.balign 16
.Lm_71:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor:

	.byte 72,131,236,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1884
	.byte 190,16,0,0,0
call .Lp_2

	.byte 72,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1484
	.byte 72,137,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor,.-Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor
.Lme_71:
.text 0
	.balign 16
.Lm_72:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor,.-Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor
.Lme_72:
.text 0
	.balign 16
.Lm_73:
	.local Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
	.type Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,@function
Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition:

	.byte 72,131,236,24,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1892
	.byte 190,24,0,0,0
call .Lp_2

	.byte 72,139,200,72,137,76,36,16,72,139,208,72,131,194,16,72,139,76,36,8,72,137,10,193,234,9,72,129,226,255,255,127
	.byte 0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,72,133,192,15,132,134,0,0,0,73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1900
	.byte 190,128,0,0,0
call .Lp_2

	.byte 72,139,76,36,16,72,133,201,15,132,88,0,0,0,72,137,72,32,72,139,208,72,131,194,32,193,234,9,72,129,226,255
	.byte 255,127,0,73,139,53
	.long mono_aot_Mono_Cecil_Rocks_got - . + 12
	.byte 72,3,214,198,2,1,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1908
	.byte 72,137,72,40,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1916
	.byte 72,137,72,64,73,139,13
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1924
	.byte 72,139,81,40,72,137,80,24,72,139,73,32,72,137,72,16,198,64,112,0,72,131,196,24,195,190,109,0,0,0,191,42
	.byte 1,0,0
call .Lp_19

	.byte 190,155,0,0,0,191,187,0,0,0
call .Lp_19

	.size Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,.-Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
.Lme_73:
.text 0
	.balign 16
.Lm_74:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor
	.type Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor,@function
Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor:

	.byte 72,131,236,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 73,139,61
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1932
	.byte 190,16,0,0,0
call .Lp_2

	.byte 72,139,200,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 1660
	.byte 72,137,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor,.-Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor
.Lme_74:
.text 0
	.balign 16
.Lm_75:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor
	.type Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor,@function
Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor:

	.byte 72,131,236,8,72,131,196,8,195

	.size Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor,.-Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor
.Lme_75:
.text 0
	.balign 16
.Lm_76:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,124,36,8,72,139,199,131,56,0
call .Lp_165

	.byte 72,15,182,192,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition
.Lme_76:
.text 0
	.balign 16
.Lm_77:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,76,137,60,36,76,139,254,65,131,63,0,65,15,183,135,136,0,0,0,131,224,16,133,192,64,15,151,192
	.byte 72,15,182,192,72,15,182,192,72,15,182,192,76,139,60,36,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition
.Lme_77:
.text 0
	.balign 16
.Lm_78:
	.local Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition
	.type Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition,@function
Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition:

	.byte 72,131,236,24,72,137,116,36,8,73,139,5
	.long mono_aot_Mono_Cecil_Rocks_got - . + 52
	.byte 247,0,1,0,0,0,116,5
call .Lp_1

	.byte 72,139,124,36,8,72,139,199,131,56,0
call .Lp_165

	.byte 72,15,182,192,133,192,64,15,148,192,72,15,182,192,72,131,196,24,195

	.size Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition,.-Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition
.Lme_78:
.text 0
	.balign 8
jit_code_end:

	.byte 144,144,144,144
.section ".data.rel.ro"
.subsection 0
	.balign 8
method_addresses:
	.local method_addresses
	.type method_addresses,@object
call .Lm_0
call .Lm_1
call .Lm_2
call .Lm_3
call .Lm_4
call .Lm_5
call .Lm_6
call .Lm_7
call .Lm_8
call .Lm_9
call .Lm_a
call .Lm_b
call .Lm_c
call .Lm_d
call .Lm_e
call .Lm_f
call .Lm_10
call .Lm_11
call .Lm_12
call .Lm_13
call .Lm_14
call .Lm_15
call .Lm_16
call .Lm_17
call .Lm_18
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call method_addresses
call .Lm_29
call .Lm_2a
call .Lm_2b
call .Lm_2c
call .Lm_2d
call .Lm_2e
call .Lm_2f
call .Lm_30
call .Lm_31
call .Lm_32
call .Lm_33
call .Lm_34
call .Lm_35
call .Lm_36
call .Lm_37
call .Lm_38
call .Lm_39
call .Lm_3a
call .Lm_3b
call .Lm_3c
call .Lm_3d
call .Lm_3e
call .Lm_3f
call .Lm_40
call .Lm_41
call .Lm_42
call .Lm_43
call .Lm_44
call .Lm_45
call .Lm_46
call .Lm_47
call .Lm_48
call .Lm_49
call .Lm_4a
call .Lm_4b
call .Lm_4c
call .Lm_4d
call .Lm_4e
call .Lm_4f
call .Lm_50
call .Lm_51
call .Lm_52
call .Lm_53
call .Lm_54
call .Lm_55
call .Lm_56
call .Lm_57
call .Lm_58
call .Lm_59
call .Lm_5a
call .Lm_5b
call .Lm_5c
call .Lm_5d
call .Lm_5e
call .Lm_5f
call .Lm_60
call .Lm_61
call .Lm_62
call .Lm_63
call .Lm_64
call .Lm_65
call .Lm_66
call .Lm_67
call .Lm_68
call .Lm_69
call .Lm_6a
call .Lm_6b
call .Lm_6c
call .Lm_6d
call .Lm_6e
call .Lm_6f
call .Lm_70
call .Lm_71
call .Lm_72
call .Lm_73
call .Lm_74
call .Lm_75
call .Lm_76
call .Lm_77
call .Lm_78
call method_addresses
method_addresses_end:

.section ".rodata"
.subsection 0
	.balign 8
unbox_trampolines:
unbox_trampolines_end:

	.long 0
.text 0
	.balign 8
unbox_trampoline_addresses:

	.long 0
.section ".rodata"
.subsection 0
	.balign 8
method_info_offsets:

	.byte 122,0,0,0,10,0,0,0,13,0,0,0,2,0,0,0,0,0,10,0,20,0,34,0,44,0,54,0,65,0,76,0
	.byte 87,0,98,0,109,0,120,0,131,0,1,3,1,1,1,1,4,1,1,7,34,7,1,4,3,9,4,1,1,1,75,1
	.byte 1,1,1,255,255,255,255,177,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,80,7,1,11,3,34,1,64,1
	.byte 128,203,1,8,84,5,34,5,3,1,1,129,90,20,1,1,14,10,1,1,1,1,129,152,12,20,18,20,1,4,4,4
	.byte 4,129,243,4,4,4,4,1,1,1,1,6,130,17,1,1,1,1,1,1,1,1,1,130,27,1,1,1,1,1,1,1
	.byte 1,7,130,45,3,1,6,8,3,14,8,3,3,130,97,255,255,255,253,159
.section ".rodata"
.subsection 0
	.balign 8
extra_method_table:

	.byte 11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.byte 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.byte 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.byte 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.byte 0,0,0,0,0,0,0,0
.section ".rodata"
.subsection 0
	.balign 8
extra_method_info_offsets:

	.byte 0,0,0,0
.section ".rodata"
.subsection 0
	.balign 8
class_name_table:

	.byte 37,0,0,0,0,0,13,0,0,0,0,0,0,0,0,0,0,0,9,0,38,0,12,0,0,0,6,0,0,0,0,0
	.byte 0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,17,0,0,0,0,0,0,0,4,0,0,0,10,0
	.byte 39,0,0,0,0,0,0,0,0,0,0,0,0,0,19,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,7,0
	.byte 37,0,0,0,0,0,16,0,0,0,0,0,0,0,11,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,1,0
	.byte 0,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,0,0,15,0,40,0,18,0
	.byte 0,0,20,0,0,0
.section ".rodata"
.subsection 0
	.balign 8
got_info_offsets:

	.byte 243,0,0,0,10,0,0,0,25,0,0,0,2,0,0,0,0,0,11,0,22,0,33,0,44,0,55,0,66,0,77,0
	.byte 88,0,99,0,110,0,121,0,132,0,143,0,154,0,165,0,176,0,187,0,198,0,209,0,220,0,231,0,242,0,253,0
	.byte 8,1,130,100,2,1,1,1,1,1,1,1,2,130,113,2,2,2,3,2,2,2,2,2,130,135,3,2,3,3,3,5
	.byte 3,3,6,130,168,2,9,12,16,14,4,5,4,4,130,242,5,5,5,6,2,2,9,12,5,131,42,3,3,3,6,2
	.byte 2,9,3,5,131,83,3,5,4,5,5,4,5,5,3,131,128,2,2,9,4,4,6,2,2,9,131,180,3,7,7,7
	.byte 42,2,7,2,2,132,10,2,2,2,2,2,2,2,2,2,132,30,5,2,5,2,4,2,6,108,7,132,178,7,7,7
	.byte 7,7,5,5,7,7,132,244,7,7,7,7,7,7,7,7,7,133,58,7,5,7,14,5,10,7,7,7,133,134,7,5
	.byte 10,7,7,7,7,7,10,133,208,7,7,7,7,7,7,5,22,7,134,35,7,7,7,7,7,7,7,7,5,134,101,28
	.byte 7,7,7,7,7,7,7,7,134,192,7,7,7,7,7,4,4,6,2,134,245,9,12,12,4,4,5,5,4,4,135,53
	.byte 6,7,5,5,5,5,7,4,4,135,107,2,2,9,12,4,2,2,9,12,135,165,2,2,9,4,5,5,5,5,4,135
	.byte 211,5,7,5,5,3,12,3,3,6,136,6,2,9
.section ".rodata"
.subsection 0
	.balign 8
ex_info_offsets:

	.byte 122,0,0,0,10,0,0,0,13,0,0,0,2,0,0,0,0,0,11,0,22,0,37,0,47,0,60,0,72,0,83,0
	.byte 94,0,105,0,116,0,127,0,138,0,141,6,15,13,13,17,46,34,17,21,19,142,21,34,48,23,26,33,27,52,20,14
	.byte 143,108,15,43,44,35,255,255,255,240,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,144,25,43,42,30,30
	.byte 128,250,15,129,96,17,147,53,20,55,129,69,72,112,62,48,24,23,150,41,23,15,26,84,66,27,27,70,70,151,234,51
	.byte 30,28,30,24,13,35,13,13,152,228,13,55,13,53,36,37,43,70,106,154,184,38,36,38,58,38,14,13,14,13,155,204
	.byte 13,14,13,14,13,12,12,13,16,156,80,13,12,17,16,12,17,16,12,13,156,221,255,255,255,227,35
.section ".rodata"
.subsection 1
	.balign 8
unwind_info:

	.byte 16,12,7,8,144,1,68,14,32,28,10,68,12,7,8,65,11,28,12,7,8,144,1,68,14,32,68,142,4,69,143,3
	.byte 28,10,68,8,14,69,8,15,68,12,7,8,65,11,22,12,7,8,144,1,68,14,16,68,143,2,28,10,68,8,15,68
	.byte 12,7,8,65,11,22,12,7,8,144,1,68,14,32,68,143,4,28,10,68,8,15,68,12,7,8,65,11,22,12,7,8
	.byte 144,1,68,14,32,68,142,4,28,10,68,8,14,68,12,7,8,65,11,40,12,7,8,144,1,68,14,48,68,140,6,69
	.byte 141,5,69,142,4,69,143,3,28,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8,65,11,28,12,7,8
	.byte 144,1,68,14,32,68,141,4,69,142,3,28,10,68,8,13,69,8,14,68,12,7,8,65,11,28,12,7,8,144,1,68
	.byte 14,32,68,141,4,69,143,3,28,10,68,8,13,69,8,15,68,12,7,8,65,11,16,12,7,8,144,1,68,14,16,28
	.byte 10,68,12,7,8,65,11,34,12,7,8,144,1,68,14,48,68,141,6,69,142,5,69,143,4,28,10,68,8,13,69,8
	.byte 14,69,8,15,68,12,7,8,65,11,22,12,7,8,144,1,68,14,48,68,143,6,28,10,68,8,15,68,12,7,8,65
	.byte 11,22,12,7,8,144,1,68,14,64,68,143,8,28,10,68,8,15,68,12,7,8,65,11,16,12,7,8,144,1,68,14
	.byte 48,28,10,68,12,7,8,65,11,28,12,7,8,144,1,68,14,48,68,141,6,69,142,5,28,10,68,8,13,69,8,14
	.byte 68,12,7,8,65,11,34,12,7,8,144,1,68,14,64,68,131,8,69,141,7,69,142,6,28,10,68,8,3,69,8,13
	.byte 69,8,14,68,12,7,8,65,11,28,12,7,8,144,1,68,14,80,68,142,10,69,143,9,28,10,68,8,14,69,8,15
	.byte 68,12,7,8,65,11,53,12,7,8,144,1,71,14,208,2,68,131,42,69,134,41,69,140,40,69,141,39,69,142,38,69
	.byte 143,37,28,10,68,8,3,69,8,6,69,8,12,69,8,13,69,8,14,69,8,15,71,12,7,8,65,11,47,12,7,8
	.byte 144,1,65,14,16,134,2,67,13,6,75,140,6,68,141,5,68,142,4,68,143,3,28,10,68,8,12,68,8,13,68,8
	.byte 14,68,8,15,65,8,6,12,7,8,65,11,40,12,7,8,144,1,68,14,96,68,140,12,69,141,11,69,142,10,69,143
	.byte 9,28,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8,65,11,53,12,7,8,144,1,65,14,16,134,2
	.byte 67,13,6,75,131,7,68,140,6,68,141,5,68,142,4,68,143,3,28,10,68,8,3,68,8,12,68,8,13,68,8,14
	.byte 68,8,15,65,8,6,12,7,8,65,11,35,12,7,8,144,1,65,14,16,134,2,67,13,6,72,142,4,68,143,3,28
	.byte 10,68,8,14,68,8,15,65,8,6,12,7,8,65,11,35,12,7,8,144,1,71,14,160,1,68,141,20,69,142,19,69
	.byte 143,18,28,10,68,8,13,69,8,14,69,8,15,71,12,7,8,65,11,34,12,7,8,144,1,68,14,32,68,141,4,69
	.byte 142,3,69,143,2,28,10,68,8,13,69,8,14,69,8,15,68,12,7,8,65,11,34,12,7,8,144,1,68,14,96,68
	.byte 140,12,69,141,11,69,142,10,28,10,68,8,12,69,8,13,69,8,14,68,12,7,8,65,11,41,12,7,8,144,1,65
	.byte 14,16,134,2,67,13,6,72,141,5,68,142,4,68,143,3,28,10,68,8,13,68,8,14,68,8,15,65,8,6,12,7
	.byte 8,65,11,35,12,7,8,144,1,65,14,16,134,2,67,13,6,75,141,4,68,142,3,28,10,68,8,13,68,8,14,65
	.byte 8,6,12,7,8,65,11,29,12,7,8,144,1,65,14,16,134,2,67,13,6,72,143,3,28,10,68,8,15,65,8,6
	.byte 12,7,8,65,11,41,12,7,8,144,1,65,14,16,134,2,67,13,6,75,141,5,68,142,4,68,143,3,28,10,68,8
	.byte 13,68,8,14,68,8,15,65,8,6,12,7,8,65,11,28,12,7,8,144,1,68,14,48,68,142,6,69,143,5,28,10
	.byte 68,8,14,69,8,15,68,12,7,8,65,11,34,12,7,8,144,1,68,14,80,68,141,10,69,142,9,69,143,8,28,10
	.byte 68,8,13,69,8,14,69,8,15,68,12,7,8,65,11,40,12,7,8,144,1,68,14,64,68,140,8,69,141,7,69,142
	.byte 6,69,143,5,28,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8,65,11
.section ".rodata"
.subsection 0
	.balign 8
class_info_offsets:

	.byte 20,0,0,0,10,0,0,0,2,0,0,0,2,0,0,0,0,0,11,0,156,236,7,20,23,7,23,23,23,23,23,157
	.byte 175,23,23,5,5,23,23,24,23,24

.text 0
	.balign 16
plt:
mono_aot_Mono_Cecil_Rocks_plt:
	.local plt__jit_icall_mono_threads_state_poll
	.type plt__jit_icall_mono_threads_state_poll,@function
plt__jit_icall_mono_threads_state_poll:
.Lp_1:
jmp *mono_aot_Mono_Cecil_Rocks_got+1952(%rip)

	.long 2068
	.size plt__jit_icall_mono_threads_state_poll,.-plt__jit_icall_mono_threads_state_poll
	.local plt_wrapper_alloc_object_AllocSmall_intptr_intptr
	.type plt_wrapper_alloc_object_AllocSmall_intptr_intptr,@function
plt_wrapper_alloc_object_AllocSmall_intptr_intptr:
.Lp_2:
jmp *mono_aot_Mono_Cecil_Rocks_got+1960(%rip)

	.long 2071
	.size plt_wrapper_alloc_object_AllocSmall_intptr_intptr,.-plt_wrapper_alloc_object_AllocSmall_intptr_intptr
	.local plt_System_Text_StringBuilder__ctor
	.type plt_System_Text_StringBuilder__ctor,@function
plt_System_Text_StringBuilder__ctor:
.Lp_3:
jmp *mono_aot_Mono_Cecil_Rocks_got+1968(%rip)

	.long 2079
	.size plt_System_Text_StringBuilder__ctor,.-plt_System_Text_StringBuilder__ctor
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition:
.Lp_4:
jmp *mono_aot_Mono_Cecil_Rocks_got+1976(%rip)

	.long 2084
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition
	.local plt_System_Text_StringBuilder_Append_char
	.type plt_System_Text_StringBuilder_Append_char,@function
plt_System_Text_StringBuilder_Append_char:
.Lp_5:
jmp *mono_aot_Mono_Cecil_Rocks_got+1984(%rip)

	.long 2086
	.size plt_System_Text_StringBuilder_Append_char,.-plt_System_Text_StringBuilder_Append_char
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool:
.Lp_6:
jmp *mono_aot_Mono_Cecil_Rocks_got+1992(%rip)

	.long 2091
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool
	.local plt_System_Text_StringBuilder_Append_int
	.type plt_System_Text_StringBuilder_Append_int,@function
plt_System_Text_StringBuilder_Append_int:
.Lp_7:
jmp *mono_aot_Mono_Cecil_Rocks_got+2000(%rip)

	.long 2093
	.size plt_System_Text_StringBuilder_Append_int,.-plt_System_Text_StringBuilder_Append_int
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition:
.Lp_8:
jmp *mono_aot_Mono_Cecil_Rocks_got+2008(%rip)

	.long 2098
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition:
.Lp_9:
jmp *mono_aot_Mono_Cecil_Rocks_got+2016(%rip)

	.long 2100
	.size plt_Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition:
.Lp_10:
jmp *mono_aot_Mono_Cecil_Rocks_got+2024(%rip)

	.long 2102
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition
	.local plt_string_op_Equality_string_string
	.type plt_string_op_Equality_string_string,@function
plt_string_op_Equality_string_string:
.Lp_11:
jmp *mono_aot_Mono_Cecil_Rocks_got+2032(%rip)

	.long 2104
	.size plt_string_op_Equality_string_string,.-plt_string_op_Equality_string_string
	.local plt__jit_icall_mono_helper_ldstr
	.type plt__jit_icall_mono_helper_ldstr,@function
plt__jit_icall_mono_helper_ldstr:
.Lp_12:
jmp *mono_aot_Mono_Cecil_Rocks_got+2040(%rip)

	.long 2109
	.size plt__jit_icall_mono_helper_ldstr,.-plt__jit_icall_mono_helper_ldstr
	.local plt__jit_icall_mono_create_corlib_exception_1
	.type plt__jit_icall_mono_create_corlib_exception_1,@function
plt__jit_icall_mono_create_corlib_exception_1:
.Lp_13:
jmp *mono_aot_Mono_Cecil_Rocks_got+2048(%rip)

	.long 2112
	.size plt__jit_icall_mono_create_corlib_exception_1,.-plt__jit_icall_mono_create_corlib_exception_1
	.local plt__jit_icall_mono_arch_throw_exception
	.type plt__jit_icall_mono_arch_throw_exception,@function
plt__jit_icall_mono_arch_throw_exception:
.Lp_14:
jmp *mono_aot_Mono_Cecil_Rocks_got+2056(%rip)

	.long 2115
	.size plt__jit_icall_mono_arch_throw_exception,.-plt__jit_icall_mono_arch_throw_exception
	.local plt_Mono_Cecil_MethodReference_get_ReturnType
	.type plt_Mono_Cecil_MethodReference_get_ReturnType,@function
plt_Mono_Cecil_MethodReference_get_ReturnType:
.Lp_15:
jmp *mono_aot_Mono_Cecil_Rocks_got+2064(%rip)

	.long 2117
	.size plt_Mono_Cecil_MethodReference_get_ReturnType,.-plt_Mono_Cecil_MethodReference_get_ReturnType
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference:
.Lp_16:
jmp *mono_aot_Mono_Cecil_Rocks_got+2072(%rip)

	.long 2122
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_PropertyDefinition_get_HasParameters
	.type plt_Mono_Cecil_PropertyDefinition_get_HasParameters,@function
plt_Mono_Cecil_PropertyDefinition_get_HasParameters:
.Lp_17:
jmp *mono_aot_Mono_Cecil_Rocks_got+2080(%rip)

	.long 2124
	.size plt_Mono_Cecil_PropertyDefinition_get_HasParameters,.-plt_Mono_Cecil_PropertyDefinition_get_HasParameters
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ParameterDefinition_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition_System_Action_1_Mono_Cecil_ParameterDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ParameterDefinition_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition_System_Action_1_Mono_Cecil_ParameterDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ParameterDefinition_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition_System_Action_1_Mono_Cecil_ParameterDefinition:
.Lp_18:
jmp *mono_aot_Mono_Cecil_Rocks_got+2088(%rip)

	.long 2129
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ParameterDefinition_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition_System_Action_1_Mono_Cecil_ParameterDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ParameterDefinition_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition_System_Action_1_Mono_Cecil_ParameterDefinition
	.local plt__jit_icall_mono_arch_throw_corlib_exception
	.type plt__jit_icall_mono_arch_throw_corlib_exception,@function
plt__jit_icall_mono_arch_throw_corlib_exception:
.Lp_19:
jmp *mono_aot_Mono_Cecil_Rocks_got+2096(%rip)

	.long 2141
	.size plt__jit_icall_mono_arch_throw_corlib_exception,.-plt__jit_icall_mono_arch_throw_corlib_exception
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType:
.Lp_20:
jmp *mono_aot_Mono_Cecil_Rocks_got+2104(%rip)

	.long 2143
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType:
.Lp_21:
jmp *mono_aot_Mono_Cecil_Rocks_got+2112(%rip)

	.long 2145
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType:
.Lp_22:
jmp *mono_aot_Mono_Cecil_Rocks_got+2120(%rip)

	.long 2147
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char:
.Lp_23:
jmp *mono_aot_Mono_Cecil_Rocks_got+2128(%rip)

	.long 2149
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char
	.local plt_Mono_Cecil_Mixin_IsTypeSpecification_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_Mixin_IsTypeSpecification_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_Mixin_IsTypeSpecification_Mono_Cecil_TypeReference:
.Lp_24:
jmp *mono_aot_Mono_Cecil_Rocks_got+2136(%rip)

	.long 2151
	.size plt_Mono_Cecil_Mixin_IsTypeSpecification_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_Mixin_IsTypeSpecification_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_GenericInstanceType_get_GenericArguments
	.type plt_Mono_Cecil_GenericInstanceType_get_GenericArguments,@function
plt_Mono_Cecil_GenericInstanceType_get_GenericArguments:
.Lp_25:
jmp *mono_aot_Mono_Cecil_Rocks_got+2144(%rip)

	.long 2156
	.size plt_Mono_Cecil_GenericInstanceType_get_GenericArguments,.-plt_Mono_Cecil_GenericInstanceType_get_GenericArguments
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_TypeReference_System_Collections_Generic_IList_1_Mono_Cecil_TypeReference_System_Action_1_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_TypeReference_System_Collections_Generic_IList_1_Mono_Cecil_TypeReference_System_Action_1_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_TypeReference_System_Collections_Generic_IList_1_Mono_Cecil_TypeReference_System_Action_1_Mono_Cecil_TypeReference:
.Lp_26:
jmp *mono_aot_Mono_Cecil_Rocks_got+2152(%rip)

	.long 2161
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_TypeReference_System_Collections_Generic_IList_1_Mono_Cecil_TypeReference_System_Action_1_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_TypeReference_System_Collections_Generic_IList_1_Mono_Cecil_TypeReference_System_Action_1_Mono_Cecil_TypeReference
	.local plt__jit_icall_mono_create_corlib_exception_0
	.type plt__jit_icall_mono_create_corlib_exception_0,@function
plt__jit_icall_mono_create_corlib_exception_0:
.Lp_27:
jmp *mono_aot_Mono_Cecil_Rocks_got+2160(%rip)

	.long 2173
	.size plt__jit_icall_mono_create_corlib_exception_0,.-plt__jit_icall_mono_create_corlib_exception_0
	.local plt__rgctx_fetch_0
	.type plt__rgctx_fetch_0,@function
plt__rgctx_fetch_0:
.Lp_28:
jmp *mono_aot_Mono_Cecil_Rocks_got+2168(%rip)

	.long 2216
	.size plt__rgctx_fetch_0,.-plt__rgctx_fetch_0
	.local plt__rgctx_fetch_1
	.type plt__rgctx_fetch_1,@function
plt__rgctx_fetch_1:
.Lp_29:
jmp *mono_aot_Mono_Cecil_Rocks_got+2176(%rip)

	.long 2244
	.size plt__rgctx_fetch_1,.-plt__rgctx_fetch_1
	.local plt_System_Text_StringBuilder_Append_string
	.type plt_System_Text_StringBuilder_Append_string,@function
plt_System_Text_StringBuilder_Append_string:
.Lp_30:
jmp *mono_aot_Mono_Cecil_Rocks_got+2184(%rip)

	.long 2265
	.size plt_System_Text_StringBuilder_Append_string,.-plt_System_Text_StringBuilder_Append_string
	.local plt_Mono_Cecil_FunctionPointerType_get_ReturnType
	.type plt_Mono_Cecil_FunctionPointerType_get_ReturnType,@function
plt_Mono_Cecil_FunctionPointerType_get_ReturnType:
.Lp_31:
jmp *mono_aot_Mono_Cecil_Rocks_got+2192(%rip)

	.long 2270
	.size plt_Mono_Cecil_FunctionPointerType_get_ReturnType,.-plt_Mono_Cecil_FunctionPointerType_get_ReturnType
	.local plt_Mono_Cecil_FunctionPointerType_get_HasParameters
	.type plt_Mono_Cecil_FunctionPointerType_get_HasParameters,@function
plt_Mono_Cecil_FunctionPointerType_get_HasParameters:
.Lp_32:
jmp *mono_aot_Mono_Cecil_Rocks_got+2200(%rip)

	.long 2275
	.size plt_Mono_Cecil_FunctionPointerType_get_HasParameters,.-plt_Mono_Cecil_FunctionPointerType_get_HasParameters
	.local plt_Mono_Cecil_FunctionPointerType_get_Parameters
	.type plt_Mono_Cecil_FunctionPointerType_get_Parameters,@function
plt_Mono_Cecil_FunctionPointerType_get_Parameters:
.Lp_33:
jmp *mono_aot_Mono_Cecil_Rocks_got+2208(%rip)

	.long 2280
	.size plt_Mono_Cecil_FunctionPointerType_get_Parameters,.-plt_Mono_Cecil_FunctionPointerType_get_Parameters
	.local plt_Mono_Cecil_ArrayType_get_IsVector
	.type plt_Mono_Cecil_ArrayType_get_IsVector,@function
plt_Mono_Cecil_ArrayType_get_IsVector:
.Lp_34:
jmp *mono_aot_Mono_Cecil_Rocks_got+2216(%rip)

	.long 2285
	.size plt_Mono_Cecil_ArrayType_get_IsVector,.-plt_Mono_Cecil_ArrayType_get_IsVector
	.local plt_Mono_Cecil_ArrayType_get_Dimensions
	.type plt_Mono_Cecil_ArrayType_get_Dimensions,@function
plt_Mono_Cecil_ArrayType_get_Dimensions:
.Lp_35:
jmp *mono_aot_Mono_Cecil_Rocks_got+2224(%rip)

	.long 2290
	.size plt_Mono_Cecil_ArrayType_get_Dimensions,.-plt_Mono_Cecil_ArrayType_get_Dimensions
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ArrayDimension_System_Collections_Generic_IList_1_Mono_Cecil_ArrayDimension_System_Action_1_Mono_Cecil_ArrayDimension
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ArrayDimension_System_Collections_Generic_IList_1_Mono_Cecil_ArrayDimension_System_Action_1_Mono_Cecil_ArrayDimension,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ArrayDimension_System_Collections_Generic_IList_1_Mono_Cecil_ArrayDimension_System_Action_1_Mono_Cecil_ArrayDimension:
.Lp_36:
jmp *mono_aot_Mono_Cecil_Rocks_got+2232(%rip)

	.long 2295
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ArrayDimension_System_Collections_Generic_IList_1_Mono_Cecil_ArrayDimension_System_Action_1_Mono_Cecil_ArrayDimension,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteList_Mono_Cecil_ArrayDimension_System_Collections_Generic_IList_1_Mono_Cecil_ArrayDimension_System_Action_1_Mono_Cecil_ArrayDimension
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteItemName_string
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteItemName_string,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteItemName_string:
.Lp_37:
jmp *mono_aot_Mono_Cecil_Rocks_got+2240(%rip)

	.long 2307
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteItemName_string,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteItemName_string
	.local plt_string_LastIndexOf_char
	.type plt_string_LastIndexOf_char,@function
plt_string_LastIndexOf_char:
.Lp_38:
jmp *mono_aot_Mono_Cecil_Rocks_got+2248(%rip)

	.long 2309
	.size plt_string_LastIndexOf_char,.-plt_string_LastIndexOf_char
	.local plt_string_Substring_int_int
	.type plt_string_Substring_int_int,@function
plt_string_Substring_int_int:
.Lp_39:
jmp *mono_aot_Mono_Cecil_Rocks_got+2256(%rip)

	.long 2314
	.size plt_string_Substring_int_int,.-plt_string_Substring_int_int
	.local plt_string_Replace_char_char
	.type plt_string_Replace_char_char,@function
plt_string_Replace_char_char:
.Lp_40:
jmp *mono_aot_Mono_Cecil_Rocks_got+2264(%rip)

	.long 2319
	.size plt_string_Replace_char_char,.-plt_string_Replace_char_char
	.local plt_Mono_Cecil_Rocks_DocCommentId__ctor
	.type plt_Mono_Cecil_Rocks_DocCommentId__ctor,@function
plt_Mono_Cecil_Rocks_DocCommentId__ctor:
.Lp_41:
jmp *mono_aot_Mono_Cecil_Rocks_got+2272(%rip)

	.long 2324
	.size plt_Mono_Cecil_Rocks_DocCommentId__ctor,.-plt_Mono_Cecil_Rocks_DocCommentId__ctor
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition:
.Lp_42:
jmp *mono_aot_Mono_Cecil_Rocks_got+2280(%rip)

	.long 2326
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition:
.Lp_43:
jmp *mono_aot_Mono_Cecil_Rocks_got+2288(%rip)

	.long 2328
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition:
.Lp_44:
jmp *mono_aot_Mono_Cecil_Rocks_got+2296(%rip)

	.long 2330
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition:
.Lp_45:
jmp *mono_aot_Mono_Cecil_Rocks_got+2304(%rip)

	.long 2332
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition
	.local plt_Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition
	.type plt_Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition,@function
plt_Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition:
.Lp_46:
jmp *mono_aot_Mono_Cecil_Rocks_got+2312(%rip)

	.long 2334
	.size plt_Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition,.-plt_Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition
	.local plt_System_Nullable_1_int_get_Value
	.type plt_System_Nullable_1_int_get_Value,@function
plt_System_Nullable_1_int_get_Value:
.Lp_47:
jmp *mono_aot_Mono_Cecil_Rocks_got+2320(%rip)

	.long 2336
	.size plt_System_Nullable_1_int_get_Value,.-plt_System_Nullable_1_int_get_Value
	.local plt__rgctx_fetch_2
	.type plt__rgctx_fetch_2,@function
plt__rgctx_fetch_2:
.Lp_48:
jmp *mono_aot_Mono_Cecil_Rocks_got+2328(%rip)

	.long 2405
	.size plt__rgctx_fetch_2,.-plt__rgctx_fetch_2
	.local plt_Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor
	.type plt_Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor,@function
plt_Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor:
.Lp_49:
jmp *mono_aot_Mono_Cecil_Rocks_got+2336(%rip)

	.long 2413
	.size plt_Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor,.-plt_Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor
	.local plt__rgctx_fetch_3
	.type plt__rgctx_fetch_3,@function
plt__rgctx_fetch_3:
.Lp_50:
jmp *mono_aot_Mono_Cecil_Rocks_got+2344(%rip)

	.long 2434
	.size plt__rgctx_fetch_3,.-plt__rgctx_fetch_3
	.local plt__rgctx_fetch_4
	.type plt__rgctx_fetch_4,@function
plt__rgctx_fetch_4:
.Lp_51:
jmp *mono_aot_Mono_Cecil_Rocks_got+2352(%rip)

	.long 2442
	.size plt__rgctx_fetch_4,.-plt__rgctx_fetch_4
	.local plt__rgctx_fetch_5
	.type plt__rgctx_fetch_5,@function
plt__rgctx_fetch_5:
.Lp_52:
jmp *mono_aot_Mono_Cecil_Rocks_got+2360(%rip)

	.long 2460
	.size plt__rgctx_fetch_5,.-plt__rgctx_fetch_5
	.local plt__rgctx_fetch_6
	.type plt__rgctx_fetch_6,@function
plt__rgctx_fetch_6:
.Lp_53:
jmp *mono_aot_Mono_Cecil_Rocks_got+2368(%rip)

	.long 2516
	.size plt__rgctx_fetch_6,.-plt__rgctx_fetch_6
	.local plt_Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
	.type plt_Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,@function
plt_Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF:
.Lp_54:
jmp *mono_aot_Mono_Cecil_Rocks_got+2376(%rip)

	.long 2533
	.size plt_Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF,.-plt_Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF
	.local plt__rgctx_fetch_7
	.type plt__rgctx_fetch_7,@function
plt__rgctx_fetch_7:
.Lp_55:
jmp *mono_aot_Mono_Cecil_Rocks_got+2384(%rip)

	.long 2584
	.size plt__rgctx_fetch_7,.-plt__rgctx_fetch_7
	.local plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int
	.type plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int,@function
plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int:
.Lp_56:
jmp *mono_aot_Mono_Cecil_Rocks_got+2392(%rip)

	.long 2592
	.size plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int,.-plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int
	.local plt_Mono_Cecil_MethodDefinition_get_HasBody
	.type plt_Mono_Cecil_MethodDefinition_get_HasBody,@function
plt_Mono_Cecil_MethodDefinition_get_HasBody:
.Lp_57:
jmp *mono_aot_Mono_Cecil_Rocks_got+2400(%rip)

	.long 2606
	.size plt_Mono_Cecil_MethodDefinition_get_HasBody,.-plt_Mono_Cecil_MethodDefinition_get_HasBody
	.local plt_Mono_Cecil_MemberReference_get_HasImage
	.type plt_Mono_Cecil_MemberReference_get_HasImage,@function
plt_Mono_Cecil_MemberReference_get_HasImage:
.Lp_58:
jmp *mono_aot_Mono_Cecil_Rocks_got+2408(%rip)

	.long 2611
	.size plt_Mono_Cecil_MemberReference_get_HasImage,.-plt_Mono_Cecil_MemberReference_get_HasImage
	.local plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_bool_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_bool
	.type plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_bool_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_bool,@function
plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_bool_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_bool:
.Lp_59:
jmp *mono_aot_Mono_Cecil_Rocks_got+2416(%rip)

	.long 2616
	.size plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_bool_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_bool,.-plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_bool_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_bool
	.local plt_Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.type plt_Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,@function
plt_Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor:
.Lp_60:
jmp *mono_aot_Mono_Cecil_Rocks_got+2424(%rip)

	.long 2628
	.size plt_Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,.-plt_Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.local plt_Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext
	.type plt_Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext,@function
plt_Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext:
.Lp_61:
jmp *mono_aot_Mono_Cecil_Rocks_got+2432(%rip)

	.long 2630
	.size plt_Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext,.-plt_Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext
	.local plt_Mono_Cecil_PE_BinaryStreamReader_Advance_int
	.type plt_Mono_Cecil_PE_BinaryStreamReader_Advance_int,@function
plt_Mono_Cecil_PE_BinaryStreamReader_Advance_int:
.Lp_62:
jmp *mono_aot_Mono_Cecil_Rocks_got+2440(%rip)

	.long 2632
	.size plt_Mono_Cecil_PE_BinaryStreamReader_Advance_int,.-plt_Mono_Cecil_PE_BinaryStreamReader_Advance_int
	.local plt_Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext
	.type plt_Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext,@function
plt_Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext:
.Lp_63:
jmp *mono_aot_Mono_Cecil_Rocks_got+2448(%rip)

	.long 2637
	.size plt_Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext,.-plt_Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext
	.local plt_Mono_Cecil_Cil_CodeReader_MoveBackTo_int
	.type plt_Mono_Cecil_Cil_CodeReader_MoveBackTo_int,@function
plt_Mono_Cecil_Cil_CodeReader_MoveBackTo_int:
.Lp_64:
jmp *mono_aot_Mono_Cecil_Rocks_got+2456(%rip)

	.long 2639
	.size plt_Mono_Cecil_Cil_CodeReader_MoveBackTo_int,.-plt_Mono_Cecil_Cil_CodeReader_MoveBackTo_int
	.local plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_Mono_Cecil_Cil_CodeReader_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_Mono_Cecil_Cil_CodeReader
	.type plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_Mono_Cecil_Cil_CodeReader_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_Mono_Cecil_Cil_CodeReader,@function
plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_Mono_Cecil_Cil_CodeReader_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_Mono_Cecil_Cil_CodeReader:
.Lp_65:
jmp *mono_aot_Mono_Cecil_Rocks_got+2464(%rip)

	.long 2644
	.size plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_Mono_Cecil_Cil_CodeReader_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_Mono_Cecil_Cil_CodeReader,.-plt_Mono_Cecil_ModuleDefinition_Read_Mono_Cecil_MethodDefinition_Mono_Cecil_Cil_CodeReader_Mono_Cecil_MethodDefinition_System_Func_3_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader_Mono_Cecil_Cil_CodeReader
	.local plt_Mono_Cecil_Cil_CodeReader_MoveTo_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Cil_CodeReader_MoveTo_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Cil_CodeReader_MoveTo_Mono_Cecil_MethodDefinition:
.Lp_66:
jmp *mono_aot_Mono_Cecil_Rocks_got+2472(%rip)

	.long 2656
	.size plt_Mono_Cecil_Cil_CodeReader_MoveTo_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Cil_CodeReader_MoveTo_Mono_Cecil_MethodDefinition
	.local plt_Mono_Cecil_Cil_CodeReader_ReadToken
	.type plt_Mono_Cecil_Cil_CodeReader_ReadToken,@function
plt_Mono_Cecil_Cil_CodeReader_ReadToken:
.Lp_67:
jmp *mono_aot_Mono_Cecil_Rocks_got+2480(%rip)

	.long 2661
	.size plt_Mono_Cecil_Cil_CodeReader_ReadToken,.-plt_Mono_Cecil_Cil_CodeReader_ReadToken
	.local plt_Mono_Cecil_Cil_CodeReader_ReadVariables_Mono_Cecil_MetadataToken
	.type plt_Mono_Cecil_Cil_CodeReader_ReadVariables_Mono_Cecil_MetadataToken,@function
plt_Mono_Cecil_Cil_CodeReader_ReadVariables_Mono_Cecil_MetadataToken:
.Lp_68:
jmp *mono_aot_Mono_Cecil_Rocks_got+2488(%rip)

	.long 2666
	.size plt_Mono_Cecil_Cil_CodeReader_ReadVariables_Mono_Cecil_MetadataToken,.-plt_Mono_Cecil_Cil_CodeReader_ReadVariables_Mono_Cecil_MetadataToken
	.local plt_Mono_Cecil_PE_BinaryStreamReader_get_Position
	.type plt_Mono_Cecil_PE_BinaryStreamReader_get_Position,@function
plt_Mono_Cecil_PE_BinaryStreamReader_get_Position:
.Lp_69:
jmp *mono_aot_Mono_Cecil_Rocks_got+2496(%rip)

	.long 2671
	.size plt_Mono_Cecil_PE_BinaryStreamReader_get_Position,.-plt_Mono_Cecil_PE_BinaryStreamReader_get_Position
	.local plt_wrapper_alloc_object_AllocVector_intptr_intptr
	.type plt_wrapper_alloc_object_AllocVector_intptr_intptr,@function
plt_wrapper_alloc_object_AllocVector_intptr_intptr:
.Lp_70:
jmp *mono_aot_Mono_Cecil_Rocks_got+2504(%rip)

	.long 2676
	.size plt_wrapper_alloc_object_AllocVector_intptr_intptr,.-plt_wrapper_alloc_object_AllocVector_intptr_intptr
	.local plt_Mono_Cecil_Cil_OpCode_op_Equality_Mono_Cecil_Cil_OpCode_Mono_Cecil_Cil_OpCode
	.type plt_Mono_Cecil_Cil_OpCode_op_Equality_Mono_Cecil_Cil_OpCode_Mono_Cecil_Cil_OpCode,@function
plt_Mono_Cecil_Cil_OpCode_op_Equality_Mono_Cecil_Cil_OpCode_Mono_Cecil_Cil_OpCode:
.Lp_71:
jmp *mono_aot_Mono_Cecil_Rocks_got+2512(%rip)

	.long 2684
	.size plt_Mono_Cecil_Cil_OpCode_op_Equality_Mono_Cecil_Cil_OpCode_Mono_Cecil_Cil_OpCode,.-plt_Mono_Cecil_Cil_OpCode_op_Equality_Mono_Cecil_Cil_OpCode_Mono_Cecil_Cil_OpCode
	.local plt_Mono_Cecil_Cil_CodeReader_GetCallSite_Mono_Cecil_MetadataToken
	.type plt_Mono_Cecil_Cil_CodeReader_GetCallSite_Mono_Cecil_MetadataToken,@function
plt_Mono_Cecil_Cil_CodeReader_GetCallSite_Mono_Cecil_MetadataToken:
.Lp_72:
jmp *mono_aot_Mono_Cecil_Rocks_got+2520(%rip)

	.long 2689
	.size plt_Mono_Cecil_Cil_CodeReader_GetCallSite_Mono_Cecil_MetadataToken,.-plt_Mono_Cecil_Cil_CodeReader_GetCallSite_Mono_Cecil_MetadataToken
	.local plt_Mono_Cecil_Cil_CodeReader_GetString_Mono_Cecil_MetadataToken
	.type plt_Mono_Cecil_Cil_CodeReader_GetString_Mono_Cecil_MetadataToken,@function
plt_Mono_Cecil_Cil_CodeReader_GetString_Mono_Cecil_MetadataToken:
.Lp_73:
jmp *mono_aot_Mono_Cecil_Rocks_got+2528(%rip)

	.long 2694
	.size plt_Mono_Cecil_Cil_CodeReader_GetString_Mono_Cecil_MetadataToken,.-plt_Mono_Cecil_Cil_CodeReader_GetString_Mono_Cecil_MetadataToken
	.local plt_Mono_Cecil_Cil_CodeReader_GetParameter_int
	.type plt_Mono_Cecil_Cil_CodeReader_GetParameter_int,@function
plt_Mono_Cecil_Cil_CodeReader_GetParameter_int:
.Lp_74:
jmp *mono_aot_Mono_Cecil_Rocks_got+2536(%rip)

	.long 2699
	.size plt_Mono_Cecil_Cil_CodeReader_GetParameter_int,.-plt_Mono_Cecil_Cil_CodeReader_GetParameter_int
	.local plt_Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int
	.type plt_Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int,@function
plt_Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int:
.Lp_75:
jmp *mono_aot_Mono_Cecil_Rocks_got+2544(%rip)

	.long 2704
	.size plt_Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int,.-plt_Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int
	.local plt_Mono_Cecil_MetadataReader_LookupToken_Mono_Cecil_MetadataToken
	.type plt_Mono_Cecil_MetadataReader_LookupToken_Mono_Cecil_MetadataToken,@function
plt_Mono_Cecil_MetadataReader_LookupToken_Mono_Cecil_MetadataToken:
.Lp_76:
jmp *mono_aot_Mono_Cecil_Rocks_got+2552(%rip)

	.long 2706
	.size plt_Mono_Cecil_MetadataReader_LookupToken_Mono_Cecil_MetadataToken,.-plt_Mono_Cecil_MetadataReader_LookupToken_Mono_Cecil_MetadataToken
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition_get_Item_int
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition_get_Item_int,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition_get_Item_int:
.Lp_77:
jmp *mono_aot_Mono_Cecil_Rocks_got+2560(%rip)

	.long 2711
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition_get_Item_int,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition_get_Item_int
	.local plt_Mono_Cecil_Cil_MethodBody_get_Instructions
	.type plt_Mono_Cecil_Cil_MethodBody_get_Instructions,@function
plt_Mono_Cecil_Cil_MethodBody_get_Instructions:
.Lp_78:
jmp *mono_aot_Mono_Cecil_Rocks_got+2568(%rip)

	.long 2722
	.size plt_Mono_Cecil_Cil_MethodBody_get_Instructions,.-plt_Mono_Cecil_Cil_MethodBody_get_Instructions
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_GetEnumerator
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_GetEnumerator,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_GetEnumerator:
.Lp_79:
jmp *mono_aot_Mono_Cecil_Rocks_got+2576(%rip)

	.long 2727
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_GetEnumerator,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_GetEnumerator
	.local plt_Mono_Cecil_Mixin_GetParameter_Mono_Cecil_Cil_MethodBody_int
	.type plt_Mono_Cecil_Mixin_GetParameter_Mono_Cecil_Cil_MethodBody_int,@function
plt_Mono_Cecil_Mixin_GetParameter_Mono_Cecil_Cil_MethodBody_int:
.Lp_80:
jmp *mono_aot_Mono_Cecil_Rocks_got+2584(%rip)

	.long 2738
	.size plt_Mono_Cecil_Mixin_GetParameter_Mono_Cecil_Cil_MethodBody_int,.-plt_Mono_Cecil_Mixin_GetParameter_Mono_Cecil_Cil_MethodBody_int
	.local plt_Mono_Cecil_Cil_MethodBody_get_Variables
	.type plt_Mono_Cecil_Cil_MethodBody_get_Variables,@function
plt_Mono_Cecil_Cil_MethodBody_get_Variables:
.Lp_81:
jmp *mono_aot_Mono_Cecil_Rocks_got+2592(%rip)

	.long 2743
	.size plt_Mono_Cecil_Cil_MethodBody_get_Variables,.-plt_Mono_Cecil_Cil_MethodBody_get_Variables
	.local plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_Cil_Instruction_MoveNext
	.type plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_Cil_Instruction_MoveNext,@function
plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_Cil_Instruction_MoveNext:
.Lp_82:
jmp *mono_aot_Mono_Cecil_Rocks_got+2600(%rip)

	.long 2748
	.size plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_Cil_Instruction_MoveNext,.-plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_Cil_Instruction_MoveNext
	.local plt__jit_icall_ves_icall_thread_finish_async_abort
	.type plt__jit_icall_ves_icall_thread_finish_async_abort,@function
plt__jit_icall_ves_icall_thread_finish_async_abort:
.Lp_83:
jmp *mono_aot_Mono_Cecil_Rocks_got+2608(%rip)

	.long 2759
	.size plt__jit_icall_ves_icall_thread_finish_async_abort,.-plt__jit_icall_ves_icall_thread_finish_async_abort
	.local plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody
	.type plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody,@function
plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody:
.Lp_84:
jmp *mono_aot_Mono_Cecil_Rocks_got+2616(%rip)

	.long 2762
	.size plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody,.-plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody
	.local plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody
	.type plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody,@function
plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody:
.Lp_85:
jmp *mono_aot_Mono_Cecil_Rocks_got+2624(%rip)

	.long 2764
	.size plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody,.-plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_get_Item_int
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_get_Item_int,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_get_Item_int:
.Lp_86:
jmp *mono_aot_Mono_Cecil_Rocks_got+2632(%rip)

	.long 2766
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_get_Item_int,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_get_Item_int
	.local plt_Mono_Cecil_Cil_Instruction_Create_Mono_Cecil_Cil_OpCode
	.type plt_Mono_Cecil_Cil_Instruction_Create_Mono_Cecil_Cil_OpCode,@function
plt_Mono_Cecil_Cil_Instruction_Create_Mono_Cecil_Cil_OpCode:
.Lp_87:
jmp *mono_aot_Mono_Cecil_Rocks_got+2640(%rip)

	.long 2777
	.size plt_Mono_Cecil_Cil_Instruction_Create_Mono_Cecil_Cil_OpCode,.-plt_Mono_Cecil_Cil_Instruction_Create_Mono_Cecil_Cil_OpCode
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_Insert_int_Mono_Cecil_Cil_Instruction
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_Insert_int_Mono_Cecil_Cil_Instruction,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_Insert_int_Mono_Cecil_Cil_Instruction:
.Lp_88:
jmp *mono_aot_Mono_Cecil_Rocks_got+2648(%rip)

	.long 2782
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_Insert_int_Mono_Cecil_Cil_Instruction,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_Instruction_Insert_int_Mono_Cecil_Cil_Instruction
	.local plt_Mono_Cecil_Cil_MethodBody_get_ThisParameter
	.type plt_Mono_Cecil_Cil_MethodBody_get_ThisParameter,@function
plt_Mono_Cecil_Cil_MethodBody_get_ThisParameter:
.Lp_89:
jmp *mono_aot_Mono_Cecil_Rocks_got+2656(%rip)

	.long 2793
	.size plt_Mono_Cecil_Cil_MethodBody_get_ThisParameter,.-plt_Mono_Cecil_Cil_MethodBody_get_ThisParameter
	.local plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody
	.type plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody,@function
plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody:
.Lp_90:
jmp *mono_aot_Mono_Cecil_Rocks_got+2664(%rip)

	.long 2798
	.size plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody,.-plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody
	.local plt_Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody
	.type plt_Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody,@function
plt_Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody:
.Lp_91:
jmp *mono_aot_Mono_Cecil_Rocks_got+2672(%rip)

	.long 2800
	.size plt_Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody,.-plt_Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody
	.local plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction
	.type plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction,@function
plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction:
.Lp_92:
jmp *mono_aot_Mono_Cecil_Rocks_got+2680(%rip)

	.long 2802
	.size plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction,.-plt_Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction
	.local plt_Mono_Cecil_Cil_Instruction_GetSize
	.type plt_Mono_Cecil_Cil_Instruction_GetSize,@function
plt_Mono_Cecil_Cil_Instruction_GetSize:
.Lp_93:
jmp *mono_aot_Mono_Cecil_Rocks_got+2688(%rip)

	.long 2804
	.size plt_Mono_Cecil_Cil_Instruction_GetSize,.-plt_Mono_Cecil_Cil_Instruction_GetSize
	.local plt_Mono_Cecil_MethodDefinition_get_IsNewSlot
	.type plt_Mono_Cecil_MethodDefinition_get_IsNewSlot,@function
plt_Mono_Cecil_MethodDefinition_get_IsNewSlot:
.Lp_94:
jmp *mono_aot_Mono_Cecil_Rocks_got+2696(%rip)

	.long 2809
	.size plt_Mono_Cecil_MethodDefinition_get_IsNewSlot,.-plt_Mono_Cecil_MethodDefinition_get_IsNewSlot
	.local plt_Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition:
.Lp_95:
jmp *mono_aot_Mono_Cecil_Rocks_got+2704(%rip)

	.long 2814
	.size plt_Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition
	.local plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition:
.Lp_96:
jmp *mono_aot_Mono_Cecil_Rocks_got+2712(%rip)

	.long 2816
	.size plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition
	.local plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition
	.type plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition,@function
plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition:
.Lp_97:
jmp *mono_aot_Mono_Cecil_Rocks_got+2720(%rip)

	.long 2818
	.size plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition,.-plt_Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition
	.local plt_Mono_Cecil_TypeDefinition_get_Methods
	.type plt_Mono_Cecil_TypeDefinition_get_Methods,@function
plt_Mono_Cecil_TypeDefinition_get_Methods:
.Lp_98:
jmp *mono_aot_Mono_Cecil_Rocks_got+2728(%rip)

	.long 2820
	.size plt_Mono_Cecil_TypeDefinition_get_Methods,.-plt_Mono_Cecil_TypeDefinition_get_Methods
	.local plt_Mono_Cecil_MetadataResolver_GetMethod_Mono_Collections_Generic_Collection_1_Mono_Cecil_MethodDefinition_Mono_Cecil_MethodReference
	.type plt_Mono_Cecil_MetadataResolver_GetMethod_Mono_Collections_Generic_Collection_1_Mono_Cecil_MethodDefinition_Mono_Cecil_MethodReference,@function
plt_Mono_Cecil_MetadataResolver_GetMethod_Mono_Collections_Generic_Collection_1_Mono_Cecil_MethodDefinition_Mono_Cecil_MethodReference:
.Lp_99:
jmp *mono_aot_Mono_Cecil_Rocks_got+2736(%rip)

	.long 2825
	.size plt_Mono_Cecil_MetadataResolver_GetMethod_Mono_Collections_Generic_Collection_1_Mono_Cecil_MethodDefinition_Mono_Cecil_MethodReference,.-plt_Mono_Cecil_MetadataResolver_GetMethod_Mono_Collections_Generic_Collection_1_Mono_Cecil_MethodDefinition_Mono_Cecil_MethodReference
	.local plt_Mono_Cecil_ModuleDefinition_get_Types
	.type plt_Mono_Cecil_ModuleDefinition_get_Types,@function
plt_Mono_Cecil_ModuleDefinition_get_Types:
.Lp_100:
jmp *mono_aot_Mono_Cecil_Rocks_got+2744(%rip)

	.long 2830
	.size plt_Mono_Cecil_ModuleDefinition_get_Types,.-plt_Mono_Cecil_ModuleDefinition_get_Types
	.local plt_Mono_Cecil_Rocks_Functional_Y_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Rocks_Functional_Y_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Rocks_Functional_Y_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition:
.Lp_101:
jmp *mono_aot_Mono_Cecil_Rocks_got+2752(%rip)

	.long 2835
	.size plt_Mono_Cecil_Rocks_Functional_Y_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Rocks_Functional_Y_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
	.local plt_System_Linq_Enumerable_SelectMany_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
	.type plt_System_Linq_Enumerable_SelectMany_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,@function
plt_System_Linq_Enumerable_SelectMany_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition:
.Lp_102:
jmp *mono_aot_Mono_Cecil_Rocks_got+2760(%rip)

	.long 2847
	.size plt_System_Linq_Enumerable_SelectMany_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition,.-plt_System_Linq_Enumerable_SelectMany_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_:
.Lp_103:
jmp *mono_aot_Mono_Cecil_Rocks_got+2768(%rip)

	.long 2859
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration:
.Lp_104:
jmp *mono_aot_Mono_Cecil_Rocks_got+2776(%rip)

	.long 2861
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration
	.local plt_Mono_Cecil_SecurityDeclaration_get_HasSecurityAttributes
	.type plt_Mono_Cecil_SecurityDeclaration_get_HasSecurityAttributes,@function
plt_Mono_Cecil_SecurityDeclaration_get_HasSecurityAttributes:
.Lp_105:
jmp *mono_aot_Mono_Cecil_Rocks_got+2784(%rip)

	.long 2863
	.size plt_Mono_Cecil_SecurityDeclaration_get_HasSecurityAttributes,.-plt_Mono_Cecil_SecurityDeclaration_get_HasSecurityAttributes
	.local plt_Mono_Cecil_SecurityDeclaration_get_SecurityAttributes
	.type plt_Mono_Cecil_SecurityDeclaration_get_SecurityAttributes,@function
plt_Mono_Cecil_SecurityDeclaration_get_SecurityAttributes:
.Lp_106:
jmp *mono_aot_Mono_Cecil_Rocks_got+2792(%rip)

	.long 2868
	.size plt_Mono_Cecil_SecurityDeclaration_get_SecurityAttributes,.-plt_Mono_Cecil_SecurityDeclaration_get_SecurityAttributes
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_get_Item_int
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_get_Item_int,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_get_Item_int:
.Lp_107:
jmp *mono_aot_Mono_Cecil_Rocks_got+2800(%rip)

	.long 2873
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_get_Item_int,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_get_Item_int
	.local plt_Mono_Cecil_Mixin_IsTypeOf_Mono_Cecil_TypeReference_string_string
	.type plt_Mono_Cecil_Mixin_IsTypeOf_Mono_Cecil_TypeReference_string_string,@function
plt_Mono_Cecil_Mixin_IsTypeOf_Mono_Cecil_TypeReference_string_string:
.Lp_108:
jmp *mono_aot_Mono_Cecil_Rocks_got+2808(%rip)

	.long 2884
	.size plt_Mono_Cecil_Mixin_IsTypeOf_Mono_Cecil_TypeReference_string_string,.-plt_Mono_Cecil_Mixin_IsTypeOf_Mono_Cecil_TypeReference_string_string
	.local plt_Mono_Cecil_SecurityAttribute_get_Properties
	.type plt_Mono_Cecil_SecurityAttribute_get_Properties,@function
plt_Mono_Cecil_SecurityAttribute_get_Properties:
.Lp_109:
jmp *mono_aot_Mono_Cecil_Rocks_got+2816(%rip)

	.long 2889
	.size plt_Mono_Cecil_SecurityAttribute_get_Properties,.-plt_Mono_Cecil_SecurityAttribute_get_Properties
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_get_Item_int
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_get_Item_int,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_get_Item_int:
.Lp_110:
jmp *mono_aot_Mono_Cecil_Rocks_got+2824(%rip)

	.long 2894
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_get_Item_int,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_get_Item_int
	.local plt_System_Security_Permissions_PermissionSetAttribute_CreatePermissionSet
	.type plt_System_Security_Permissions_PermissionSetAttribute_CreatePermissionSet,@function
plt_System_Security_Permissions_PermissionSetAttribute_CreatePermissionSet:
.Lp_111:
jmp *mono_aot_Mono_Cecil_Rocks_got+2832(%rip)

	.long 2905
	.size plt_System_Security_Permissions_PermissionSetAttribute_CreatePermissionSet,.-plt_System_Security_Permissions_PermissionSetAttribute_CreatePermissionSet
	.local plt_System_Security_PermissionSet__ctor_System_Security_Permissions_PermissionState
	.type plt_System_Security_PermissionSet__ctor_System_Security_Permissions_PermissionState,@function
plt_System_Security_PermissionSet__ctor_System_Security_Permissions_PermissionState:
.Lp_112:
jmp *mono_aot_Mono_Cecil_Rocks_got+2840(%rip)

	.long 2910
	.size plt_System_Security_PermissionSet__ctor_System_Security_Permissions_PermissionState,.-plt_System_Security_PermissionSet__ctor_System_Security_Permissions_PermissionState
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_GetEnumerator
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_GetEnumerator,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_GetEnumerator:
.Lp_113:
jmp *mono_aot_Mono_Cecil_Rocks_got+2848(%rip)

	.long 2915
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_GetEnumerator,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_GetEnumerator
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute:
.Lp_114:
jmp *mono_aot_Mono_Cecil_Rocks_got+2856(%rip)

	.long 2926
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute
	.local plt_System_Security_PermissionSet_AddPermission_System_Security_IPermission
	.type plt_System_Security_PermissionSet_AddPermission_System_Security_IPermission,@function
plt_System_Security_PermissionSet_AddPermission_System_Security_IPermission:
.Lp_115:
jmp *mono_aot_Mono_Cecil_Rocks_got+2864(%rip)

	.long 2928
	.size plt_System_Security_PermissionSet_AddPermission_System_Security_IPermission,.-plt_System_Security_PermissionSet_AddPermission_System_Security_IPermission
	.local plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_SecurityAttribute_MoveNext
	.type plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_SecurityAttribute_MoveNext,@function
plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_SecurityAttribute_MoveNext:
.Lp_116:
jmp *mono_aot_Mono_Cecil_Rocks_got+2872(%rip)

	.long 2933
	.size plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_SecurityAttribute_MoveNext,.-plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_SecurityAttribute_MoveNext
	.local plt_System_Type_GetType_string
	.type plt_System_Type_GetType_string,@function
plt_System_Type_GetType_string:
.Lp_117:
jmp *mono_aot_Mono_Cecil_Rocks_got+2880(%rip)

	.long 2944
	.size plt_System_Type_GetType_string,.-plt_System_Type_GetType_string
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration:
.Lp_118:
jmp *mono_aot_Mono_Cecil_Rocks_got+2888(%rip)

	.long 2949
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:
.Lp_119:
jmp *mono_aot_Mono_Cecil_Rocks_got+2896(%rip)

	.long 2951
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:
.Lp_120:
jmp *mono_aot_Mono_Cecil_Rocks_got+2904(%rip)

	.long 2953
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.local plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.type plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,@function
plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute:
.Lp_121:
jmp *mono_aot_Mono_Cecil_Rocks_got+2912(%rip)

	.long 2955
	.size plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute,.-plt_Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute
	.local plt_Mono_Cecil_SecurityAttribute_get_Fields
	.type plt_Mono_Cecil_SecurityAttribute_get_Fields,@function
plt_Mono_Cecil_SecurityAttribute_get_Fields:
.Lp_122:
jmp *mono_aot_Mono_Cecil_Rocks_got+2920(%rip)

	.long 2957
	.size plt_Mono_Cecil_SecurityAttribute_get_Fields,.-plt_Mono_Cecil_SecurityAttribute_get_Fields
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_GetEnumerator
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_GetEnumerator,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_GetEnumerator:
.Lp_123:
jmp *mono_aot_Mono_Cecil_Rocks_got+2928(%rip)

	.long 2962
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_GetEnumerator,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_GetEnumerator
	.local plt_System_Type_GetField_string
	.type plt_System_Type_GetField_string,@function
plt_System_Type_GetField_string:
.Lp_124:
jmp *mono_aot_Mono_Cecil_Rocks_got+2936(%rip)

	.long 2973
	.size plt_System_Type_GetField_string,.-plt_System_Type_GetField_string
	.local plt_System_Reflection_FieldInfo_SetValue_object_object
	.type plt_System_Reflection_FieldInfo_SetValue_object_object,@function
plt_System_Reflection_FieldInfo_SetValue_object_object:
.Lp_125:
jmp *mono_aot_Mono_Cecil_Rocks_got+2944(%rip)

	.long 2978
	.size plt_System_Reflection_FieldInfo_SetValue_object_object,.-plt_System_Reflection_FieldInfo_SetValue_object_object
	.local plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_CustomAttributeNamedArgument_MoveNext
	.type plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_CustomAttributeNamedArgument_MoveNext,@function
plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_CustomAttributeNamedArgument_MoveNext:
.Lp_126:
jmp *mono_aot_Mono_Cecil_Rocks_got+2952(%rip)

	.long 2983
	.size plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_CustomAttributeNamedArgument_MoveNext,.-plt_Mono_Collections_Generic_Collection_1_Enumerator_Mono_Cecil_CustomAttributeNamedArgument_MoveNext
	.local plt_System_Type_GetProperty_string
	.type plt_System_Type_GetProperty_string,@function
plt_System_Type_GetProperty_string:
.Lp_127:
jmp *mono_aot_Mono_Cecil_Rocks_got+2960(%rip)

	.long 2994
	.size plt_System_Type_GetProperty_string,.-plt_System_Type_GetProperty_string
	.local plt_System_Activator_CreateInstance_System_Type_object__
	.type plt_System_Activator_CreateInstance_System_Type_object__,@function
plt_System_Activator_CreateInstance_System_Type_object__:
.Lp_128:
jmp *mono_aot_Mono_Cecil_Rocks_got+2968(%rip)

	.long 2999
	.size plt_System_Activator_CreateInstance_System_Type_object__,.-plt_System_Activator_CreateInstance_System_Type_object__
	.local plt__jit_icall_mono_thread_get_undeniable_exception
	.type plt__jit_icall_mono_thread_get_undeniable_exception,@function
plt__jit_icall_mono_thread_get_undeniable_exception:
.Lp_129:
jmp *mono_aot_Mono_Cecil_Rocks_got+2976(%rip)

	.long 3004
	.size plt__jit_icall_mono_thread_get_undeniable_exception,.-plt__jit_icall_mono_thread_get_undeniable_exception
	.local plt_Mono_Cecil_SecurityDeclaration__ctor_Mono_Cecil_SecurityAction
	.type plt_Mono_Cecil_SecurityDeclaration__ctor_Mono_Cecil_SecurityAction,@function
plt_Mono_Cecil_SecurityDeclaration__ctor_Mono_Cecil_SecurityAction:
.Lp_130:
jmp *mono_aot_Mono_Cecil_Rocks_got+2984(%rip)

	.long 3007
	.size plt_Mono_Cecil_SecurityDeclaration__ctor_Mono_Cecil_SecurityAction,.-plt_Mono_Cecil_SecurityDeclaration__ctor_Mono_Cecil_SecurityAction
	.local plt_Mono_Cecil_ModuleDefinition_get_TypeSystem
	.type plt_Mono_Cecil_ModuleDefinition_get_TypeSystem,@function
plt_Mono_Cecil_ModuleDefinition_get_TypeSystem:
.Lp_131:
jmp *mono_aot_Mono_Cecil_Rocks_got+2992(%rip)

	.long 3012
	.size plt_Mono_Cecil_ModuleDefinition_get_TypeSystem,.-plt_Mono_Cecil_ModuleDefinition_get_TypeSystem
	.local plt_Mono_Cecil_TypeSystem_get_String
	.type plt_Mono_Cecil_TypeSystem_get_String,@function
plt_Mono_Cecil_TypeSystem_get_String:
.Lp_132:
jmp *mono_aot_Mono_Cecil_Rocks_got+3000(%rip)

	.long 3017
	.size plt_Mono_Cecil_TypeSystem_get_String,.-plt_Mono_Cecil_TypeSystem_get_String
	.local plt_Mono_Cecil_CustomAttributeArgument__ctor_Mono_Cecil_TypeReference_object
	.type plt_Mono_Cecil_CustomAttributeArgument__ctor_Mono_Cecil_TypeReference_object,@function
plt_Mono_Cecil_CustomAttributeArgument__ctor_Mono_Cecil_TypeReference_object:
.Lp_133:
jmp *mono_aot_Mono_Cecil_Rocks_got+3008(%rip)

	.long 3022
	.size plt_Mono_Cecil_CustomAttributeArgument__ctor_Mono_Cecil_TypeReference_object,.-plt_Mono_Cecil_CustomAttributeArgument__ctor_Mono_Cecil_TypeReference_object
	.local plt_Mono_Cecil_CustomAttributeNamedArgument__ctor_string_Mono_Cecil_CustomAttributeArgument
	.type plt_Mono_Cecil_CustomAttributeNamedArgument__ctor_string_Mono_Cecil_CustomAttributeArgument,@function
plt_Mono_Cecil_CustomAttributeNamedArgument__ctor_string_Mono_Cecil_CustomAttributeArgument:
.Lp_134:
jmp *mono_aot_Mono_Cecil_Rocks_got+3016(%rip)

	.long 3027
	.size plt_Mono_Cecil_CustomAttributeNamedArgument__ctor_string_Mono_Cecil_CustomAttributeArgument,.-plt_Mono_Cecil_CustomAttributeNamedArgument__ctor_string_Mono_Cecil_CustomAttributeArgument
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_Add_Mono_Cecil_CustomAttributeNamedArgument
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_Add_Mono_Cecil_CustomAttributeNamedArgument,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_Add_Mono_Cecil_CustomAttributeNamedArgument:
.Lp_135:
jmp *mono_aot_Mono_Cecil_Rocks_got+3024(%rip)

	.long 3032
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_Add_Mono_Cecil_CustomAttributeNamedArgument,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_CustomAttributeNamedArgument_Add_Mono_Cecil_CustomAttributeNamedArgument
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_Add_Mono_Cecil_SecurityAttribute
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_Add_Mono_Cecil_SecurityAttribute,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_Add_Mono_Cecil_SecurityAttribute:
.Lp_136:
jmp *mono_aot_Mono_Cecil_Rocks_got+3032(%rip)

	.long 3043
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_Add_Mono_Cecil_SecurityAttribute,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_SecurityAttribute_Add_Mono_Cecil_SecurityAttribute
	.local plt_Mono_Cecil_TypeDefinition_get_HasMethods
	.type plt_Mono_Cecil_TypeDefinition_get_HasMethods,@function
plt_Mono_Cecil_TypeDefinition_get_HasMethods:
.Lp_137:
jmp *mono_aot_Mono_Cecil_Rocks_got+3040(%rip)

	.long 3054
	.size plt_Mono_Cecil_TypeDefinition_get_HasMethods,.-plt_Mono_Cecil_TypeDefinition_get_HasMethods
	.local plt_System_Linq_Enumerable_Where_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool
	.type plt_System_Linq_Enumerable_Where_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool,@function
plt_System_Linq_Enumerable_Where_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool:
.Lp_138:
jmp *mono_aot_Mono_Cecil_Rocks_got+3048(%rip)

	.long 3059
	.size plt_System_Linq_Enumerable_Where_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool,.-plt_System_Linq_Enumerable_Where_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool
	.local plt_Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition:
.Lp_139:
jmp *mono_aot_Mono_Cecil_Rocks_got+3056(%rip)

	.long 3071
	.size plt_Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition
	.local plt_System_Linq_Enumerable_FirstOrDefault_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool
	.type plt_System_Linq_Enumerable_FirstOrDefault_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool,@function
plt_System_Linq_Enumerable_FirstOrDefault_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool:
.Lp_140:
jmp *mono_aot_Mono_Cecil_Rocks_got+3064(%rip)

	.long 3073
	.size plt_System_Linq_Enumerable_FirstOrDefault_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool,.-plt_System_Linq_Enumerable_FirstOrDefault_Mono_Cecil_MethodDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_MethodDefinition_System_Func_2_Mono_Cecil_MethodDefinition_bool
	.local plt_Mono_Cecil_TypeDefinition_get_IsEnum
	.type plt_Mono_Cecil_TypeDefinition_get_IsEnum,@function
plt_Mono_Cecil_TypeDefinition_get_IsEnum:
.Lp_141:
jmp *mono_aot_Mono_Cecil_Rocks_got+3072(%rip)

	.long 3085
	.size plt_Mono_Cecil_TypeDefinition_get_IsEnum,.-plt_Mono_Cecil_TypeDefinition_get_IsEnum
	.local plt_Mono_Cecil_Mixin_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Mixin_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Mixin_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition:
.Lp_142:
jmp *mono_aot_Mono_Cecil_Rocks_got+3080(%rip)

	.long 3090
	.size plt_Mono_Cecil_Mixin_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Mixin_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition
	.local plt_Mono_Cecil_ArrayType__ctor_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_ArrayType__ctor_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_ArrayType__ctor_Mono_Cecil_TypeReference:
.Lp_143:
jmp *mono_aot_Mono_Cecil_Rocks_got+3088(%rip)

	.long 3095
	.size plt_Mono_Cecil_ArrayType__ctor_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_ArrayType__ctor_Mono_Cecil_TypeReference
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_ArrayDimension_Add_Mono_Cecil_ArrayDimension
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_ArrayDimension_Add_Mono_Cecil_ArrayDimension,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_ArrayDimension_Add_Mono_Cecil_ArrayDimension:
.Lp_144:
jmp *mono_aot_Mono_Cecil_Rocks_got+3096(%rip)

	.long 3100
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_ArrayDimension_Add_Mono_Cecil_ArrayDimension,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_ArrayDimension_Add_Mono_Cecil_ArrayDimension
	.local plt_Mono_Cecil_PointerType__ctor_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_PointerType__ctor_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_PointerType__ctor_Mono_Cecil_TypeReference:
.Lp_145:
jmp *mono_aot_Mono_Cecil_Rocks_got+3104(%rip)

	.long 3111
	.size plt_Mono_Cecil_PointerType__ctor_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_PointerType__ctor_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_ByReferenceType__ctor_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_ByReferenceType__ctor_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_ByReferenceType__ctor_Mono_Cecil_TypeReference:
.Lp_146:
jmp *mono_aot_Mono_Cecil_Rocks_got+3112(%rip)

	.long 3116
	.size plt_Mono_Cecil_ByReferenceType__ctor_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_ByReferenceType__ctor_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_OptionalModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_OptionalModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_OptionalModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference:
.Lp_147:
jmp *mono_aot_Mono_Cecil_Rocks_got+3120(%rip)

	.long 3121
	.size plt_Mono_Cecil_OptionalModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_OptionalModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_RequiredModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_RequiredModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_RequiredModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference:
.Lp_148:
jmp *mono_aot_Mono_Cecil_Rocks_got+3128(%rip)

	.long 3126
	.size plt_Mono_Cecil_RequiredModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_RequiredModifierType__ctor_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_GenericInstanceType__ctor_Mono_Cecil_TypeReference_int
	.type plt_Mono_Cecil_GenericInstanceType__ctor_Mono_Cecil_TypeReference_int,@function
plt_Mono_Cecil_GenericInstanceType__ctor_Mono_Cecil_TypeReference_int:
.Lp_149:
jmp *mono_aot_Mono_Cecil_Rocks_got+3136(%rip)

	.long 3131
	.size plt_Mono_Cecil_GenericInstanceType__ctor_Mono_Cecil_TypeReference_int,.-plt_Mono_Cecil_GenericInstanceType__ctor_Mono_Cecil_TypeReference_int
	.local plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_TypeReference_Add_Mono_Cecil_TypeReference
	.type plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_TypeReference_Add_Mono_Cecil_TypeReference,@function
plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_TypeReference_Add_Mono_Cecil_TypeReference:
.Lp_150:
jmp *mono_aot_Mono_Cecil_Rocks_got+3144(%rip)

	.long 3136
	.size plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_TypeReference_Add_Mono_Cecil_TypeReference,.-plt_Mono_Collections_Generic_Collection_1_Mono_Cecil_TypeReference_Add_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_PinnedType__ctor_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_PinnedType__ctor_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_PinnedType__ctor_Mono_Cecil_TypeReference:
.Lp_151:
jmp *mono_aot_Mono_Cecil_Rocks_got+3152(%rip)

	.long 3147
	.size plt_Mono_Cecil_PinnedType__ctor_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_PinnedType__ctor_Mono_Cecil_TypeReference
	.local plt_Mono_Cecil_SentinelType__ctor_Mono_Cecil_TypeReference
	.type plt_Mono_Cecil_SentinelType__ctor_Mono_Cecil_TypeReference,@function
plt_Mono_Cecil_SentinelType__ctor_Mono_Cecil_TypeReference:
.Lp_152:
jmp *mono_aot_Mono_Cecil_Rocks_got+3160(%rip)

	.long 3152
	.size plt_Mono_Cecil_SentinelType__ctor_Mono_Cecil_TypeReference,.-plt_Mono_Cecil_SentinelType__ctor_Mono_Cecil_TypeReference
	.local plt_System_Threading_Thread_get_CurrentThread
	.type plt_System_Threading_Thread_get_CurrentThread,@function
plt_System_Threading_Thread_get_CurrentThread:
.Lp_153:
jmp *mono_aot_Mono_Cecil_Rocks_got+3168(%rip)

	.long 3157
	.size plt_System_Threading_Thread_get_CurrentThread,.-plt_System_Threading_Thread_get_CurrentThread
	.local plt_System_Threading_Thread_get_ManagedThreadId
	.type plt_System_Threading_Thread_get_ManagedThreadId,@function
plt_System_Threading_Thread_get_ManagedThreadId:
.Lp_154:
jmp *mono_aot_Mono_Cecil_Rocks_got+3176(%rip)

	.long 3162
	.size plt_System_Threading_Thread_get_ManagedThreadId,.-plt_System_Threading_Thread_get_ManagedThreadId
	.local plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1
	.type plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1,@function
plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1:
.Lp_155:
jmp *mono_aot_Mono_Cecil_Rocks_got+3184(%rip)

	.long 3190
	.size plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1,.-plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1
	.local plt__rgctx_fetch_8
	.type plt__rgctx_fetch_8,@function
plt__rgctx_fetch_8:
.Lp_156:
jmp *mono_aot_Mono_Cecil_Rocks_got+3192(%rip)

	.long 3211
	.size plt__rgctx_fetch_8,.-plt__rgctx_fetch_8
	.local plt__rgctx_fetch_9
	.type plt__rgctx_fetch_9,@function
plt__rgctx_fetch_9:
.Lp_157:
jmp *mono_aot_Mono_Cecil_Rocks_got+3200(%rip)

	.long 3239
	.size plt__rgctx_fetch_9,.-plt__rgctx_fetch_9
	.local plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose
	.type plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose,@function
plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose:
.Lp_158:
jmp *mono_aot_Mono_Cecil_Rocks_got+3208(%rip)

	.long 3260
	.size plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose,.-plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose
	.local plt__rgctx_fetch_10
	.type plt__rgctx_fetch_10,@function
plt__rgctx_fetch_10:
.Lp_159:
jmp *mono_aot_Mono_Cecil_Rocks_got+3216(%rip)

	.long 3274
	.size plt__rgctx_fetch_10,.-plt__rgctx_fetch_10
	.local plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int_0
	.type plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int_0,@function
plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int_0:
.Lp_160:
jmp *mono_aot_Mono_Cecil_Rocks_got+3224(%rip)

	.long 3282
	.size plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int_0,.-plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int_0
	.local plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator
	.type plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator,@function
plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator:
.Lp_161:
jmp *mono_aot_Mono_Cecil_Rocks_got+3232(%rip)

	.long 3296
	.size plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator,.-plt_Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator
	.local plt_Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.type plt_Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,@function
plt_Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor:
.Lp_162:
jmp *mono_aot_Mono_Cecil_Rocks_got+3240(%rip)

	.long 3310
	.size plt_Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor,.-plt_Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor
	.local plt_Mono_Cecil_TypeDefinition_get_NestedTypes
	.type plt_Mono_Cecil_TypeDefinition_get_NestedTypes,@function
plt_Mono_Cecil_TypeDefinition_get_NestedTypes:
.Lp_163:
jmp *mono_aot_Mono_Cecil_Rocks_got+3248(%rip)

	.long 3312
	.size plt_Mono_Cecil_TypeDefinition_get_NestedTypes,.-plt_Mono_Cecil_TypeDefinition_get_NestedTypes
	.local plt_Mono_Cecil_Rocks_Functional_Prepend_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition
	.type plt_Mono_Cecil_Rocks_Functional_Prepend_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition,@function
plt_Mono_Cecil_Rocks_Functional_Prepend_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition:
.Lp_164:
jmp *mono_aot_Mono_Cecil_Rocks_got+3256(%rip)

	.long 3317
	.size plt_Mono_Cecil_Rocks_Functional_Prepend_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition,.-plt_Mono_Cecil_Rocks_Functional_Prepend_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition_Mono_Cecil_TypeDefinition
	.local plt_Mono_Cecil_MethodDefinition_get_IsConstructor
	.type plt_Mono_Cecil_MethodDefinition_get_IsConstructor,@function
plt_Mono_Cecil_MethodDefinition_get_IsConstructor:
.Lp_165:
jmp *mono_aot_Mono_Cecil_Rocks_got+3264(%rip)

	.long 3329
	.size plt_Mono_Cecil_MethodDefinition_get_IsConstructor,.-plt_Mono_Cecil_MethodDefinition_get_IsConstructor
	.size mono_aot_Mono_Cecil_Rocks_plt,.-mono_aot_Mono_Cecil_Rocks_plt
plt_end:
.section ".rodata"
.subsection 0
	.balign 8
image_table:

	.byte 4,0,0,0,77,111,110,111,46,67,101,99,105,108,46,82,111,99,107,115,0,70,50,68,49,52,53,55,53,45,68,50
	.byte 65,65,45,52,65,53,50,45,57,67,67,68,45,48,70,51,70,57,51,65,53,49,54,57,54,0,0,53,48,99,101,98
	.byte 102,49,99,99,101,98,57,100,48,53,101,0,0,0,0,0,1,0,0,0,0,0,0,0,11,0,0,0,2,0,0,0
	.byte 0,0,0,0,109,115,99,111,114,108,105,98,0,65,49,65,69,54,49,54,54,45,53,57,49,68,45,52,48,50,48,45
	.byte 66,56,49,48,45,50,56,56,68,49,57,65,70,51,56,68,52,0,0,98,55,55,97,53,99,53,54,49,57,51,52,101
	.byte 48,56,57,0,0,0,0,0,1,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,77,111,110,111
	.byte 46,67,101,99,105,108,0,50,70,67,57,65,51,52,50,45,66,70,50,55,45,52,57,68,65,45,65,56,53,52,45,51
	.byte 53,65,67,52,48,54,53,52,65,67,65,0,0,53,48,99,101,98,102,49,99,99,101,98,57,100,48,53,101,0,0,0
	.byte 1,0,0,0,0,0,0,0,11,0,0,0,2,0,0,0,0,0,0,0,83,121,115,116,101,109,46,67,111,114,101,0
	.byte 53,57,48,57,51,69,70,51,45,48,49,65,50,45,52,69,53,65,45,57,49,67,66,45,48,50,57,53,70,66,56,51
	.byte 50,67,67,65,0,0,98,55,55,97,53,99,53,54,49,57,51,52,101,48,56,57,0,0,1,0,0,0,4,0,0,0
	.byte 0,0,0,0,0,0,0,0,0,0,0,0
.section ".rodata"
.subsection 0
	.balign 8
weak_field_indexes:

	.byte 0,0,0,0
.bss 0
	.balign 8
	.local mono_aot_Mono_Cecil_Rocks_got
	.type mono_aot_Mono_Cecil_Rocks_got,@object
mono_aot_Mono_Cecil_Rocks_got:
	.skip 3272
got_end:
.section ".rodata"
.subsection 0
	.balign 8
blob:

	.byte 0,4,1,25,0,0,0,0,4,2,26,27,0,0,4,5,28,29,30,31,32,4,11,33,34,35,36,37,38,39,39,40
	.byte 41,42,4,5,43,44,45,46,47,0,4,2,48,49,4,1,50,4,7,51,52,53,54,55,56,57,4,2,58,59,0,0
	.byte 0,4,8,60,61,62,63,64,65,66,67,0,0,0,0,0,4,5,68,69,70,71,72,0,4,9,73,74,75,76,77,78
	.byte 73,79,80,4,1,81,4,32,82,83,84,85,86,87,88,88,89,90,91,92,93,94,95,96,97,98,98,99,99,61,100,101
	.byte 102,103,104,105,104,105,102,103,0,4,59,106,107,108,108,108,108,109,109,109,109,110,110,110,110,108,111,112,109,113,110,114
	.byte 115,114,115,114,115,114,115,114,115,114,115,114,115,114,115,114,115,114,115,114,116,115,117,118,119,120,121,122,123,124,125,126
	.byte 127,128,128,128,129,128,130,106,106,0,0,0,4,4,128,131,114,115,128,132,4,43,106,128,133,128,134,128,135,128,136,128
	.byte 137,128,138,128,139,128,140,128,141,128,142,128,143,128,144,128,145,128,146,128,147,128,141,128,148,128,149,128,150,128,151,128
	.byte 152,128,153,128,134,128,154,128,141,128,155,128,156,128,157,128,158,128,159,128,160,128,161,128,162,128,163,128,164,128,165,128
	.byte 166,128,167,89,128,168,106,106,4,3,106,106,106,4,16,128,169,128,170,128,171,128,172,128,173,128,174,128,175,128,176,128
	.byte 177,128,178,128,179,128,180,128,181,128,182,128,183,128,184,4,3,106,106,106,4,1,64,0,0,0,4,9,128,185,128,186
	.byte 128,187,128,188,128,189,128,190,128,185,128,191,128,192,0,0,4,6,128,193,128,194,128,195,128,196,128,197,128,198,4,4
	.byte 128,199,128,200,128,200,128,200,0,0,0,0,4,5,128,201,128,202,128,203,128,201,128,203,4,5,128,204,128,193,128,194
	.byte 128,205,128,197,4,9,128,206,128,207,128,208,128,209,128,210,128,211,128,212,128,207,128,213,4,8,128,214,128,208,128,209
	.byte 128,215,128,216,128,217,128,214,128,218,4,9,128,206,128,219,128,208,128,209,128,220,128,221,128,222,128,219,128,213,0,4
	.byte 1,128,223,4,1,128,223,4,1,128,224,4,1,128,225,4,1,128,226,4,1,128,227,4,1,128,228,4,1,128,229,4
	.byte 1,128,230,0,0,0,0,4,2,128,231,128,232,4,1,128,233,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	.byte 0,0,0,5,1,17,2,128,234,74,1,1,17,1,1,17,0,4,2,128,192,128,235,5,1,19,2,128,236,128,186,1
	.byte 1,19,5,1,19,5,128,237,128,238,128,239,128,240,128,241,5,1,20,2,128,242,128,208,1,1,20,1,1,20,1,1
	.byte 20,1,1,20,11,0,35,37,45,49,51,31,47,54,9,54,10,54,11,54,12,54,13,54,129,3,6,93,6,91,6,90
	.byte 6,92,6,101,6,128,188,6,129,9,6,96,6,128,167,6,128,145,6,128,144,13,2,131,124,1,15,0,11,15,0,35
	.byte 13,3,219,0,0,4,5,21,43,21,28,3,219,0,0,4,1,21,0,32,255,254,0,0,0,0,255,43,0,0,1,7
	.byte 7,130,169,128,201,130,242,130,242,129,123,128,150,129,72,7,6,129,21,130,242,130,242,129,208,130,113,130,57,10,2,13
	.byte 2,10,2,128,170,2,10,2,93,2,10,2,95,2,10,2,96,2,10,2,128,145,2,10,2,128,146,2,10,2,128,166
	.byte 2,13,3,219,0,0,5,5,10,43,10,28,3,219,0,0,5,1,10,0,32,255,254,0,0,0,0,255,43,0,0,2
	.byte 5,194,0,6,27,5,194,0,6,26,15,0,59,15,0,73,15,0,79,13,3,219,0,0,9,5,22,43,22,28,3,219
	.byte 0,0,9,1,22,0,15,0,83,5,194,0,4,127,5,194,0,4,120,13,1,2,5,194,0,4,132,10,2,90,2,10
	.byte 2,128,138,2,10,2,128,186,2,10,2,86,2,10,2,128,168,2,5,194,0,4,122,13,1,16,13,3,219,0,0,15
	.byte 5,108,43,108,28,3,219,0,0,15,1,108,0,14,1,17,18,14,1,17,17,13,3,219,0,0,16,5,111,43,111,28
	.byte 3,219,0,0,16,1,111,0,32,255,254,0,0,0,0,255,43,0,0,6,13,1,15,14,2,128,203,2,131,32,14,2
	.byte 129,9,2,133,164,14,2,129,9,2,133,163,7,20,133,129,143,177,136,185,137,110,143,177,130,238,148,154,138,213,139,135
	.byte 140,82,131,147,143,177,143,177,143,6,141,176,132,203,134,54,138,35,142,91,141,5,5,26,13,6,1,2,129,17,1,5
	.byte 35,5,34,14,2,129,9,2,133,196,5,27,5,28,5,29,5,30,5,31,5,32,5,38,5,33,5,37,5,36,10,2
	.byte 128,192,2,5,39,10,2,128,140,2,5,41,10,2,91,2,5,40,13,3,219,0,0,19,7,53,129,247,130,245,131,246
	.byte 132,247,133,248,135,5,136,21,137,37,138,53,139,66,140,82,141,98,142,114,143,68,144,22,144,232,145,186,146,140,168,86
	.byte 147,94,148,106,149,118,150,130,151,142,152,154,153,166,154,178,155,190,156,202,157,214,168,86,168,86,168,86,168,86,168,86
	.byte 168,86,168,86,168,86,168,86,168,86,159,31,159,241,160,195,161,101,162,7,162,169,163,75,163,237,164,143,165,49,165,211
	.byte 166,117,167,23,14,2,129,9,2,134,108,14,2,129,9,2,134,111,14,2,129,9,2,134,113,14,2,129,9,2,134,109
	.byte 14,2,129,9,2,134,110,14,2,129,9,2,134,112,14,2,129,9,2,133,197,13,2,129,17,1,10,2,129,66,1,14
	.byte 2,129,9,2,133,220,14,2,129,9,2,133,221,14,2,129,9,2,133,222,14,2,129,9,2,133,223,14,2,129,9,2
	.byte 133,224,14,2,129,9,2,133,225,14,2,129,9,2,133,226,14,2,129,9,2,133,227,14,2,129,9,2,133,228,14,2
	.byte 129,9,2,133,229,14,2,129,9,2,133,230,14,2,129,9,2,133,231,14,2,129,9,2,133,232,14,2,129,9,2,134
	.byte 96,10,2,129,18,1,14,2,129,9,2,134,14,7,6,129,141,145,229,157,251,135,53,147,119,140,141,10,2,128,160,2
	.byte 7,4,130,57,131,53,132,49,133,45,14,2,129,9,2,133,167,14,2,129,9,2,133,168,14,2,129,9,2,133,169,14
	.byte 2,129,9,2,133,170,14,2,129,9,2,133,179,10,2,129,54,2,7,4,135,145,136,141,137,137,138,133,14,2,129,9
	.byte 2,133,171,14,2,129,9,2,133,172,14,2,129,9,2,133,173,14,2,129,9,2,133,174,14,2,129,9,2,133,182,7
	.byte 4,140,233,141,229,142,225,143,221,14,2,129,9,2,133,175,14,2,129,9,2,133,176,14,2,129,9,2,133,177,14,2
	.byte 129,9,2,133,178,14,2,129,9,2,133,184,14,2,129,9,2,133,180,14,2,129,9,2,133,183,10,2,129,17,1,7
	.byte 10,149,22,149,226,150,174,151,122,152,70,153,18,153,222,154,170,155,118,156,66,14,2,129,9,2,133,186,14,2,129,9
	.byte 2,133,187,14,2,129,9,2,133,188,14,2,129,9,2,133,189,14,2,129,9,2,133,190,14,2,129,9,2,133,191,14
	.byte 2,129,9,2,133,192,14,2,129,9,2,133,193,14,2,129,9,2,133,194,14,2,129,9,2,133,195,13,2,129,66,1
	.byte 10,2,128,255,2,7,13,129,240,130,210,131,132,132,54,132,232,133,154,134,76,134,254,135,176,136,98,137,20,137,198,138
	.byte 120,14,2,129,9,2,133,207,14,2,129,9,2,133,208,14,2,129,9,2,133,209,14,2,129,9,2,133,210,14,2,129
	.byte 9,2,133,211,14,2,129,9,2,133,212,14,2,129,9,2,133,213,14,2,129,9,2,133,214,14,2,129,9,2,133,215
	.byte 14,2,129,9,2,133,216,14,2,129,9,2,133,217,14,2,129,9,2,133,218,14,2,129,9,2,133,219,14,2,129,9
	.byte 2,134,97,14,1,19,21,14,1,19,20,13,3,219,0,0,20,5,116,43,116,28,3,219,0,0,20,1,116,0,32,255
	.byte 254,0,0,0,0,255,43,0,0,7,32,255,254,0,0,0,0,255,43,0,0,8,15,0,128,145,15,0,128,201,13,2
	.byte 132,28,1,10,2,129,79,1,15,0,128,247,15,0,128,255,13,2,131,180,1,13,3,219,0,0,23,13,6,1,2,130
	.byte 30,1,13,2,132,38,1,10,2,132,39,1,13,2,128,176,2,13,2,128,175,2,14,3,219,0,0,25,5,14,1,20
	.byte 23,14,1,20,22,13,3,219,0,0,26,5,119,43,119,28,3,219,0,0,26,1,119,0,32,255,254,0,0,0,0,255
	.byte 43,0,0,9,14,1,20,24,5,120,43,120,28,3,219,0,0,26,1,120,0,32,255,254,0,0,0,0,255,43,0,0
	.byte 10,14,1,20,25,5,121,43,121,28,3,219,0,0,26,1,121,0,13,2,13,2,13,2,128,166,2,13,2,128,170,2
	.byte 13,2,128,145,2,13,2,128,146,2,13,2,95,2,13,2,128,163,2,13,2,128,177,2,7,3,92,128,169,129,119,5
	.byte 193,0,97,156,5,193,0,10,50,13,1,17,32,255,254,0,0,0,0,255,43,0,0,11,13,1,19,13,1,18,13,3
	.byte 219,0,0,33,5,113,43,113,28,3,219,0,0,33,1,113,0,13,1,20,6,129,9,3,255,252,0,0,0,25,2,3
	.byte 193,0,38,47,3,16,3,193,0,38,82,3,17,3,193,0,38,86,3,9,3,6,3,7,3,193,0,13,240,6,128,166
	.byte 6,128,132,6,108,3,194,0,5,226,3,10,3,194,0,7,85,3,255,254,0,0,0,0,255,43,0,0,1,6,107,3
	.byte 15,3,14,3,11,3,13,3,194,0,0,144,3,194,0,4,32,3,255,254,0,0,0,0,255,43,0,0,2,6,128,131
	.byte 5,0,30,0,1,255,255,255,255,255,12,5,1,28,7,136,128,1,7,136,139,255,253,0,0,0,1,2,0,12,2,136
	.byte 145,4,2,138,247,1,136,145,33,136,149,138,13,255,253,0,0,0,7,136,161,1,192,0,103,52,1,136,145,4,2,138
	.byte 237,1,136,145,33,136,149,138,13,255,253,0,0,0,7,136,189,1,192,0,103,24,1,136,145,3,193,0,38,69,3,194
	.byte 0,4,6,3,194,0,4,4,3,194,0,4,5,3,194,0,0,175,3,194,0,0,173,3,255,254,0,0,0,0,255,43
	.byte 0,0,3,3,18,3,193,0,14,102,3,193,0,14,58,3,193,0,14,36,3,1,3,2,3,5,3,4,3,3,3,8
	.byte 3,255,254,0,0,0,0,202,0,0,75,5,0,30,0,1,255,255,255,255,255,23,5,1,28,7,137,43,5,0,30,1
	.byte 1,255,255,255,255,255,23,5,1,28,7,137,60,2,7,137,54,7,137,71,255,253,0,0,0,1,3,0,23,2,137,77
	.byte 4,1,13,137,77,33,137,84,148,7,7,137,96,3,255,253,0,0,0,7,137,96,0,85,1,137,77,4,2,128,174,1
	.byte 137,77,33,137,84,148,7,7,137,123,33,137,84,138,27,255,253,0,0,0,7,137,96,0,86,1,137,77,33,137,84,184
	.byte 65,7,137,123,1,255,253,0,0,0,7,137,96,0,86,1,137,77,0,5,0,30,0,1,255,255,255,255,255,24,5,1
	.byte 28,7,137,179,1,7,137,190,255,253,0,0,0,1,3,0,24,2,137,196,33,137,200,138,21,255,253,0,0,0,1,3
	.byte 0,25,2,137,196,3,255,253,0,0,0,1,3,0,25,2,137,196,5,0,30,0,1,255,255,255,255,255,25,5,1,28
	.byte 7,137,242,1,7,137,253,255,253,0,0,0,1,3,0,25,2,138,3,4,1,14,138,3,33,138,7,148,7,7,138,19
	.byte 3,255,253,0,0,0,7,138,19,0,87,1,138,3,3,194,0,5,116,3,194,0,5,8,3,255,254,0,0,0,0,255
	.byte 43,0,0,5,3,44,3,46,3,194,0,8,195,3,45,3,194,0,9,176,3,255,254,0,0,0,0,255,43,0,0,6
	.byte 3,194,0,9,175,3,194,0,9,198,3,194,0,9,182,3,194,0,8,191,3,255,252,0,0,0,25,1,3,194,0,10
	.byte 156,3,194,0,9,189,3,194,0,9,186,3,194,0,9,187,3,47,3,194,0,1,145,3,255,254,0,0,0,0,202,0
	.byte 0,119,3,194,0,10,119,3,255,254,0,0,0,0,202,0,0,121,3,194,0,0,111,3,194,0,10,123,3,255,254,0
	.byte 0,0,0,202,0,0,151,6,129,41,3,52,3,53,3,255,254,0,0,0,0,202,0,0,153,3,194,0,10,95,3,255
	.byte 254,0,0,0,0,202,0,0,156,3,194,0,10,124,3,54,3,56,3,55,3,194,0,10,92,3,194,0,5,154,3,59
	.byte 3,60,3,57,3,194,0,7,169,3,194,0,5,38,3,194,0,6,149,3,255,254,0,0,0,0,255,43,0,0,7,3
	.byte 255,254,0,0,0,0,255,43,0,0,8,3,64,3,65,3,194,0,7,140,3,194,0,7,141,3,255,254,0,0,0,0
	.byte 202,0,0,221,3,194,0,0,143,3,194,0,7,134,3,255,254,0,0,0,0,202,0,0,227,3,193,0,44,65,3,193
	.byte 0,40,129,3,255,254,0,0,0,0,202,0,0,236,3,66,3,193,0,40,133,3,255,254,0,0,0,0,202,0,0,239
	.byte 3,193,0,17,199,3,70,3,67,3,68,3,69,3,194,0,7,132,3,255,254,0,0,0,0,202,0,0,249,3,193,0
	.byte 17,101,3,193,0,72,104,3,255,254,0,0,0,0,202,0,0,253,3,193,0,17,128,3,193,0,20,210,6,129,1,3
	.byte 194,0,7,144,3,194,0,6,139,3,194,0,8,121,3,194,0,3,52,3,194,0,3,55,3,255,254,0,0,0,0,202
	.byte 0,1,9,3,255,254,0,0,0,0,202,0,1,10,3,194,0,7,168,3,255,254,0,0,0,0,255,43,0,0,9,3
	.byte 72,3,255,254,0,0,0,0,255,43,0,0,10,3,194,0,7,232,3,194,0,0,139,3,194,0,0,182,3,255,254,0
	.byte 0,0,0,202,0,1,20,3,194,0,7,72,3,194,0,7,116,3,194,0,6,37,3,194,0,6,47,3,194,0,4,40
	.byte 3,255,254,0,0,0,0,202,0,1,27,3,194,0,7,29,3,194,0,7,151,3,193,0,31,93,3,193,0,31,154,5
	.byte 0,19,0,1,0,1,14,5,1,28,7,140,95,1,7,140,103,4,1,14,140,109,3,255,253,0,0,0,7,140,113,0
	.byte 90,1,140,109,4,2,138,244,1,140,109,33,140,113,138,12,255,253,0,0,0,7,140,132,1,192,0,103,48,1,140,109
	.byte 4,2,138,245,1,140,109,33,140,113,138,12,255,253,0,0,0,7,140,160,1,192,0,103,49,1,140,109,3,255,253,0
	.byte 0,0,7,140,113,0,88,1,140,109,33,140,113,148,6,7,140,113,3,255,253,0,0,0,7,140,113,0,87,1,140,109
	.byte 3,255,253,0,0,0,7,140,113,0,94,1,140,109,3,43,3,194,0,7,167,3,255,254,0,0,0,0,255,43,0,0
	.byte 11,3,194,0,5,208,128,138,0,102,0,5,0,6,12,56,12,70,10,68,0,128,138,0,57,0,5,0,4,0,66,18
	.byte 38,0,128,138,0,57,0,5,0,4,0,66,18,38,0,128,138,0,94,0,5,0,8,0,66,26,48,16,32,16,32,0
	.byte 128,138,17,128,249,0,14,0,36,0,78,18,32,12,32,4,16,26,40,16,32,24,58,10,20,10,22,2,0,12,32,4
	.byte 8,14,30,10,16,0,0,12,24,4,8,14,22,0,128,138,46,128,211,0,47,0,24,0,62,28,18,12,70,4,16,12
	.byte 30,20,32,4,16,12,30,20,32,4,4,4,14,113,22,0,128,138,0,90,0,5,0,8,0,66,28,48,14,38,10,18
	.byte 0,128,138,69,112,0,9,0,12,0,72,18,36,12,32,4,16,14,30,10,20,0,128,138,92,128,255,0,39,0,9,0
	.byte 72,28,40,38,152,2,28,40,0,128,138,115,131,94,0,95,0,66,0,98,12,32,2,8,74,80,76,82,24,92,2,10
	.byte 24,86,10,16,28,40,2,10,24,92,2,10,24,92,2,10,28,40,34,94,12,26,2,10,26,40,16,32,34,102,12,26
	.byte 2,10,28,102,2,10,28,102,2,10,24,86,10,16,28,40,2,4,16,26,0,128,138,17,129,88,0,62,0,24,0,78
	.byte 12,16,10,18,16,16,14,16,12,26,28,40,14,34,34,152,2,28,40,141,1,28,0,128,139,115,128,209,0,24,2,1
	.byte 10,28,0,4,32,28,0,7,255,255,0,0,0,136,149,0,0,20,0,114,4,6,4,64,8,10,26,40,2,0,16,56
	.byte 10,14,8,6,14,50,0,128,138,128,156,128,132,0,14,0,12,0,88,14,38,10,16,26,40,14,38,10,16,0,128,138
	.byte 17,128,145,0,14,0,16,0,78,34,44,14,30,10,16,12,32,4,16,14,30,10,16,0,128,138,17,129,88,0,44,0
	.byte 23,0,78,14,16,10,16,12,32,4,16,34,44,2,10,34,44,14,34,34,138,2,34,44,0,128,138,128,185,128,173,0
	.byte 14,0,16,0,88,24,40,16,32,14,38,12,20,28,40,14,44,10,16,0,128,138,115,129,86,0,24,0,42,0,104,12
	.byte 24,4,18,14,30,12,20,26,40,2,0,12,30,10,62,4,16,24,58,12,22,26,40,2,0,14,30,6,18,18,40,8
	.byte 8,16,40,2,0,26,36,0,128,138,0,128,140,0,5,0,10,0,66,32,82,18,42,18,58,12,22,0,128,138,128,214
	.byte 50,0,5,0,4,0,56,22,34,0,128,138,128,231,130,123,0,128,140,0,54,0,98,28,18,10,70,2,6,14,40,16
	.byte 28,16,28,16,26,20,30,16,26,16,26,20,36,24,100,4,10,24,100,4,10,24,100,4,10,24,100,4,10,24,100,28
	.byte 0,12,18,215,2,38,180,2,76,12,44,0,128,138,69,63,0,9,0,6,0,72,14,16,10,20,0,128,138,129,10,129
	.byte 52,0,9,0,32,0,114,16,40,14,18,4,16,26,58,16,36,10,22,2,0,28,40,16,48,14,18,4,16,26,66,16
	.byte 36,30,40,18,30,0,128,139,129,33,129,91,0,39,2,1,10,13,0,4,8,13,0,7,255,255,0,0,0,137,84,0
	.byte 0,15,0,72,10,82,2,6,14,22,38,232,2,10,66,12,8,0,128,139,0,122,0,43,2,1,10,8,0,4,0,8
	.byte 0,7,255,255,0,0,0,137,200,0,0,8,0,76,28,28,14,54,35,10,0,128,139,129,56,128,169,0,5,2,1,10
	.byte 8,0,4,0,8,0,7,255,255,0,0,0,138,7,0,0,7,0,76,14,100,28,152,1,0,128,138,129,73,129,208,0
	.byte 128,138,0,31,0,82,10,40,2,6,14,70,28,18,38,26,12,32,4,16,12,32,16,16,12,34,38,152,2,115,28,54
	.byte 76,91,36,0,128,138,115,128,234,0,42,0,32,0,98,16,28,14,20,12,38,2,8,8,20,8,16,12,24,18,28,4
	.byte 4,14,44,12,16,16,0,14,16,10,24,35,48,0,128,138,129,102,129,227,0,49,0,19,0,92,12,30,76,174,3,16
	.byte 34,10,34,14,72,14,14,24,80,14,82,0,128,138,129,137,129,3,0,14,0,19,0,72,14,16,14,38,12,34,12,42
	.byte 24,136,1,20,58,10,68,12,26,0,128,138,129,166,149,14,0,95,0,238,1,0,156,2,14,30,14,14,14,14,12,26
	.byte 6,12,10,60,12,34,4,8,18,28,22,92,14,250,1,28,148,4,18,18,184,1,98,16,192,2,10,10,16,32,18,36
	.byte 6,22,4,56,20,32,2,56,12,34,12,20,20,198,2,10,10,18,178,2,10,48,10,10,18,176,2,10,48,10,10,24
	.byte 158,4,4,16,18,178,2,10,48,10,10,18,178,2,10,48,10,10,18,176,2,10,48,10,10,18,176,2,10,48,10,10
	.byte 18,170,2,10,48,10,10,18,170,2,10,48,10,10,20,178,2,10,42,10,48,10,10,20,130,2,10,42,10,48,10,10
	.byte 20,130,2,10,32,10,42,10,10,20,130,2,10,32,10,42,10,10,20,130,2,10,32,10,42,10,10,20,130,2,10,32
	.byte 10,42,10,10,14,34,14,42,18,46,18,38,18,22,18,34,18,34,28,44,18,26,18,34,22,44,18,26,22,44,30,146
	.byte 3,4,10,30,140,3,4,10,30,140,3,4,10,18,90,8,24,20,154,2,4,10,18,80,8,18,20,144,2,4,10,12
	.byte 36,12,26,0,128,138,92,69,0,9,0,6,0,72,12,16,12,32,0,128,174,129,220,2,169,50,1,2,255,255,255,254
	.byte 96,168,228,128,171,168,161,168,163,0,16,168,140,0,5,168,156,0,78,0,188,2,0,130,2,28,18,12,24,10,42,2
	.byte 0,10,50,16,28,14,216,1,14,14,12,18,14,206,1,16,16,184,3,80,22,26,10,10,26,224,1,10,146,2,10,10
	.byte 26,230,1,10,146,2,10,10,26,230,1,10,146,2,10,10,26,230,1,10,146,2,10,10,24,228,1,12,26,10,146,2
	.byte 10,10,24,228,1,12,32,10,146,2,10,10,24,228,1,12,32,10,146,2,10,10,24,228,1,12,32,10,146,2,10,10
	.byte 24,228,1,12,26,10,146,2,10,10,24,228,1,12,32,10,146,2,10,10,24,228,1,12,32,10,146,2,10,10,24,228
	.byte 1,12,32,10,146,2,10,10,22,154,3,10,10,22,154,3,10,10,22,154,3,10,10,22,154,3,10,10,22,154,3,10
	.byte 10,22,154,3,10,10,34,142,4,10,10,34,142,4,10,10,34,142,4,10,10,34,142,4,10,10,34,142,4,10,10,34
	.byte 142,4,10,10,34,142,4,10,10,34,142,4,10,10,34,142,4,10,10,34,142,4,10,10,24,220,1,30,172,3,10,10
	.byte 22,154,3,10,10,22,154,3,10,10,22,186,2,10,10,22,186,2,10,10,22,186,2,4,10,22,186,2,4,10,22,186
	.byte 2,4,10,22,186,2,4,10,22,186,2,4,10,22,186,2,4,10,22,186,2,4,10,22,186,2,4,10,22,186,2,4
	.byte 10,22,186,2,0,0,14,52,10,16,4,140,1,26,60,203,18,52,0,128,138,92,128,156,0,9,0,7,0,42,14,174
	.byte 1,14,78,0,128,138,69,128,152,0,9,0,7,0,32,14,174,1,14,80,0,128,138,128,214,102,0,43,0,10,0,56
	.byte 28,26,12,18,12,18,45,10,0,128,138,130,12,131,33,0,46,0,44,0,172,1,4,6,4,54,12,24,14,34,14,178
	.byte 1,14,10,8,18,12,18,12,84,18,30,18,26,36,228,3,12,34,30,248,1,10,22,0,0,8,6,14,24,10,20,0
	.byte 128,174,130,53,2,159,6,1,2,255,255,255,254,208,158,137,128,183,158,70,158,72,0,16,158,49,0,5,158,65,0,117
	.byte 0,161,2,0,138,2,28,18,14,16,12,24,10,42,2,0,10,58,16,28,16,216,1,18,16,18,24,74,76,10,10,12
	.byte 18,22,92,8,16,12,32,12,44,4,10,4,6,4,4,12,32,4,8,8,6,44,66,4,10,22,238,3,10,10,22,238
	.byte 3,10,10,22,238,3,10,10,22,238,3,10,10,22,26,24,222,1,10,150,2,10,10,12,18,22,92,44,64,4,10,22
	.byte 238,3,10,10,22,238,3,10,10,22,238,3,10,10,22,238,3,10,10,22,26,24,222,1,10,150,2,10,10,12,18,22
	.byte 92,44,64,4,10,22,238,3,10,10,22,238,3,10,10,22,238,3,10,10,22,238,3,10,10,22,26,24,222,1,10,150
	.byte 2,10,10,12,18,22,92,8,16,12,32,12,44,4,10,4,6,4,4,12,32,4,8,8,6,22,26,24,222,1,10,150
	.byte 2,10,10,12,18,20,92,20,22,24,222,1,10,150,2,10,10,12,18,14,84,98,76,10,10,22,142,3,10,10,22,142
	.byte 3,10,10,22,142,3,4,10,22,142,3,4,10,22,142,3,4,10,22,142,3,4,10,22,142,3,4,10,22,142,3,4
	.byte 10,22,142,3,4,10,22,142,3,4,10,12,20,18,26,38,172,3,0,0,14,52,10,16,4,140,1,26,60,2,16,12
	.byte 16,131,15,44,0,128,174,130,107,2,129,155,1,2,255,255,255,255,200,129,145,123,129,89,129,91,0,13,129,71,0,5
	.byte 129,84,0,10,0,38,0,170,1,12,16,12,24,10,36,2,0,4,50,16,22,14,168,1,14,8,4,16,12,24,4,8
	.byte 12,16,0,0,14,46,4,16,4,122,26,50,0,128,138,130,143,140,1,0,37,0,101,0,176,1,12,16,20,86,12,16
	.byte 12,222,1,16,56,10,22,10,16,12,12,2,14,14,222,1,16,18,122,80,32,36,22,186,3,10,10,22,218,2,10,10
	.byte 22,218,2,10,10,22,218,2,10,10,22,218,2,4,10,22,218,2,4,10,22,218,2,4,10,22,218,2,4,10,22,218
	.byte 2,4,10,22,218,2,4,10,22,218,2,4,10,22,218,2,4,10,22,218,2,4,10,22,218,2,2,0,0,128,174,130
	.byte 107,2,129,24,1,2,255,255,255,255,208,129,14,86,128,214,128,216,0,13,128,196,0,5,128,209,0,10,0,28,0,106
	.byte 4,6,12,24,10,36,2,0,4,60,16,22,14,20,14,24,4,6,14,46,4,8,4,122,26,50,0,128,138,130,179,129
	.byte 63,0,72,0,37,0,82,28,18,12,66,6,8,2,16,12,32,6,8,2,16,12,92,12,16,4,54,16,28,8,10,2
	.byte 10,12,22,2,0,8,10,137,1,44,0,128,138,17,128,146,0,52,0,14,0,72,28,64,14,22,10,10,2,10,6,6
	.byte 53,32,0,128,138,17,91,0,14,0,14,0,72,8,10,2,8,14,16,8,16,2,8,12,24,0,128,138,0,66,0,5
	.byte 0,6,0,66,12,36,12,20,0,128,138,17,129,98,0,82,0,13,0,72,28,18,12,30,72,138,3,10,30,115,28,0
	.byte 128,138,46,30,0,9,0,6,0,22,12,16,4,4,0,128,138,0,128,131,0,43,0,16,0,74,28,28,16,34,4,8
	.byte 2,8,2,4,12,20,57,10,0,128,138,130,214,130,96,0,57,0,73,0,146,1,6,24,12,32,4,16,12,24,10,20
	.byte 8,10,2,14,12,24,14,32,12,20,30,46,6,8,2,14,12,36,10,50,2,6,12,26,14,36,18,52,14,10,12,86
	.byte 18,10,8,24,24,38,4,8,24,38,8,20,14,66,4,4,14,66,30,0,14,24,4,62,43,48,14,10,0,128,174,130
	.byte 249,2,129,75,1,2,255,255,255,255,200,129,58,125,129,2,129,4,0,13,128,240,0,5,128,253,0,14,0,32,0,114
	.byte 12,70,2,6,12,24,10,36,2,0,4,62,16,22,16,28,14,30,2,0,14,46,4,8,4,122,26,50,4,10,0,128
	.byte 138,128,185,128,213,0,70,0,16,0,82,12,16,10,30,10,10,14,28,38,48,32,46,10,26,0,128,138,128,185,128,195
	.byte 0,14,0,16,0,82,12,106,4,8,14,26,0,0,12,106,4,8,14,26,0,128,174,131,35,2,129,121,1,2,255,255
	.byte 255,255,152,129,111,128,134,129,62,129,64,0,13,129,44,0,5,129,57,0,10,0,35,0,182,1,14,14,12,36,10,36
	.byte 2,0,4,60,16,68,16,8,10,26,16,52,16,8,10,28,0,0,14,32,4,16,4,122,26,36,0,128,174,131,35,2
	.byte 129,124,1,2,255,255,255,255,152,129,114,128,134,129,65,129,67,0,13,129,47,0,5,129,60,0,10,0,35,0,182,1
	.byte 14,14,12,36,10,36,2,0,4,60,16,68,16,8,10,26,16,52,16,8,12,34,0,0,14,32,4,16,4,122,26,36
	.byte 0,128,142,131,71,129,123,1,0,4,2,129,36,1,47,128,206,128,206,0,28,0,18,0,94,30,100,22,122,12,86,6
	.byte 58,24,76,12,102,4,56,2,8,0,128,138,131,101,130,65,0,90,0,40,0,106,28,18,28,18,12,66,12,24,30,60
	.byte 10,114,14,42,22,52,10,36,12,26,10,38,10,90,10,130,1,10,82,12,36,12,36,207,1,28,27,76,0,128,138,17
	.byte 129,118,0,82,0,20,0,72,28,18,12,32,4,8,10,20,2,10,12,30,72,138,3,133,1,28,0,128,138,131,143,129
	.byte 106,0,82,0,17,0,72,28,18,12,32,6,8,2,14,12,22,72,138,3,125,28,0,128,138,17,129,118,0,82,0,20
	.byte 0,72,28,18,12,32,4,8,10,20,2,10,12,30,72,138,3,133,1,28,0,128,138,46,128,137,0,65,0,14,0,62
	.byte 28,18,12,32,16,16,12,16,61,18,38,76,0,128,138,0,72,0,5,0,4,0,56,12,78,0,128,138,131,172,129,81
	.byte 0,57,0,24,0,152,1,28,18,12,76,2,6,4,12,4,64,12,24,28,178,1,8,6,10,18,101,44,0,128,138,0
	.byte 72,0,5,0,4,0,56,12,78,0,128,138,0,72,0,5,0,4,0,56,12,78,0,128,138,0,82,0,5,0,4,0
	.byte 66,14,88,0,128,138,0,82,0,5,0,4,0,66,14,88,0,128,138,131,207,129,161,0,128,151,0,43,0,98,28,18
	.byte 28,18,20,24,12,24,10,20,22,24,18,104,2,6,4,6,4,6,4,60,8,42,12,24,12,28,8,6,14,18,171,1
	.byte 54,30,76,44,36,101,36,0,128,138,0,72,0,5,0,4,0,56,12,78,0,128,138,0,72,0,5,0,4,0,56,12
	.byte 78,0,5,0,19,0,1,0,1,13,5,1,28,7,153,66,5,0,19,1,1,0,1,13,5,1,28,7,153,80,2,7
	.byte 153,74,7,153,88,4,1,13,153,94,128,139,128,214,13,0,5,2,1,7,8,0,4,0,8,0,13,255,253,0,0,0
	.byte 7,153,101,0,85,1,153,94,0,0,2,12,16,0,128,139,0,67,0,5,2,1,7,8,0,4,0,8,0,13,255,253
	.byte 0,0,0,7,153,101,0,86,1,153,94,0,0,4,0,66,24,58,0,128,139,0,86,0,5,2,1,7,8,0,4,0
	.byte 8,0,13,255,253,0,0,0,7,140,113,0,87,1,140,109,0,0,10,12,66,14,24,12,28,10,38,10,6,0,128,175
	.byte 131,71,2,128,143,1,2,255,255,255,255,240,128,137,62,97,99,0,13,79,0,5,92,0,6,2,1,7,16,0,5,255
	.byte 255,255,255,216,16,0,13,255,253,0,0,0,7,140,113,0,88,1,140,109,0,0,12,0,72,14,16,10,16,10,20,4
	.byte 122,12,18,0,128,143,130,107,129,249,1,4,0,0,40,129,198,129,198,0,10,2,1,7,20,0,5,255,255,255,255,216
	.byte 20,0,13,255,253,0,0,0,7,140,113,0,89,1,140,109,0,0,58,0,80,14,16,36,66,4,12,10,10,14,22,24
	.byte 82,14,22,4,18,4,10,14,22,24,96,10,60,16,22,4,10,24,86,14,66,14,22,4,18,4,10,16,22,22,56,4
	.byte 16,12,18,14,24,4,12,4,58,12,18,4,10,0,128,139,128,214,81,0,5,2,1,7,8,0,4,0,8,0,13,255
	.byte 253,0,0,0,7,140,113,0,90,1,140,109,0,0,8,0,56,14,22,16,26,22,48,0,128,139,128,214,20,0,5,2
	.byte 1,7,8,0,4,0,8,0,13,255,253,0,0,0,7,140,113,0,91,1,140,109,0,0,4,0,16,12,14,0,128,139
	.byte 128,214,51,0,5,2,1,7,8,0,4,0,8,0,13,255,253,0,0,0,7,140,113,0,92,1,140,109,0,0,2,0
	.byte 56,0,128,139,128,214,20,0,5,2,1,7,8,0,4,0,8,0,13,255,253,0,0,0,7,140,113,0,93,1,140,109
	.byte 0,0,4,0,16,22,14,0,128,139,69,128,254,0,9,2,1,7,13,0,4,8,13,0,13,255,253,0,0,0,7,140
	.byte 113,0,94,1,140,109,0,0,24,0,66,20,36,22,38,10,38,4,8,14,24,4,10,4,10,12,92,2,6,24,78,26
	.byte 78,0,128,139,128,214,42,0,5,2,1,7,8,0,4,0,8,0,13,255,253,0,0,0,7,140,113,0,95,1,140,109
	.byte 0,0,4,0,56,12,18,0,128,138,128,214,20,0,5,0,4,0,16,12,14,0,128,138,0,56,0,5,0,4,0,26
	.byte 14,76,0,128,138,128,214,20,0,5,0,4,0,16,12,14,0,128,138,0,29,0,5,0,4,0,26,14,22,0,128,138
	.byte 128,214,20,0,5,0,4,0,16,12,14,0,128,138,0,56,0,5,0,4,0,26,14,76,0,128,138,128,214,20,0,5
	.byte 0,4,0,16,12,14,0,128,138,0,56,0,5,0,4,0,26,14,76,0,128,138,128,214,20,0,5,0,4,0,16,12
	.byte 14,0,128,138,0,56,0,5,0,4,0,26,14,76,0,128,138,128,214,9,0,5,0,2,12,8,0,128,138,128,214,9
	.byte 0,5,0,2,12,8,0,128,138,0,61,0,5,0,4,0,66,26,36,0,128,138,128,214,59,0,5,0,6,0,48,10
	.byte 40,10,20,0,128,138,128,214,9,0,5,0,2,12,8,0,128,138,0,21,0,5,0,4,0,18,12,14,0,128,138,128
	.byte 214,9,0,5,0,2,12,8,0,128,138,69,99,0,9,0,8,0,72,12,30,22,48,12,30,0,128,138,128,214,59,0
	.byte 5,0,6,0,48,10,40,10,20,0,128,138,128,214,9,0,5,0,2,12,8,0,128,138,0,128,250,0,35,0,7,0
	.byte 58,10,34,36,210,2,0,128,138,128,214,59,0,5,0,6,0,48,10,40,10,20,0,128,138,128,214,9,0,5,0,2
	.byte 12,8,0,128,138,0,54,0,5,0,4,0,58,12,40,0,128,138,69,53,0,9,0,4,0,22,12,66,0,128,138,0
	.byte 64,0,5,0,6,0,58,12,40,6,20,0,0,128,144,16,0,0,1,4,128,160,24,0,0,8,19,193,0,26,194,193
	.byte 0,26,193,193,0,26,190,4,128,152,16,0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,0,128
	.byte 144,16,0,0,1,4,128,152,16,0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,144,16
	.byte 0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,144,16,0,0,1,193,0,26,197,193,0
	.byte 26,194,193,0,26,193,193,0,26,190,4,128,152,16,0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26
	.byte 190,4,128,144,16,0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,144,16,0,0,1,193
	.byte 0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,152,16,0,0,1,193,0,26,197,193,0,26,194,193,0
	.byte 26,193,193,0,26,190,4,128,144,16,0,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,255,255,255
	.byte 255,255,255,255,255,255,255,4,128,160,56,0,0,8,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128
	.byte 160,24,0,0,8,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,196,109,16,16,0,1,193,0,26
	.byte 197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,160,24,0,0,8,193,0,26,197,193,0,26,194,193,0,26,193
	.byte 193,0,26,190,4,128,196,114,16,16,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,4,128,196,117
	.byte 16,32,0,1,193,0,26,197,193,0,26,194,193,0,26,193,193,0,26,190,115,103,101,110,0
.section ".rodata"
.subsection 1
runtime_version:
	.string ""
.section ".rodata"
.subsection 1
assembly_guid:
	.string "F2D14575-D2AA-4A52-9CCD-0F3F93A51696"
.section ".rodata"
.subsection 1
assembly_name:
	.string "Mono.Cecil.Rocks"
.data 0
	.balign 8
mono_aot_file_info:
	.globl mono_aot_file_info
	.type mono_aot_file_info,@object

	.long 171,0
	.balign 8
	.quad mono_aot_Mono_Cecil_Rocks_got
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad jit_code_start
	.balign 8
	.quad jit_code_end
	.balign 8
	.quad method_addresses
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad blob
	.balign 8
	.quad class_name_table
	.balign 8
	.quad class_info_offsets
	.balign 8
	.quad method_info_offsets
	.balign 8
	.quad ex_info_offsets
	.balign 8
	.quad extra_method_info_offsets
	.balign 8
	.quad extra_method_table
	.balign 8
	.quad got_info_offsets
	.balign 8
	.quad 0
	.balign 8
	.quad image_table
	.balign 8
	.quad weak_field_indexes
	.balign 8
	.quad mem_end
	.balign 8
	.quad assembly_guid
	.balign 8
	.quad runtime_version
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad 0
	.balign 8
	.quad assembly_name
	.balign 8
	.quad plt
	.balign 8
	.quad plt_end
	.balign 8
	.quad unwind_info
	.balign 8
	.quad unbox_trampolines
	.balign 8
	.quad unbox_trampolines_end
	.balign 8
	.quad unbox_trampoline_addresses

	.long 243,3272,166,122,0,32,374434303,63
	.long 7796,128,8,8,8,9,8388607,0
	.long 5,25,0,0,0,0,0,0
	.long 0,0,0,0,0,0,0,0
	.long 0,0,0,0,0,0,0,0
	.long 0,0,0,0,0,0,0,0
	.long 0,0,0,0,0,0,0,0
	.byte 58,179,139,255,98,149,92,141,218,50,226,24,135,162,109,105
.section ".debug_info"
.subsection 0
.LTDIE_1:

	.byte 17
	.string "System_Object"

	.byte 16,7
	.string "System_Object"

.LDIFF_SYM3=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM3
.LTDIE_1_POINTER:

	.byte 13
.LDIFF_SYM4=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM4
.LTDIE_1_REFERENCE:

	.byte 14
.LDIFF_SYM5=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM5
.LTDIE_4:

	.byte 5
	.string "System_ValueType"

	.byte 16,16
.LDIFF_SYM6=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM6
	.byte 2,35,0,0,7
	.string "System_ValueType"

.LDIFF_SYM7=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM7
.LTDIE_4_POINTER:

	.byte 13
.LDIFF_SYM8=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM8
.LTDIE_4_REFERENCE:

	.byte 14
.LDIFF_SYM9=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM9
.LTDIE_3:

	.byte 5
	.string "System_Int32"

	.byte 20,16
.LDIFF_SYM10=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM10
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM11=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM11
	.byte 2,35,16,0,7
	.string "System_Int32"

.LDIFF_SYM12=.LTDIE_3 - .Ldebug_info_start
	.long .LDIFF_SYM12
.LTDIE_3_POINTER:

	.byte 13
.LDIFF_SYM13=.LTDIE_3 - .Ldebug_info_start
	.long .LDIFF_SYM13
.LTDIE_3_REFERENCE:

	.byte 14
.LDIFF_SYM14=.LTDIE_3 - .Ldebug_info_start
	.long .LDIFF_SYM14
.LTDIE_2:

	.byte 5
	.string "System_Text_StringBuilder"

	.byte 48,16
.LDIFF_SYM15=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM15
	.byte 2,35,0,6
	.string "m_ChunkChars"

.LDIFF_SYM16=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM16
	.byte 2,35,16,6
	.string "m_ChunkPrevious"

.LDIFF_SYM17=.LTDIE_2_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM17
	.byte 2,35,24,6
	.string "m_ChunkLength"

.LDIFF_SYM18=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM18
	.byte 2,35,32,6
	.string "m_ChunkOffset"

.LDIFF_SYM19=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM19
	.byte 2,35,36,6
	.string "m_MaxCapacity"

.LDIFF_SYM20=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM20
	.byte 2,35,40,0,7
	.string "System_Text_StringBuilder"

.LDIFF_SYM21=.LTDIE_2 - .Ldebug_info_start
	.long .LDIFF_SYM21
.LTDIE_2_POINTER:

	.byte 13
.LDIFF_SYM22=.LTDIE_2 - .Ldebug_info_start
	.long .LDIFF_SYM22
.LTDIE_2_REFERENCE:

	.byte 14
.LDIFF_SYM23=.LTDIE_2 - .Ldebug_info_start
	.long .LDIFF_SYM23
.LTDIE_0:

	.byte 5
	.string "Mono_Cecil_Rocks_DocCommentId"

	.byte 24,16
.LDIFF_SYM24=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM24
	.byte 2,35,0,6
	.string "id"

.LDIFF_SYM25=.LTDIE_2_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM25
	.byte 2,35,16,0,7
	.string "Mono_Cecil_Rocks_DocCommentId"

.LDIFF_SYM26=.LTDIE_0 - .Ldebug_info_start
	.long .LDIFF_SYM26
.LTDIE_0_POINTER:

	.byte 13
.LDIFF_SYM27=.LTDIE_0 - .Ldebug_info_start
	.long .LDIFF_SYM27
.LTDIE_0_REFERENCE:

	.byte 14
.LDIFF_SYM28=.LTDIE_0 - .Ldebug_info_start
	.long .LDIFF_SYM28
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:.ctor"
	.string "Mono_Cecil_Rocks_DocCommentId__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:.ctor"
	.quad .Lm_0
	.quad .Lme_0

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM29=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM29
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM30=.Lfde0_end - .Lfde0_start
	.long .LDIFF_SYM30
.Lfde0_start:

	.long 0
	.balign 8
	.quad .Lm_0

.LDIFF_SYM31=.Lme_0 - .Lm_0
	.long .LDIFF_SYM31
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde0_end:

.section ".debug_info"
.subsection 0
.LTDIE_9:

	.byte 5
	.string "System_Boolean"

	.byte 17,16
.LDIFF_SYM32=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM32
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM33=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM33
	.byte 2,35,16,0,7
	.string "System_Boolean"

.LDIFF_SYM34=.LTDIE_9 - .Ldebug_info_start
	.long .LDIFF_SYM34
.LTDIE_9_POINTER:

	.byte 13
.LDIFF_SYM35=.LTDIE_9 - .Ldebug_info_start
	.long .LDIFF_SYM35
.LTDIE_9_REFERENCE:

	.byte 14
.LDIFF_SYM36=.LTDIE_9 - .Ldebug_info_start
	.long .LDIFF_SYM36
.LTDIE_10:

	.byte 17
	.string "Mono_Cecil_IMetadataScope"

	.byte 16,7
	.string "Mono_Cecil_IMetadataScope"

.LDIFF_SYM37=.LTDIE_10 - .Ldebug_info_start
	.long .LDIFF_SYM37
.LTDIE_10_POINTER:

	.byte 13
.LDIFF_SYM38=.LTDIE_10 - .Ldebug_info_start
	.long .LDIFF_SYM38
.LTDIE_10_REFERENCE:

	.byte 14
.LDIFF_SYM39=.LTDIE_10 - .Ldebug_info_start
	.long .LDIFF_SYM39
.LTDIE_12:

	.byte 5
	.string "Mono_Cecil_ModuleReference"

	.byte 32,16
.LDIFF_SYM40=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM40
	.byte 2,35,0,6
	.string "name"

.LDIFF_SYM41=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM41
	.byte 2,35,16,6
	.string "token"

.LDIFF_SYM42=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM42
	.byte 2,35,24,0,7
	.string "Mono_Cecil_ModuleReference"

.LDIFF_SYM43=.LTDIE_12 - .Ldebug_info_start
	.long .LDIFF_SYM43
.LTDIE_12_POINTER:

	.byte 13
.LDIFF_SYM44=.LTDIE_12 - .Ldebug_info_start
	.long .LDIFF_SYM44
.LTDIE_12_REFERENCE:

	.byte 14
.LDIFF_SYM45=.LTDIE_12 - .Ldebug_info_start
	.long .LDIFF_SYM45
.LTDIE_14:

	.byte 8
	.string "Mono_Cecil_ModuleKind"

	.byte 4
.LDIFF_SYM46=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM46
	.byte 9
	.string "Dll"

	.byte 0,9
	.string "Console"

	.byte 1,9
	.string "Windows"

	.byte 2,9
	.string "NetModule"

	.byte 3,0,7
	.string "Mono_Cecil_ModuleKind"

.LDIFF_SYM47=.LTDIE_14 - .Ldebug_info_start
	.long .LDIFF_SYM47
.LTDIE_14_POINTER:

	.byte 13
.LDIFF_SYM48=.LTDIE_14 - .Ldebug_info_start
	.long .LDIFF_SYM48
.LTDIE_14_REFERENCE:

	.byte 14
.LDIFF_SYM49=.LTDIE_14 - .Ldebug_info_start
	.long .LDIFF_SYM49
.LTDIE_15:

	.byte 8
	.string "Mono_Cecil_TargetArchitecture"

	.byte 4
.LDIFF_SYM50=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM50
	.byte 9
	.string "I386"

	.byte 204,2,9
	.string "AMD64"

	.byte 228,140,2,9
	.string "IA64"

	.byte 128,4,9
	.string "ARM"

	.byte 192,3,9
	.string "ARMv7"

	.byte 196,3,9
	.string "ARM64"

	.byte 228,212,2,0,7
	.string "Mono_Cecil_TargetArchitecture"

.LDIFF_SYM51=.LTDIE_15 - .Ldebug_info_start
	.long .LDIFF_SYM51
.LTDIE_15_POINTER:

	.byte 13
.LDIFF_SYM52=.LTDIE_15 - .Ldebug_info_start
	.long .LDIFF_SYM52
.LTDIE_15_REFERENCE:

	.byte 14
.LDIFF_SYM53=.LTDIE_15 - .Ldebug_info_start
	.long .LDIFF_SYM53
.LTDIE_16:

	.byte 8
	.string "Mono_Cecil_ModuleCharacteristics"

	.byte 4
.LDIFF_SYM54=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM54
	.byte 9
	.string "HighEntropyVA"

	.byte 32,9
	.string "DynamicBase"

	.byte 192,0,9
	.string "NoSEH"

	.byte 128,8,9
	.string "NXCompat"

	.byte 128,2,9
	.string "AppContainer"

	.byte 128,32,9
	.string "TerminalServerAware"

	.byte 128,128,2,0,7
	.string "Mono_Cecil_ModuleCharacteristics"

.LDIFF_SYM55=.LTDIE_16 - .Ldebug_info_start
	.long .LDIFF_SYM55
.LTDIE_16_POINTER:

	.byte 13
.LDIFF_SYM56=.LTDIE_16 - .Ldebug_info_start
	.long .LDIFF_SYM56
.LTDIE_16_REFERENCE:

	.byte 14
.LDIFF_SYM57=.LTDIE_16 - .Ldebug_info_start
	.long .LDIFF_SYM57
.LTDIE_17:

	.byte 5
	.string "System_UInt16"

	.byte 18,16
.LDIFF_SYM58=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM58
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM59=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM59
	.byte 2,35,16,0,7
	.string "System_UInt16"

.LDIFF_SYM60=.LTDIE_17 - .Ldebug_info_start
	.long .LDIFF_SYM60
.LTDIE_17_POINTER:

	.byte 13
.LDIFF_SYM61=.LTDIE_17 - .Ldebug_info_start
	.long .LDIFF_SYM61
.LTDIE_17_REFERENCE:

	.byte 14
.LDIFF_SYM62=.LTDIE_17 - .Ldebug_info_start
	.long .LDIFF_SYM62
.LTDIE_18:

	.byte 5
	.string "Mono_Cecil_Cil_ImageDebugHeader"

	.byte 24,16
.LDIFF_SYM63=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM63
	.byte 2,35,0,6
	.string "entries"

.LDIFF_SYM64=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM64
	.byte 2,35,16,0,7
	.string "Mono_Cecil_Cil_ImageDebugHeader"

.LDIFF_SYM65=.LTDIE_18 - .Ldebug_info_start
	.long .LDIFF_SYM65
.LTDIE_18_POINTER:

	.byte 13
.LDIFF_SYM66=.LTDIE_18 - .Ldebug_info_start
	.long .LDIFF_SYM66
.LTDIE_18_REFERENCE:

	.byte 14
.LDIFF_SYM67=.LTDIE_18 - .Ldebug_info_start
	.long .LDIFF_SYM67
.LTDIE_20:

	.byte 5
	.string "System_UInt32"

	.byte 20,16
.LDIFF_SYM68=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM68
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM69=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM69
	.byte 2,35,16,0,7
	.string "System_UInt32"

.LDIFF_SYM70=.LTDIE_20 - .Ldebug_info_start
	.long .LDIFF_SYM70
.LTDIE_20_POINTER:

	.byte 13
.LDIFF_SYM71=.LTDIE_20 - .Ldebug_info_start
	.long .LDIFF_SYM71
.LTDIE_20_REFERENCE:

	.byte 14
.LDIFF_SYM72=.LTDIE_20 - .Ldebug_info_start
	.long .LDIFF_SYM72
.LTDIE_19:

	.byte 5
	.string "Mono_Cecil_PE_Section"

	.byte 40,16
.LDIFF_SYM73=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM73
	.byte 2,35,0,6
	.string "Name"

.LDIFF_SYM74=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM74
	.byte 2,35,16,6
	.string "VirtualAddress"

.LDIFF_SYM75=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM75
	.byte 2,35,24,6
	.string "VirtualSize"

.LDIFF_SYM76=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM76
	.byte 2,35,28,6
	.string "SizeOfRawData"

.LDIFF_SYM77=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM77
	.byte 2,35,32,6
	.string "PointerToRawData"

.LDIFF_SYM78=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM78
	.byte 2,35,36,0,7
	.string "Mono_Cecil_PE_Section"

.LDIFF_SYM79=.LTDIE_19 - .Ldebug_info_start
	.long .LDIFF_SYM79
.LTDIE_19_POINTER:

	.byte 13
.LDIFF_SYM80=.LTDIE_19 - .Ldebug_info_start
	.long .LDIFF_SYM80
.LTDIE_19_REFERENCE:

	.byte 14
.LDIFF_SYM81=.LTDIE_19 - .Ldebug_info_start
	.long .LDIFF_SYM81
.LTDIE_21:

	.byte 8
	.string "Mono_Cecil_ModuleAttributes"

	.byte 4
.LDIFF_SYM82=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM82
	.byte 9
	.string "ILOnly"

	.byte 1,9
	.string "Required32Bit"

	.byte 2,9
	.string "ILLibrary"

	.byte 4,9
	.string "StrongNameSigned"

	.byte 8,9
	.string "Preferred32Bit"

	.byte 128,128,8,0,7
	.string "Mono_Cecil_ModuleAttributes"

.LDIFF_SYM83=.LTDIE_21 - .Ldebug_info_start
	.long .LDIFF_SYM83
.LTDIE_21_POINTER:

	.byte 13
.LDIFF_SYM84=.LTDIE_21 - .Ldebug_info_start
	.long .LDIFF_SYM84
.LTDIE_21_REFERENCE:

	.byte 14
.LDIFF_SYM85=.LTDIE_21 - .Ldebug_info_start
	.long .LDIFF_SYM85
.LTDIE_23:

	.byte 5
	.string "Mono_Cecil_Metadata_Heap"

	.byte 32,16
.LDIFF_SYM86=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM86
	.byte 2,35,0,6
	.string "IndexSize"

.LDIFF_SYM87=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM87
	.byte 2,35,24,6
	.string "data"

.LDIFF_SYM88=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM88
	.byte 2,35,16,0,7
	.string "Mono_Cecil_Metadata_Heap"

.LDIFF_SYM89=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM89
.LTDIE_23_POINTER:

	.byte 13
.LDIFF_SYM90=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM90
.LTDIE_23_REFERENCE:

	.byte 14
.LDIFF_SYM91=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM91
.LTDIE_25:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM92=.LTDIE_25 - .Ldebug_info_start
	.long .LDIFF_SYM92
.LTDIE_25_POINTER:

	.byte 13
.LDIFF_SYM93=.LTDIE_25 - .Ldebug_info_start
	.long .LDIFF_SYM93
.LTDIE_25_REFERENCE:

	.byte 14
.LDIFF_SYM94=.LTDIE_25 - .Ldebug_info_start
	.long .LDIFF_SYM94
.LTDIE_26:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM95=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM95
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM96=.LTDIE_24_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM96
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM97=.LTDIE_26 - .Ldebug_info_start
	.long .LDIFF_SYM97
.LTDIE_26_POINTER:

	.byte 13
.LDIFF_SYM98=.LTDIE_26 - .Ldebug_info_start
	.long .LDIFF_SYM98
.LTDIE_26_REFERENCE:

	.byte 14
.LDIFF_SYM99=.LTDIE_26 - .Ldebug_info_start
	.long .LDIFF_SYM99
.LTDIE_27:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM100=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM100
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM101=.LTDIE_24_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM101
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM102=.LTDIE_27 - .Ldebug_info_start
	.long .LDIFF_SYM102
.LTDIE_27_POINTER:

	.byte 13
.LDIFF_SYM103=.LTDIE_27 - .Ldebug_info_start
	.long .LDIFF_SYM103
.LTDIE_27_REFERENCE:

	.byte 14
.LDIFF_SYM104=.LTDIE_27 - .Ldebug_info_start
	.long .LDIFF_SYM104
.LTDIE_24:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM105=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM105
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM106=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM106
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM107=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM107
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM108=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM108
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM109=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM109
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM110=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM110
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM111=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM111
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM112=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM112
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM113=.LTDIE_26_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM113
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM114=.LTDIE_27_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM114
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM115=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM115
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM116=.LTDIE_24 - .Ldebug_info_start
	.long .LDIFF_SYM116
.LTDIE_24_POINTER:

	.byte 13
.LDIFF_SYM117=.LTDIE_24 - .Ldebug_info_start
	.long .LDIFF_SYM117
.LTDIE_24_REFERENCE:

	.byte 14
.LDIFF_SYM118=.LTDIE_24 - .Ldebug_info_start
	.long .LDIFF_SYM118
.LTDIE_22:

	.byte 5
	.string "Mono_Cecil_Metadata_StringHeap"

	.byte 40,16
.LDIFF_SYM119=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM119
	.byte 2,35,0,6
	.string "strings"

.LDIFF_SYM120=.LTDIE_24_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM120
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Metadata_StringHeap"

.LDIFF_SYM121=.LTDIE_22 - .Ldebug_info_start
	.long .LDIFF_SYM121
.LTDIE_22_POINTER:

	.byte 13
.LDIFF_SYM122=.LTDIE_22 - .Ldebug_info_start
	.long .LDIFF_SYM122
.LTDIE_22_REFERENCE:

	.byte 14
.LDIFF_SYM123=.LTDIE_22 - .Ldebug_info_start
	.long .LDIFF_SYM123
.LTDIE_28:

	.byte 5
	.string "Mono_Cecil_Metadata_BlobHeap"

	.byte 32,16
.LDIFF_SYM124=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM124
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_BlobHeap"

.LDIFF_SYM125=.LTDIE_28 - .Ldebug_info_start
	.long .LDIFF_SYM125
.LTDIE_28_POINTER:

	.byte 13
.LDIFF_SYM126=.LTDIE_28 - .Ldebug_info_start
	.long .LDIFF_SYM126
.LTDIE_28_REFERENCE:

	.byte 14
.LDIFF_SYM127=.LTDIE_28 - .Ldebug_info_start
	.long .LDIFF_SYM127
.LTDIE_29:

	.byte 5
	.string "Mono_Cecil_Metadata_UserStringHeap"

	.byte 40,16
.LDIFF_SYM128=.LTDIE_22 - .Ldebug_info_start
	.long .LDIFF_SYM128
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_UserStringHeap"

.LDIFF_SYM129=.LTDIE_29 - .Ldebug_info_start
	.long .LDIFF_SYM129
.LTDIE_29_POINTER:

	.byte 13
.LDIFF_SYM130=.LTDIE_29 - .Ldebug_info_start
	.long .LDIFF_SYM130
.LTDIE_29_REFERENCE:

	.byte 14
.LDIFF_SYM131=.LTDIE_29 - .Ldebug_info_start
	.long .LDIFF_SYM131
.LTDIE_30:

	.byte 5
	.string "Mono_Cecil_Metadata_GuidHeap"

	.byte 32,16
.LDIFF_SYM132=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM132
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_GuidHeap"

.LDIFF_SYM133=.LTDIE_30 - .Ldebug_info_start
	.long .LDIFF_SYM133
.LTDIE_30_POINTER:

	.byte 13
.LDIFF_SYM134=.LTDIE_30 - .Ldebug_info_start
	.long .LDIFF_SYM134
.LTDIE_30_REFERENCE:

	.byte 14
.LDIFF_SYM135=.LTDIE_30 - .Ldebug_info_start
	.long .LDIFF_SYM135
.LTDIE_32:

	.byte 5
	.string "System_Int64"

	.byte 24,16
.LDIFF_SYM136=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM136
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM137=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM137
	.byte 2,35,16,0,7
	.string "System_Int64"

.LDIFF_SYM138=.LTDIE_32 - .Ldebug_info_start
	.long .LDIFF_SYM138
.LTDIE_32_POINTER:

	.byte 13
.LDIFF_SYM139=.LTDIE_32 - .Ldebug_info_start
	.long .LDIFF_SYM139
.LTDIE_32_REFERENCE:

	.byte 14
.LDIFF_SYM140=.LTDIE_32 - .Ldebug_info_start
	.long .LDIFF_SYM140
.LTDIE_31:

	.byte 5
	.string "Mono_Cecil_Metadata_TableHeap"

	.byte 56,16
.LDIFF_SYM141=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM141
	.byte 2,35,0,6
	.string "Valid"

.LDIFF_SYM142=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM142
	.byte 2,35,40,6
	.string "Sorted"

.LDIFF_SYM143=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM143
	.byte 2,35,48,6
	.string "Tables"

.LDIFF_SYM144=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM144
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Metadata_TableHeap"

.LDIFF_SYM145=.LTDIE_31 - .Ldebug_info_start
	.long .LDIFF_SYM145
.LTDIE_31_POINTER:

	.byte 13
.LDIFF_SYM146=.LTDIE_31 - .Ldebug_info_start
	.long .LDIFF_SYM146
.LTDIE_31_REFERENCE:

	.byte 14
.LDIFF_SYM147=.LTDIE_31 - .Ldebug_info_start
	.long .LDIFF_SYM147
.LTDIE_33:

	.byte 5
	.string "Mono_Cecil_Metadata_PdbHeap"

	.byte 64,16
.LDIFF_SYM148=.LTDIE_23 - .Ldebug_info_start
	.long .LDIFF_SYM148
	.byte 2,35,0,6
	.string "Id"

.LDIFF_SYM149=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM149
	.byte 2,35,32,6
	.string "EntryPoint"

.LDIFF_SYM150=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM150
	.byte 2,35,48,6
	.string "TypeSystemTables"

.LDIFF_SYM151=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM151
	.byte 2,35,56,6
	.string "TypeSystemTableRows"

.LDIFF_SYM152=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM152
	.byte 2,35,40,0,7
	.string "Mono_Cecil_Metadata_PdbHeap"

.LDIFF_SYM153=.LTDIE_33 - .Ldebug_info_start
	.long .LDIFF_SYM153
.LTDIE_33_POINTER:

	.byte 13
.LDIFF_SYM154=.LTDIE_33 - .Ldebug_info_start
	.long .LDIFF_SYM154
.LTDIE_33_REFERENCE:

	.byte 14
.LDIFF_SYM155=.LTDIE_33 - .Ldebug_info_start
	.long .LDIFF_SYM155
.LTDIE_39:

	.byte 5
	.string "System_Reflection_MemberInfo"

	.byte 16,16
.LDIFF_SYM156=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM156
	.byte 2,35,0,0,7
	.string "System_Reflection_MemberInfo"

.LDIFF_SYM157=.LTDIE_39 - .Ldebug_info_start
	.long .LDIFF_SYM157
.LTDIE_39_POINTER:

	.byte 13
.LDIFF_SYM158=.LTDIE_39 - .Ldebug_info_start
	.long .LDIFF_SYM158
.LTDIE_39_REFERENCE:

	.byte 14
.LDIFF_SYM159=.LTDIE_39 - .Ldebug_info_start
	.long .LDIFF_SYM159
.LTDIE_38:

	.byte 5
	.string "System_Reflection_MethodBase"

	.byte 16,16
.LDIFF_SYM160=.LTDIE_39 - .Ldebug_info_start
	.long .LDIFF_SYM160
	.byte 2,35,0,0,7
	.string "System_Reflection_MethodBase"

.LDIFF_SYM161=.LTDIE_38 - .Ldebug_info_start
	.long .LDIFF_SYM161
.LTDIE_38_POINTER:

	.byte 13
.LDIFF_SYM162=.LTDIE_38 - .Ldebug_info_start
	.long .LDIFF_SYM162
.LTDIE_38_REFERENCE:

	.byte 14
.LDIFF_SYM163=.LTDIE_38 - .Ldebug_info_start
	.long .LDIFF_SYM163
.LTDIE_37:

	.byte 5
	.string "System_Reflection_MethodInfo"

	.byte 16,16
.LDIFF_SYM164=.LTDIE_38 - .Ldebug_info_start
	.long .LDIFF_SYM164
	.byte 2,35,0,0,7
	.string "System_Reflection_MethodInfo"

.LDIFF_SYM165=.LTDIE_37 - .Ldebug_info_start
	.long .LDIFF_SYM165
.LTDIE_37_POINTER:

	.byte 13
.LDIFF_SYM166=.LTDIE_37 - .Ldebug_info_start
	.long .LDIFF_SYM166
.LTDIE_37_REFERENCE:

	.byte 14
.LDIFF_SYM167=.LTDIE_37 - .Ldebug_info_start
	.long .LDIFF_SYM167
.LTDIE_41:

	.byte 5
	.string "System_Type"

	.byte 24,16
.LDIFF_SYM168=.LTDIE_39 - .Ldebug_info_start
	.long .LDIFF_SYM168
	.byte 2,35,0,6
	.string "_impl"

.LDIFF_SYM169=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM169
	.byte 2,35,16,0,7
	.string "System_Type"

.LDIFF_SYM170=.LTDIE_41 - .Ldebug_info_start
	.long .LDIFF_SYM170
.LTDIE_41_POINTER:

	.byte 13
.LDIFF_SYM171=.LTDIE_41 - .Ldebug_info_start
	.long .LDIFF_SYM171
.LTDIE_41_REFERENCE:

	.byte 14
.LDIFF_SYM172=.LTDIE_41 - .Ldebug_info_start
	.long .LDIFF_SYM172
.LTDIE_40:

	.byte 5
	.string "System_DelegateData"

	.byte 40,16
.LDIFF_SYM173=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM173
	.byte 2,35,0,6
	.string "target_type"

.LDIFF_SYM174=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM174
	.byte 2,35,16,6
	.string "method_name"

.LDIFF_SYM175=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM175
	.byte 2,35,24,6
	.string "curried_first_arg"

.LDIFF_SYM176=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM176
	.byte 2,35,32,0,7
	.string "System_DelegateData"

.LDIFF_SYM177=.LTDIE_40 - .Ldebug_info_start
	.long .LDIFF_SYM177
.LTDIE_40_POINTER:

	.byte 13
.LDIFF_SYM178=.LTDIE_40 - .Ldebug_info_start
	.long .LDIFF_SYM178
.LTDIE_40_REFERENCE:

	.byte 14
.LDIFF_SYM179=.LTDIE_40 - .Ldebug_info_start
	.long .LDIFF_SYM179
.LTDIE_36:

	.byte 5
	.string "System_Delegate"

	.byte 120,16
.LDIFF_SYM180=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM180
	.byte 2,35,0,6
	.string "method_ptr"

.LDIFF_SYM181=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM181
	.byte 2,35,16,6
	.string "invoke_impl"

.LDIFF_SYM182=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM182
	.byte 2,35,24,6
	.string "m_target"

.LDIFF_SYM183=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM183
	.byte 2,35,32,6
	.string "method"

.LDIFF_SYM184=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM184
	.byte 2,35,40,6
	.string "delegate_trampoline"

.LDIFF_SYM185=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM185
	.byte 2,35,48,6
	.string "extra_arg"

.LDIFF_SYM186=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM186
	.byte 2,35,56,6
	.string "method_code"

.LDIFF_SYM187=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM187
	.byte 2,35,64,6
	.string "interp_method"

.LDIFF_SYM188=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM188
	.byte 2,35,72,6
	.string "interp_invoke_impl"

.LDIFF_SYM189=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM189
	.byte 2,35,80,6
	.string "method_info"

.LDIFF_SYM190=.LTDIE_37_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM190
	.byte 2,35,88,6
	.string "original_method_info"

.LDIFF_SYM191=.LTDIE_37_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM191
	.byte 2,35,96,6
	.string "data"

.LDIFF_SYM192=.LTDIE_40_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM192
	.byte 2,35,104,6
	.string "method_is_virtual"

.LDIFF_SYM193=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM193
	.byte 2,35,112,0,7
	.string "System_Delegate"

.LDIFF_SYM194=.LTDIE_36 - .Ldebug_info_start
	.long .LDIFF_SYM194
.LTDIE_36_POINTER:

	.byte 13
.LDIFF_SYM195=.LTDIE_36 - .Ldebug_info_start
	.long .LDIFF_SYM195
.LTDIE_36_REFERENCE:

	.byte 14
.LDIFF_SYM196=.LTDIE_36 - .Ldebug_info_start
	.long .LDIFF_SYM196
.LTDIE_35:

	.byte 5
	.string "System_MulticastDelegate"

	.byte 128,1,16
.LDIFF_SYM197=.LTDIE_36 - .Ldebug_info_start
	.long .LDIFF_SYM197
	.byte 2,35,0,6
	.string "delegates"

.LDIFF_SYM198=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM198
	.byte 2,35,120,0,7
	.string "System_MulticastDelegate"

.LDIFF_SYM199=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM199
.LTDIE_35_POINTER:

	.byte 13
.LDIFF_SYM200=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM200
.LTDIE_35_REFERENCE:

	.byte 14
.LDIFF_SYM201=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM201
.LTDIE_34:

	.byte 5
	.string "System_Func`2"

	.byte 128,1,16
.LDIFF_SYM202=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM202
	.byte 2,35,0,0,7
	.string "System_Func`2"

.LDIFF_SYM203=.LTDIE_34 - .Ldebug_info_start
	.long .LDIFF_SYM203
.LTDIE_34_POINTER:

	.byte 13
.LDIFF_SYM204=.LTDIE_34 - .Ldebug_info_start
	.long .LDIFF_SYM204
.LTDIE_34_REFERENCE:

	.byte 14
.LDIFF_SYM205=.LTDIE_34 - .Ldebug_info_start
	.long .LDIFF_SYM205
.LTDIE_13:

	.byte 5
	.string "Mono_Cecil_PE_Image"

	.byte 200,1,16
.LDIFF_SYM206=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM206
	.byte 2,35,0,6
	.string "Stream"

.LDIFF_SYM207=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM207
	.byte 2,35,16,6
	.string "FileName"

.LDIFF_SYM208=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM208
	.byte 2,35,32,6
	.string "Kind"

.LDIFF_SYM209=.LTDIE_14 - .Ldebug_info_start
	.long .LDIFF_SYM209
	.byte 3,35,136,1,6
	.string "RuntimeVersion"

.LDIFF_SYM210=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM210
	.byte 2,35,40,6
	.string "Architecture"

.LDIFF_SYM211=.LTDIE_15 - .Ldebug_info_start
	.long .LDIFF_SYM211
	.byte 3,35,140,1,6
	.string "Characteristics"

.LDIFF_SYM212=.LTDIE_16 - .Ldebug_info_start
	.long .LDIFF_SYM212
	.byte 3,35,144,1,6
	.string "LinkerVersion"

.LDIFF_SYM213=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM213
	.byte 3,35,148,1,6
	.string "SubSystemMajor"

.LDIFF_SYM214=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM214
	.byte 3,35,150,1,6
	.string "SubSystemMinor"

.LDIFF_SYM215=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM215
	.byte 3,35,152,1,6
	.string "DebugHeader"

.LDIFF_SYM216=.LTDIE_18_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM216
	.byte 2,35,48,6
	.string "Sections"

.LDIFF_SYM217=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM217
	.byte 2,35,56,6
	.string "MetadataSection"

.LDIFF_SYM218=.LTDIE_19_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM218
	.byte 2,35,64,6
	.string "EntryPointToken"

.LDIFF_SYM219=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM219
	.byte 3,35,156,1,6
	.string "Timestamp"

.LDIFF_SYM220=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM220
	.byte 3,35,160,1,6
	.string "Attributes"

.LDIFF_SYM221=.LTDIE_21 - .Ldebug_info_start
	.long .LDIFF_SYM221
	.byte 3,35,164,1,6
	.string "Win32Resources"

.LDIFF_SYM222=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM222
	.byte 3,35,168,1,6
	.string "Debug"

.LDIFF_SYM223=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM223
	.byte 3,35,176,1,6
	.string "Resources"

.LDIFF_SYM224=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM224
	.byte 3,35,184,1,6
	.string "StrongName"

.LDIFF_SYM225=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM225
	.byte 3,35,192,1,6
	.string "StringHeap"

.LDIFF_SYM226=.LTDIE_22_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM226
	.byte 2,35,72,6
	.string "BlobHeap"

.LDIFF_SYM227=.LTDIE_28_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM227
	.byte 2,35,80,6
	.string "UserStringHeap"

.LDIFF_SYM228=.LTDIE_29_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM228
	.byte 2,35,88,6
	.string "GuidHeap"

.LDIFF_SYM229=.LTDIE_30_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM229
	.byte 2,35,96,6
	.string "TableHeap"

.LDIFF_SYM230=.LTDIE_31_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM230
	.byte 2,35,104,6
	.string "PdbHeap"

.LDIFF_SYM231=.LTDIE_33_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM231
	.byte 2,35,112,6
	.string "coded_index_sizes"

.LDIFF_SYM232=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM232
	.byte 2,35,120,6
	.string "counter"

.LDIFF_SYM233=.LTDIE_34_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM233
	.byte 3,35,128,1,0,7
	.string "Mono_Cecil_PE_Image"

.LDIFF_SYM234=.LTDIE_13 - .Ldebug_info_start
	.long .LDIFF_SYM234
.LTDIE_13_POINTER:

	.byte 13
.LDIFF_SYM235=.LTDIE_13 - .Ldebug_info_start
	.long .LDIFF_SYM235
.LTDIE_13_REFERENCE:

	.byte 14
.LDIFF_SYM236=.LTDIE_13 - .Ldebug_info_start
	.long .LDIFF_SYM236
.LTDIE_44:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM237=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM237
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM238=.LTDIE_43_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM238
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM239=.LTDIE_44 - .Ldebug_info_start
	.long .LDIFF_SYM239
.LTDIE_44_POINTER:

	.byte 13
.LDIFF_SYM240=.LTDIE_44 - .Ldebug_info_start
	.long .LDIFF_SYM240
.LTDIE_44_REFERENCE:

	.byte 14
.LDIFF_SYM241=.LTDIE_44 - .Ldebug_info_start
	.long .LDIFF_SYM241
.LTDIE_45:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM242=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM242
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM243=.LTDIE_43_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM243
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM244=.LTDIE_45 - .Ldebug_info_start
	.long .LDIFF_SYM244
.LTDIE_45_POINTER:

	.byte 13
.LDIFF_SYM245=.LTDIE_45 - .Ldebug_info_start
	.long .LDIFF_SYM245
.LTDIE_45_REFERENCE:

	.byte 14
.LDIFF_SYM246=.LTDIE_45 - .Ldebug_info_start
	.long .LDIFF_SYM246
.LTDIE_43:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM247=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM247
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM248=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM248
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM249=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM249
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM250=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM250
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM251=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM251
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM252=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM252
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM253=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM253
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM254=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM254
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM255=.LTDIE_44_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM255
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM256=.LTDIE_45_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM256
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM257=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM257
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM258=.LTDIE_43 - .Ldebug_info_start
	.long .LDIFF_SYM258
.LTDIE_43_POINTER:

	.byte 13
.LDIFF_SYM259=.LTDIE_43 - .Ldebug_info_start
	.long .LDIFF_SYM259
.LTDIE_43_REFERENCE:

	.byte 14
.LDIFF_SYM260=.LTDIE_43 - .Ldebug_info_start
	.long .LDIFF_SYM260
.LTDIE_47:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM261=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM261
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM262=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM262
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM263=.LTDIE_47 - .Ldebug_info_start
	.long .LDIFF_SYM263
.LTDIE_47_POINTER:

	.byte 13
.LDIFF_SYM264=.LTDIE_47 - .Ldebug_info_start
	.long .LDIFF_SYM264
.LTDIE_47_REFERENCE:

	.byte 14
.LDIFF_SYM265=.LTDIE_47 - .Ldebug_info_start
	.long .LDIFF_SYM265
.LTDIE_48:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM266=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM266
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM267=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM267
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM268=.LTDIE_48 - .Ldebug_info_start
	.long .LDIFF_SYM268
.LTDIE_48_POINTER:

	.byte 13
.LDIFF_SYM269=.LTDIE_48 - .Ldebug_info_start
	.long .LDIFF_SYM269
.LTDIE_48_REFERENCE:

	.byte 14
.LDIFF_SYM270=.LTDIE_48 - .Ldebug_info_start
	.long .LDIFF_SYM270
.LTDIE_46:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM271=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM271
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM272=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM272
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM273=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM273
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM274=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM274
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM275=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM275
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM276=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM276
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM277=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM277
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM278=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM278
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM279=.LTDIE_47_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM279
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM280=.LTDIE_48_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM280
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM281=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM281
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM282=.LTDIE_46 - .Ldebug_info_start
	.long .LDIFF_SYM282
.LTDIE_46_POINTER:

	.byte 13
.LDIFF_SYM283=.LTDIE_46 - .Ldebug_info_start
	.long .LDIFF_SYM283
.LTDIE_46_REFERENCE:

	.byte 14
.LDIFF_SYM284=.LTDIE_46 - .Ldebug_info_start
	.long .LDIFF_SYM284
.LTDIE_50:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM285=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM285
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM286=.LTDIE_49_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM286
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM287=.LTDIE_50 - .Ldebug_info_start
	.long .LDIFF_SYM287
.LTDIE_50_POINTER:

	.byte 13
.LDIFF_SYM288=.LTDIE_50 - .Ldebug_info_start
	.long .LDIFF_SYM288
.LTDIE_50_REFERENCE:

	.byte 14
.LDIFF_SYM289=.LTDIE_50 - .Ldebug_info_start
	.long .LDIFF_SYM289
.LTDIE_51:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM290=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM290
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM291=.LTDIE_49_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM291
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM292=.LTDIE_51 - .Ldebug_info_start
	.long .LDIFF_SYM292
.LTDIE_51_POINTER:

	.byte 13
.LDIFF_SYM293=.LTDIE_51 - .Ldebug_info_start
	.long .LDIFF_SYM293
.LTDIE_51_REFERENCE:

	.byte 14
.LDIFF_SYM294=.LTDIE_51 - .Ldebug_info_start
	.long .LDIFF_SYM294
.LTDIE_49:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM295=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM295
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM296=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM296
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM297=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM297
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM298=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM298
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM299=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM299
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM300=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM300
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM301=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM301
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM302=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM302
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM303=.LTDIE_50_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM303
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM304=.LTDIE_51_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM304
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM305=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM305
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM306=.LTDIE_49 - .Ldebug_info_start
	.long .LDIFF_SYM306
.LTDIE_49_POINTER:

	.byte 13
.LDIFF_SYM307=.LTDIE_49 - .Ldebug_info_start
	.long .LDIFF_SYM307
.LTDIE_49_REFERENCE:

	.byte 14
.LDIFF_SYM308=.LTDIE_49 - .Ldebug_info_start
	.long .LDIFF_SYM308
.LTDIE_53:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM309=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM309
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM310=.LTDIE_52_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM310
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM311=.LTDIE_53 - .Ldebug_info_start
	.long .LDIFF_SYM311
.LTDIE_53_POINTER:

	.byte 13
.LDIFF_SYM312=.LTDIE_53 - .Ldebug_info_start
	.long .LDIFF_SYM312
.LTDIE_53_REFERENCE:

	.byte 14
.LDIFF_SYM313=.LTDIE_53 - .Ldebug_info_start
	.long .LDIFF_SYM313
.LTDIE_54:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM314=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM314
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM315=.LTDIE_52_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM315
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM316=.LTDIE_54 - .Ldebug_info_start
	.long .LDIFF_SYM316
.LTDIE_54_POINTER:

	.byte 13
.LDIFF_SYM317=.LTDIE_54 - .Ldebug_info_start
	.long .LDIFF_SYM317
.LTDIE_54_REFERENCE:

	.byte 14
.LDIFF_SYM318=.LTDIE_54 - .Ldebug_info_start
	.long .LDIFF_SYM318
.LTDIE_52:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM319=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM319
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM320=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM320
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM321=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM321
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM322=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM322
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM323=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM323
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM324=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM324
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM325=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM325
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM326=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM326
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM327=.LTDIE_53_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM327
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM328=.LTDIE_54_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM328
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM329=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM329
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM330=.LTDIE_52 - .Ldebug_info_start
	.long .LDIFF_SYM330
.LTDIE_52_POINTER:

	.byte 13
.LDIFF_SYM331=.LTDIE_52 - .Ldebug_info_start
	.long .LDIFF_SYM331
.LTDIE_52_REFERENCE:

	.byte 14
.LDIFF_SYM332=.LTDIE_52 - .Ldebug_info_start
	.long .LDIFF_SYM332
.LTDIE_56:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM333=.LTDIE_56 - .Ldebug_info_start
	.long .LDIFF_SYM333
.LTDIE_56_POINTER:

	.byte 13
.LDIFF_SYM334=.LTDIE_56 - .Ldebug_info_start
	.long .LDIFF_SYM334
.LTDIE_56_REFERENCE:

	.byte 14
.LDIFF_SYM335=.LTDIE_56 - .Ldebug_info_start
	.long .LDIFF_SYM335
.LTDIE_57:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM336=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM336
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM337=.LTDIE_55_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM337
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM338=.LTDIE_57 - .Ldebug_info_start
	.long .LDIFF_SYM338
.LTDIE_57_POINTER:

	.byte 13
.LDIFF_SYM339=.LTDIE_57 - .Ldebug_info_start
	.long .LDIFF_SYM339
.LTDIE_57_REFERENCE:

	.byte 14
.LDIFF_SYM340=.LTDIE_57 - .Ldebug_info_start
	.long .LDIFF_SYM340
.LTDIE_58:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM341=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM341
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM342=.LTDIE_55_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM342
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM343=.LTDIE_58 - .Ldebug_info_start
	.long .LDIFF_SYM343
.LTDIE_58_POINTER:

	.byte 13
.LDIFF_SYM344=.LTDIE_58 - .Ldebug_info_start
	.long .LDIFF_SYM344
.LTDIE_58_REFERENCE:

	.byte 14
.LDIFF_SYM345=.LTDIE_58 - .Ldebug_info_start
	.long .LDIFF_SYM345
.LTDIE_55:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM346=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM346
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM347=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM347
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM348=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM348
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM349=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM349
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM350=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM350
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM351=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM351
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM352=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM352
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM353=.LTDIE_56_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM353
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM354=.LTDIE_57_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM354
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM355=.LTDIE_58_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM355
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM356=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM356
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM357=.LTDIE_55 - .Ldebug_info_start
	.long .LDIFF_SYM357
.LTDIE_55_POINTER:

	.byte 13
.LDIFF_SYM358=.LTDIE_55 - .Ldebug_info_start
	.long .LDIFF_SYM358
.LTDIE_55_REFERENCE:

	.byte 14
.LDIFF_SYM359=.LTDIE_55 - .Ldebug_info_start
	.long .LDIFF_SYM359
.LTDIE_60:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM360=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM360
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM361=.LTDIE_59_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM361
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM362=.LTDIE_60 - .Ldebug_info_start
	.long .LDIFF_SYM362
.LTDIE_60_POINTER:

	.byte 13
.LDIFF_SYM363=.LTDIE_60 - .Ldebug_info_start
	.long .LDIFF_SYM363
.LTDIE_60_REFERENCE:

	.byte 14
.LDIFF_SYM364=.LTDIE_60 - .Ldebug_info_start
	.long .LDIFF_SYM364
.LTDIE_61:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM365=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM365
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM366=.LTDIE_59_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM366
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM367=.LTDIE_61 - .Ldebug_info_start
	.long .LDIFF_SYM367
.LTDIE_61_POINTER:

	.byte 13
.LDIFF_SYM368=.LTDIE_61 - .Ldebug_info_start
	.long .LDIFF_SYM368
.LTDIE_61_REFERENCE:

	.byte 14
.LDIFF_SYM369=.LTDIE_61 - .Ldebug_info_start
	.long .LDIFF_SYM369
.LTDIE_59:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM370=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM370
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM371=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM371
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM372=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM372
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM373=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM373
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM374=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM374
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM375=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM375
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM376=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM376
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM377=.LTDIE_56_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM377
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM378=.LTDIE_60_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM378
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM379=.LTDIE_61_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM379
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM380=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM380
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM381=.LTDIE_59 - .Ldebug_info_start
	.long .LDIFF_SYM381
.LTDIE_59_POINTER:

	.byte 13
.LDIFF_SYM382=.LTDIE_59 - .Ldebug_info_start
	.long .LDIFF_SYM382
.LTDIE_59_REFERENCE:

	.byte 14
.LDIFF_SYM383=.LTDIE_59 - .Ldebug_info_start
	.long .LDIFF_SYM383
.LTDIE_63:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM384=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM384
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM385=.LTDIE_62_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM385
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM386=.LTDIE_63 - .Ldebug_info_start
	.long .LDIFF_SYM386
.LTDIE_63_POINTER:

	.byte 13
.LDIFF_SYM387=.LTDIE_63 - .Ldebug_info_start
	.long .LDIFF_SYM387
.LTDIE_63_REFERENCE:

	.byte 14
.LDIFF_SYM388=.LTDIE_63 - .Ldebug_info_start
	.long .LDIFF_SYM388
.LTDIE_64:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM389=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM389
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM390=.LTDIE_62_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM390
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM391=.LTDIE_64 - .Ldebug_info_start
	.long .LDIFF_SYM391
.LTDIE_64_POINTER:

	.byte 13
.LDIFF_SYM392=.LTDIE_64 - .Ldebug_info_start
	.long .LDIFF_SYM392
.LTDIE_64_REFERENCE:

	.byte 14
.LDIFF_SYM393=.LTDIE_64 - .Ldebug_info_start
	.long .LDIFF_SYM393
.LTDIE_62:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM394=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM394
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM395=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM395
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM396=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM396
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM397=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM397
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM398=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM398
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM399=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM399
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM400=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM400
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM401=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM401
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM402=.LTDIE_63_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM402
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM403=.LTDIE_64_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM403
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM404=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM404
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM405=.LTDIE_62 - .Ldebug_info_start
	.long .LDIFF_SYM405
.LTDIE_62_POINTER:

	.byte 13
.LDIFF_SYM406=.LTDIE_62 - .Ldebug_info_start
	.long .LDIFF_SYM406
.LTDIE_62_REFERENCE:

	.byte 14
.LDIFF_SYM407=.LTDIE_62 - .Ldebug_info_start
	.long .LDIFF_SYM407
.LTDIE_66:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM408=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM408
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM409=.LTDIE_65_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM409
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM410=.LTDIE_66 - .Ldebug_info_start
	.long .LDIFF_SYM410
.LTDIE_66_POINTER:

	.byte 13
.LDIFF_SYM411=.LTDIE_66 - .Ldebug_info_start
	.long .LDIFF_SYM411
.LTDIE_66_REFERENCE:

	.byte 14
.LDIFF_SYM412=.LTDIE_66 - .Ldebug_info_start
	.long .LDIFF_SYM412
.LTDIE_67:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM413=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM413
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM414=.LTDIE_65_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM414
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM415=.LTDIE_67 - .Ldebug_info_start
	.long .LDIFF_SYM415
.LTDIE_67_POINTER:

	.byte 13
.LDIFF_SYM416=.LTDIE_67 - .Ldebug_info_start
	.long .LDIFF_SYM416
.LTDIE_67_REFERENCE:

	.byte 14
.LDIFF_SYM417=.LTDIE_67 - .Ldebug_info_start
	.long .LDIFF_SYM417
.LTDIE_65:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM418=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM418
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM419=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM419
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM420=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM420
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM421=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM421
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM422=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM422
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM423=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM423
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM424=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM424
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM425=.LTDIE_56_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM425
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM426=.LTDIE_66_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM426
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM427=.LTDIE_67_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM427
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM428=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM428
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM429=.LTDIE_65 - .Ldebug_info_start
	.long .LDIFF_SYM429
.LTDIE_65_POINTER:

	.byte 13
.LDIFF_SYM430=.LTDIE_65 - .Ldebug_info_start
	.long .LDIFF_SYM430
.LTDIE_65_REFERENCE:

	.byte 14
.LDIFF_SYM431=.LTDIE_65 - .Ldebug_info_start
	.long .LDIFF_SYM431
.LTDIE_69:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM432=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM432
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM433=.LTDIE_68_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM433
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM434=.LTDIE_69 - .Ldebug_info_start
	.long .LDIFF_SYM434
.LTDIE_69_POINTER:

	.byte 13
.LDIFF_SYM435=.LTDIE_69 - .Ldebug_info_start
	.long .LDIFF_SYM435
.LTDIE_69_REFERENCE:

	.byte 14
.LDIFF_SYM436=.LTDIE_69 - .Ldebug_info_start
	.long .LDIFF_SYM436
.LTDIE_70:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM437=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM437
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM438=.LTDIE_68_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM438
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM439=.LTDIE_70 - .Ldebug_info_start
	.long .LDIFF_SYM439
.LTDIE_70_POINTER:

	.byte 13
.LDIFF_SYM440=.LTDIE_70 - .Ldebug_info_start
	.long .LDIFF_SYM440
.LTDIE_70_REFERENCE:

	.byte 14
.LDIFF_SYM441=.LTDIE_70 - .Ldebug_info_start
	.long .LDIFF_SYM441
.LTDIE_68:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM442=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM442
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM443=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM443
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM444=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM444
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM445=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM445
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM446=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM446
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM447=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM447
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM448=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM448
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM449=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM449
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM450=.LTDIE_69_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM450
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM451=.LTDIE_70_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM451
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM452=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM452
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM453=.LTDIE_68 - .Ldebug_info_start
	.long .LDIFF_SYM453
.LTDIE_68_POINTER:

	.byte 13
.LDIFF_SYM454=.LTDIE_68 - .Ldebug_info_start
	.long .LDIFF_SYM454
.LTDIE_68_REFERENCE:

	.byte 14
.LDIFF_SYM455=.LTDIE_68 - .Ldebug_info_start
	.long .LDIFF_SYM455
.LTDIE_72:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM456=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM456
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM457=.LTDIE_71_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM457
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM458=.LTDIE_72 - .Ldebug_info_start
	.long .LDIFF_SYM458
.LTDIE_72_POINTER:

	.byte 13
.LDIFF_SYM459=.LTDIE_72 - .Ldebug_info_start
	.long .LDIFF_SYM459
.LTDIE_72_REFERENCE:

	.byte 14
.LDIFF_SYM460=.LTDIE_72 - .Ldebug_info_start
	.long .LDIFF_SYM460
.LTDIE_73:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM461=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM461
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM462=.LTDIE_71_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM462
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM463=.LTDIE_73 - .Ldebug_info_start
	.long .LDIFF_SYM463
.LTDIE_73_POINTER:

	.byte 13
.LDIFF_SYM464=.LTDIE_73 - .Ldebug_info_start
	.long .LDIFF_SYM464
.LTDIE_73_REFERENCE:

	.byte 14
.LDIFF_SYM465=.LTDIE_73 - .Ldebug_info_start
	.long .LDIFF_SYM465
.LTDIE_71:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM466=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM466
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM467=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM467
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM468=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM468
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM469=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM469
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM470=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM470
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM471=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM471
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM472=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM472
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM473=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM473
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM474=.LTDIE_72_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM474
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM475=.LTDIE_73_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM475
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM476=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM476
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM477=.LTDIE_71 - .Ldebug_info_start
	.long .LDIFF_SYM477
.LTDIE_71_POINTER:

	.byte 13
.LDIFF_SYM478=.LTDIE_71 - .Ldebug_info_start
	.long .LDIFF_SYM478
.LTDIE_71_REFERENCE:

	.byte 14
.LDIFF_SYM479=.LTDIE_71 - .Ldebug_info_start
	.long .LDIFF_SYM479
.LTDIE_75:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM480=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM480
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM481=.LTDIE_74_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM481
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM482=.LTDIE_75 - .Ldebug_info_start
	.long .LDIFF_SYM482
.LTDIE_75_POINTER:

	.byte 13
.LDIFF_SYM483=.LTDIE_75 - .Ldebug_info_start
	.long .LDIFF_SYM483
.LTDIE_75_REFERENCE:

	.byte 14
.LDIFF_SYM484=.LTDIE_75 - .Ldebug_info_start
	.long .LDIFF_SYM484
.LTDIE_76:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM485=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM485
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM486=.LTDIE_74_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM486
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM487=.LTDIE_76 - .Ldebug_info_start
	.long .LDIFF_SYM487
.LTDIE_76_POINTER:

	.byte 13
.LDIFF_SYM488=.LTDIE_76 - .Ldebug_info_start
	.long .LDIFF_SYM488
.LTDIE_76_REFERENCE:

	.byte 14
.LDIFF_SYM489=.LTDIE_76 - .Ldebug_info_start
	.long .LDIFF_SYM489
.LTDIE_74:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM490=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM490
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM491=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM491
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM492=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM492
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM493=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM493
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM494=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM494
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM495=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM495
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM496=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM496
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM497=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM497
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM498=.LTDIE_75_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM498
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM499=.LTDIE_76_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM499
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM500=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM500
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM501=.LTDIE_74 - .Ldebug_info_start
	.long .LDIFF_SYM501
.LTDIE_74_POINTER:

	.byte 13
.LDIFF_SYM502=.LTDIE_74 - .Ldebug_info_start
	.long .LDIFF_SYM502
.LTDIE_74_REFERENCE:

	.byte 14
.LDIFF_SYM503=.LTDIE_74 - .Ldebug_info_start
	.long .LDIFF_SYM503
.LTDIE_78:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM504=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM504
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM505=.LTDIE_77_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM505
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM506=.LTDIE_78 - .Ldebug_info_start
	.long .LDIFF_SYM506
.LTDIE_78_POINTER:

	.byte 13
.LDIFF_SYM507=.LTDIE_78 - .Ldebug_info_start
	.long .LDIFF_SYM507
.LTDIE_78_REFERENCE:

	.byte 14
.LDIFF_SYM508=.LTDIE_78 - .Ldebug_info_start
	.long .LDIFF_SYM508
.LTDIE_79:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM509=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM509
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM510=.LTDIE_77_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM510
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM511=.LTDIE_79 - .Ldebug_info_start
	.long .LDIFF_SYM511
.LTDIE_79_POINTER:

	.byte 13
.LDIFF_SYM512=.LTDIE_79 - .Ldebug_info_start
	.long .LDIFF_SYM512
.LTDIE_79_REFERENCE:

	.byte 14
.LDIFF_SYM513=.LTDIE_79 - .Ldebug_info_start
	.long .LDIFF_SYM513
.LTDIE_77:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM514=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM514
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM515=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM515
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM516=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM516
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM517=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM517
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM518=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM518
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM519=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM519
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM520=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM520
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM521=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM521
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM522=.LTDIE_78_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM522
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM523=.LTDIE_79_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM523
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM524=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM524
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM525=.LTDIE_77 - .Ldebug_info_start
	.long .LDIFF_SYM525
.LTDIE_77_POINTER:

	.byte 13
.LDIFF_SYM526=.LTDIE_77 - .Ldebug_info_start
	.long .LDIFF_SYM526
.LTDIE_77_REFERENCE:

	.byte 14
.LDIFF_SYM527=.LTDIE_77 - .Ldebug_info_start
	.long .LDIFF_SYM527
.LTDIE_81:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM528=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM528
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM529=.LTDIE_80_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM529
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM530=.LTDIE_81 - .Ldebug_info_start
	.long .LDIFF_SYM530
.LTDIE_81_POINTER:

	.byte 13
.LDIFF_SYM531=.LTDIE_81 - .Ldebug_info_start
	.long .LDIFF_SYM531
.LTDIE_81_REFERENCE:

	.byte 14
.LDIFF_SYM532=.LTDIE_81 - .Ldebug_info_start
	.long .LDIFF_SYM532
.LTDIE_82:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM533=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM533
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM534=.LTDIE_80_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM534
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM535=.LTDIE_82 - .Ldebug_info_start
	.long .LDIFF_SYM535
.LTDIE_82_POINTER:

	.byte 13
.LDIFF_SYM536=.LTDIE_82 - .Ldebug_info_start
	.long .LDIFF_SYM536
.LTDIE_82_REFERENCE:

	.byte 14
.LDIFF_SYM537=.LTDIE_82 - .Ldebug_info_start
	.long .LDIFF_SYM537
.LTDIE_80:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM538=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM538
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM539=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM539
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM540=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM540
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM541=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM541
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM542=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM542
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM543=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM543
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM544=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM544
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM545=.LTDIE_56_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM545
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM546=.LTDIE_81_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM546
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM547=.LTDIE_82_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM547
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM548=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM548
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM549=.LTDIE_80 - .Ldebug_info_start
	.long .LDIFF_SYM549
.LTDIE_80_POINTER:

	.byte 13
.LDIFF_SYM550=.LTDIE_80 - .Ldebug_info_start
	.long .LDIFF_SYM550
.LTDIE_80_REFERENCE:

	.byte 14
.LDIFF_SYM551=.LTDIE_80 - .Ldebug_info_start
	.long .LDIFF_SYM551
.LTDIE_42:

	.byte 5
	.string "Mono_Cecil_MetadataSystem"

	.byte 248,1,16
.LDIFF_SYM552=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM552
	.byte 2,35,0,6
	.string "AssemblyReferences"

.LDIFF_SYM553=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM553
	.byte 2,35,16,6
	.string "ModuleReferences"

.LDIFF_SYM554=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM554
	.byte 2,35,24,6
	.string "Types"

.LDIFF_SYM555=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM555
	.byte 2,35,32,6
	.string "TypeReferences"

.LDIFF_SYM556=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM556
	.byte 2,35,40,6
	.string "Fields"

.LDIFF_SYM557=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM557
	.byte 2,35,48,6
	.string "Methods"

.LDIFF_SYM558=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM558
	.byte 2,35,56,6
	.string "MemberReferences"

.LDIFF_SYM559=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM559
	.byte 2,35,64,6
	.string "NestedTypes"

.LDIFF_SYM560=.LTDIE_43_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM560
	.byte 2,35,72,6
	.string "ReverseNestedTypes"

.LDIFF_SYM561=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM561
	.byte 2,35,80,6
	.string "Interfaces"

.LDIFF_SYM562=.LTDIE_49_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM562
	.byte 2,35,88,6
	.string "ClassLayouts"

.LDIFF_SYM563=.LTDIE_52_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM563
	.byte 2,35,96,6
	.string "FieldLayouts"

.LDIFF_SYM564=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM564
	.byte 2,35,104,6
	.string "FieldRVAs"

.LDIFF_SYM565=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM565
	.byte 2,35,112,6
	.string "FieldMarshals"

.LDIFF_SYM566=.LTDIE_55_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM566
	.byte 2,35,120,6
	.string "Constants"

.LDIFF_SYM567=.LTDIE_59_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM567
	.byte 3,35,128,1,6
	.string "Overrides"

.LDIFF_SYM568=.LTDIE_62_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM568
	.byte 3,35,136,1,6
	.string "CustomAttributes"

.LDIFF_SYM569=.LTDIE_65_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM569
	.byte 3,35,144,1,6
	.string "SecurityDeclarations"

.LDIFF_SYM570=.LTDIE_65_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM570
	.byte 3,35,152,1,6
	.string "Events"

.LDIFF_SYM571=.LTDIE_68_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM571
	.byte 3,35,160,1,6
	.string "Properties"

.LDIFF_SYM572=.LTDIE_68_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM572
	.byte 3,35,168,1,6
	.string "Semantics"

.LDIFF_SYM573=.LTDIE_71_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM573
	.byte 3,35,176,1,6
	.string "PInvokes"

.LDIFF_SYM574=.LTDIE_74_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM574
	.byte 3,35,184,1,6
	.string "GenericParameters"

.LDIFF_SYM575=.LTDIE_65_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM575
	.byte 3,35,192,1,6
	.string "GenericConstraints"

.LDIFF_SYM576=.LTDIE_49_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM576
	.byte 3,35,200,1,6
	.string "Documents"

.LDIFF_SYM577=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM577
	.byte 3,35,208,1,6
	.string "LocalScopes"

.LDIFF_SYM578=.LTDIE_77_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM578
	.byte 3,35,216,1,6
	.string "ImportScopes"

.LDIFF_SYM579=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM579
	.byte 3,35,224,1,6
	.string "StateMachineMethods"

.LDIFF_SYM580=.LTDIE_46_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM580
	.byte 3,35,232,1,6
	.string "CustomDebugInformations"

.LDIFF_SYM581=.LTDIE_80_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM581
	.byte 3,35,240,1,0,7
	.string "Mono_Cecil_MetadataSystem"

.LDIFF_SYM582=.LTDIE_42 - .Ldebug_info_start
	.long .LDIFF_SYM582
.LTDIE_42_POINTER:

	.byte 13
.LDIFF_SYM583=.LTDIE_42 - .Ldebug_info_start
	.long .LDIFF_SYM583
.LTDIE_42_REFERENCE:

	.byte 14
.LDIFF_SYM584=.LTDIE_42 - .Ldebug_info_start
	.long .LDIFF_SYM584
.LTDIE_83:

	.byte 8
	.string "Mono_Cecil_ReadingMode"

	.byte 4
.LDIFF_SYM585=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM585
	.byte 9
	.string "Immediate"

	.byte 1,9
	.string "Deferred"

	.byte 2,0,7
	.string "Mono_Cecil_ReadingMode"

.LDIFF_SYM586=.LTDIE_83 - .Ldebug_info_start
	.long .LDIFF_SYM586
.LTDIE_83_POINTER:

	.byte 13
.LDIFF_SYM587=.LTDIE_83 - .Ldebug_info_start
	.long .LDIFF_SYM587
.LTDIE_83_REFERENCE:

	.byte 14
.LDIFF_SYM588=.LTDIE_83 - .Ldebug_info_start
	.long .LDIFF_SYM588
.LTDIE_84:

	.byte 17
	.string "Mono_Cecil_Cil_ISymbolReaderProvider"

	.byte 16,7
	.string "Mono_Cecil_Cil_ISymbolReaderProvider"

.LDIFF_SYM589=.LTDIE_84 - .Ldebug_info_start
	.long .LDIFF_SYM589
.LTDIE_84_POINTER:

	.byte 13
.LDIFF_SYM590=.LTDIE_84 - .Ldebug_info_start
	.long .LDIFF_SYM590
.LTDIE_84_REFERENCE:

	.byte 14
.LDIFF_SYM591=.LTDIE_84 - .Ldebug_info_start
	.long .LDIFF_SYM591
.LTDIE_85:

	.byte 17
	.string "Mono_Cecil_Cil_ISymbolReader"

	.byte 16,7
	.string "Mono_Cecil_Cil_ISymbolReader"

.LDIFF_SYM592=.LTDIE_85 - .Ldebug_info_start
	.long .LDIFF_SYM592
.LTDIE_85_POINTER:

	.byte 13
.LDIFF_SYM593=.LTDIE_85 - .Ldebug_info_start
	.long .LDIFF_SYM593
.LTDIE_85_REFERENCE:

	.byte 14
.LDIFF_SYM594=.LTDIE_85 - .Ldebug_info_start
	.long .LDIFF_SYM594
.LTDIE_86:

	.byte 17
	.string "Mono_Cecil_IMetadataResolver"

	.byte 16,7
	.string "Mono_Cecil_IMetadataResolver"

.LDIFF_SYM595=.LTDIE_86 - .Ldebug_info_start
	.long .LDIFF_SYM595
.LTDIE_86_POINTER:

	.byte 13
.LDIFF_SYM596=.LTDIE_86 - .Ldebug_info_start
	.long .LDIFF_SYM596
.LTDIE_86_REFERENCE:

	.byte 14
.LDIFF_SYM597=.LTDIE_86 - .Ldebug_info_start
	.long .LDIFF_SYM597
.LTDIE_87:

	.byte 5
	.string "Mono_Cecil_TypeSystem"

	.byte 168,1,16
.LDIFF_SYM598=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM598
	.byte 2,35,0,6
	.string "module"

.LDIFF_SYM599=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM599
	.byte 2,35,16,6
	.string "type_object"

.LDIFF_SYM600=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM600
	.byte 2,35,24,6
	.string "type_void"

.LDIFF_SYM601=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM601
	.byte 2,35,32,6
	.string "type_bool"

.LDIFF_SYM602=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM602
	.byte 2,35,40,6
	.string "type_char"

.LDIFF_SYM603=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM603
	.byte 2,35,48,6
	.string "type_sbyte"

.LDIFF_SYM604=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM604
	.byte 2,35,56,6
	.string "type_byte"

.LDIFF_SYM605=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM605
	.byte 2,35,64,6
	.string "type_int16"

.LDIFF_SYM606=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM606
	.byte 2,35,72,6
	.string "type_uint16"

.LDIFF_SYM607=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM607
	.byte 2,35,80,6
	.string "type_int32"

.LDIFF_SYM608=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM608
	.byte 2,35,88,6
	.string "type_uint32"

.LDIFF_SYM609=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM609
	.byte 2,35,96,6
	.string "type_int64"

.LDIFF_SYM610=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM610
	.byte 2,35,104,6
	.string "type_uint64"

.LDIFF_SYM611=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM611
	.byte 2,35,112,6
	.string "type_single"

.LDIFF_SYM612=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM612
	.byte 2,35,120,6
	.string "type_double"

.LDIFF_SYM613=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM613
	.byte 3,35,128,1,6
	.string "type_intptr"

.LDIFF_SYM614=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM614
	.byte 3,35,136,1,6
	.string "type_uintptr"

.LDIFF_SYM615=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM615
	.byte 3,35,144,1,6
	.string "type_string"

.LDIFF_SYM616=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM616
	.byte 3,35,152,1,6
	.string "type_typedref"

.LDIFF_SYM617=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM617
	.byte 3,35,160,1,0,7
	.string "Mono_Cecil_TypeSystem"

.LDIFF_SYM618=.LTDIE_87 - .Ldebug_info_start
	.long .LDIFF_SYM618
.LTDIE_87_POINTER:

	.byte 13
.LDIFF_SYM619=.LTDIE_87 - .Ldebug_info_start
	.long .LDIFF_SYM619
.LTDIE_87_REFERENCE:

	.byte 14
.LDIFF_SYM620=.LTDIE_87 - .Ldebug_info_start
	.long .LDIFF_SYM620
.LTDIE_89:

	.byte 5
	.string "Mono_Cecil_PE_ByteBuffer"

	.byte 32,16
.LDIFF_SYM621=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM621
	.byte 2,35,0,6
	.string "buffer"

.LDIFF_SYM622=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM622
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM623=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM623
	.byte 2,35,24,6
	.string "position"

.LDIFF_SYM624=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM624
	.byte 2,35,28,0,7
	.string "Mono_Cecil_PE_ByteBuffer"

.LDIFF_SYM625=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM625
.LTDIE_89_POINTER:

	.byte 13
.LDIFF_SYM626=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM626
.LTDIE_89_REFERENCE:

	.byte 14
.LDIFF_SYM627=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM627
.LTDIE_97:

	.byte 17
	.string "System_Runtime_Remoting_Messaging_IMessageSink"

	.byte 16,7
	.string "System_Runtime_Remoting_Messaging_IMessageSink"

.LDIFF_SYM628=.LTDIE_97 - .Ldebug_info_start
	.long .LDIFF_SYM628
.LTDIE_97_POINTER:

	.byte 13
.LDIFF_SYM629=.LTDIE_97 - .Ldebug_info_start
	.long .LDIFF_SYM629
.LTDIE_97_REFERENCE:

	.byte 14
.LDIFF_SYM630=.LTDIE_97 - .Ldebug_info_start
	.long .LDIFF_SYM630
.LTDIE_99:

	.byte 5
	.string "System_Collections_ArrayList"

	.byte 40,16
.LDIFF_SYM631=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM631
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM632=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM632
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM633=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM633
	.byte 2,35,32,6
	.string "_version"

.LDIFF_SYM634=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM634
	.byte 2,35,36,6
	.string "_syncRoot"

.LDIFF_SYM635=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM635
	.byte 2,35,24,0,7
	.string "System_Collections_ArrayList"

.LDIFF_SYM636=.LTDIE_99 - .Ldebug_info_start
	.long .LDIFF_SYM636
.LTDIE_99_POINTER:

	.byte 13
.LDIFF_SYM637=.LTDIE_99 - .Ldebug_info_start
	.long .LDIFF_SYM637
.LTDIE_99_REFERENCE:

	.byte 14
.LDIFF_SYM638=.LTDIE_99 - .Ldebug_info_start
	.long .LDIFF_SYM638
.LTDIE_98:

	.byte 5
	.string "System_Runtime_Remoting_Contexts_DynamicPropertyCollection"

	.byte 24,16
.LDIFF_SYM639=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM639
	.byte 2,35,0,6
	.string "_properties"

.LDIFF_SYM640=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM640
	.byte 2,35,16,0,7
	.string "System_Runtime_Remoting_Contexts_DynamicPropertyCollection"

.LDIFF_SYM641=.LTDIE_98 - .Ldebug_info_start
	.long .LDIFF_SYM641
.LTDIE_98_POINTER:

	.byte 13
.LDIFF_SYM642=.LTDIE_98 - .Ldebug_info_start
	.long .LDIFF_SYM642
.LTDIE_98_REFERENCE:

	.byte 14
.LDIFF_SYM643=.LTDIE_98 - .Ldebug_info_start
	.long .LDIFF_SYM643
.LTDIE_101:

	.byte 17
	.string "System_Runtime_Remoting_IChannelInfo"

	.byte 16,7
	.string "System_Runtime_Remoting_IChannelInfo"

.LDIFF_SYM644=.LTDIE_101 - .Ldebug_info_start
	.long .LDIFF_SYM644
.LTDIE_101_POINTER:

	.byte 13
.LDIFF_SYM645=.LTDIE_101 - .Ldebug_info_start
	.long .LDIFF_SYM645
.LTDIE_101_REFERENCE:

	.byte 14
.LDIFF_SYM646=.LTDIE_101 - .Ldebug_info_start
	.long .LDIFF_SYM646
.LTDIE_102:

	.byte 17
	.string "System_Runtime_Remoting_IRemotingTypeInfo"

	.byte 16,7
	.string "System_Runtime_Remoting_IRemotingTypeInfo"

.LDIFF_SYM647=.LTDIE_102 - .Ldebug_info_start
	.long .LDIFF_SYM647
.LTDIE_102_POINTER:

	.byte 13
.LDIFF_SYM648=.LTDIE_102 - .Ldebug_info_start
	.long .LDIFF_SYM648
.LTDIE_102_REFERENCE:

	.byte 14
.LDIFF_SYM649=.LTDIE_102 - .Ldebug_info_start
	.long .LDIFF_SYM649
.LTDIE_103:

	.byte 17
	.string "System_Runtime_Remoting_IEnvoyInfo"

	.byte 16,7
	.string "System_Runtime_Remoting_IEnvoyInfo"

.LDIFF_SYM650=.LTDIE_103 - .Ldebug_info_start
	.long .LDIFF_SYM650
.LTDIE_103_POINTER:

	.byte 13
.LDIFF_SYM651=.LTDIE_103 - .Ldebug_info_start
	.long .LDIFF_SYM651
.LTDIE_103_REFERENCE:

	.byte 14
.LDIFF_SYM652=.LTDIE_103 - .Ldebug_info_start
	.long .LDIFF_SYM652
.LTDIE_100:

	.byte 5
	.string "System_Runtime_Remoting_ObjRef"

	.byte 64,16
.LDIFF_SYM653=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM653
	.byte 2,35,0,6
	.string "channel_info"

.LDIFF_SYM654=.LTDIE_101_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM654
	.byte 2,35,16,6
	.string "uri"

.LDIFF_SYM655=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM655
	.byte 2,35,24,6
	.string "typeInfo"

.LDIFF_SYM656=.LTDIE_102_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM656
	.byte 2,35,32,6
	.string "envoyInfo"

.LDIFF_SYM657=.LTDIE_103_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM657
	.byte 2,35,40,6
	.string "flags"

.LDIFF_SYM658=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM658
	.byte 2,35,56,6
	.string "_serverType"

.LDIFF_SYM659=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM659
	.byte 2,35,48,0,7
	.string "System_Runtime_Remoting_ObjRef"

.LDIFF_SYM660=.LTDIE_100 - .Ldebug_info_start
	.long .LDIFF_SYM660
.LTDIE_100_POINTER:

	.byte 13
.LDIFF_SYM661=.LTDIE_100 - .Ldebug_info_start
	.long .LDIFF_SYM661
.LTDIE_100_REFERENCE:

	.byte 14
.LDIFF_SYM662=.LTDIE_100 - .Ldebug_info_start
	.long .LDIFF_SYM662
.LTDIE_96:

	.byte 5
	.string "System_Runtime_Remoting_Identity"

	.byte 72,16
.LDIFF_SYM663=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM663
	.byte 2,35,0,6
	.string "_objectUri"

.LDIFF_SYM664=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM664
	.byte 2,35,16,6
	.string "_channelSink"

.LDIFF_SYM665=.LTDIE_97_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM665
	.byte 2,35,24,6
	.string "_envoySink"

.LDIFF_SYM666=.LTDIE_97_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM666
	.byte 2,35,32,6
	.string "_clientDynamicProperties"

.LDIFF_SYM667=.LTDIE_98_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM667
	.byte 2,35,40,6
	.string "_serverDynamicProperties"

.LDIFF_SYM668=.LTDIE_98_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM668
	.byte 2,35,48,6
	.string "_objRef"

.LDIFF_SYM669=.LTDIE_100_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM669
	.byte 2,35,56,6
	.string "_disposed"

.LDIFF_SYM670=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM670
	.byte 2,35,64,0,7
	.string "System_Runtime_Remoting_Identity"

.LDIFF_SYM671=.LTDIE_96 - .Ldebug_info_start
	.long .LDIFF_SYM671
.LTDIE_96_POINTER:

	.byte 13
.LDIFF_SYM672=.LTDIE_96 - .Ldebug_info_start
	.long .LDIFF_SYM672
.LTDIE_96_REFERENCE:

	.byte 14
.LDIFF_SYM673=.LTDIE_96 - .Ldebug_info_start
	.long .LDIFF_SYM673
.LTDIE_105:

	.byte 5
	.string "System_Collections_Generic_List`1"

	.byte 40,16
.LDIFF_SYM674=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM674
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM675=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM675
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM676=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM676
	.byte 2,35,32,6
	.string "_version"

.LDIFF_SYM677=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM677
	.byte 2,35,36,6
	.string "_syncRoot"

.LDIFF_SYM678=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM678
	.byte 2,35,24,0,7
	.string "System_Collections_Generic_List`1"

.LDIFF_SYM679=.LTDIE_105 - .Ldebug_info_start
	.long .LDIFF_SYM679
.LTDIE_105_POINTER:

	.byte 13
.LDIFF_SYM680=.LTDIE_105 - .Ldebug_info_start
	.long .LDIFF_SYM680
.LTDIE_105_REFERENCE:

	.byte 14
.LDIFF_SYM681=.LTDIE_105 - .Ldebug_info_start
	.long .LDIFF_SYM681
.LTDIE_109:

	.byte 5
	.string "System_Collections_Generic_List`1"

	.byte 40,16
.LDIFF_SYM682=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM682
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM683=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM683
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM684=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM684
	.byte 2,35,32,6
	.string "_version"

.LDIFF_SYM685=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM685
	.byte 2,35,36,6
	.string "_syncRoot"

.LDIFF_SYM686=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM686
	.byte 2,35,24,0,7
	.string "System_Collections_Generic_List`1"

.LDIFF_SYM687=.LTDIE_109 - .Ldebug_info_start
	.long .LDIFF_SYM687
.LTDIE_109_POINTER:

	.byte 13
.LDIFF_SYM688=.LTDIE_109 - .Ldebug_info_start
	.long .LDIFF_SYM688
.LTDIE_109_REFERENCE:

	.byte 14
.LDIFF_SYM689=.LTDIE_109 - .Ldebug_info_start
	.long .LDIFF_SYM689
.LTDIE_111:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM690=.LTDIE_111 - .Ldebug_info_start
	.long .LDIFF_SYM690
.LTDIE_111_POINTER:

	.byte 13
.LDIFF_SYM691=.LTDIE_111 - .Ldebug_info_start
	.long .LDIFF_SYM691
.LTDIE_111_REFERENCE:

	.byte 14
.LDIFF_SYM692=.LTDIE_111 - .Ldebug_info_start
	.long .LDIFF_SYM692
.LTDIE_112:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM693=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM693
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM694=.LTDIE_110_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM694
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM695=.LTDIE_112 - .Ldebug_info_start
	.long .LDIFF_SYM695
.LTDIE_112_POINTER:

	.byte 13
.LDIFF_SYM696=.LTDIE_112 - .Ldebug_info_start
	.long .LDIFF_SYM696
.LTDIE_112_REFERENCE:

	.byte 14
.LDIFF_SYM697=.LTDIE_112 - .Ldebug_info_start
	.long .LDIFF_SYM697
.LTDIE_113:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM698=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM698
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM699=.LTDIE_110_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM699
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM700=.LTDIE_113 - .Ldebug_info_start
	.long .LDIFF_SYM700
.LTDIE_113_POINTER:

	.byte 13
.LDIFF_SYM701=.LTDIE_113 - .Ldebug_info_start
	.long .LDIFF_SYM701
.LTDIE_113_REFERENCE:

	.byte 14
.LDIFF_SYM702=.LTDIE_113 - .Ldebug_info_start
	.long .LDIFF_SYM702
.LTDIE_110:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM703=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM703
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM704=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM704
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM705=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM705
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM706=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM706
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM707=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM707
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM708=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM708
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM709=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM709
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM710=.LTDIE_111_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM710
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM711=.LTDIE_112_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM711
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM712=.LTDIE_113_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM712
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM713=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM713
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM714=.LTDIE_110 - .Ldebug_info_start
	.long .LDIFF_SYM714
.LTDIE_110_POINTER:

	.byte 13
.LDIFF_SYM715=.LTDIE_110 - .Ldebug_info_start
	.long .LDIFF_SYM715
.LTDIE_110_REFERENCE:

	.byte 14
.LDIFF_SYM716=.LTDIE_110 - .Ldebug_info_start
	.long .LDIFF_SYM716
.LTDIE_108:

	.byte 5
	.string "System_LocalDataStoreMgr"

	.byte 56,16
.LDIFF_SYM717=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM717
	.byte 2,35,0,6
	.string "m_SlotInfoTable"

.LDIFF_SYM718=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM718
	.byte 2,35,16,6
	.string "m_FirstAvailableSlot"

.LDIFF_SYM719=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM719
	.byte 2,35,40,6
	.string "m_ManagedLocalDataStores"

.LDIFF_SYM720=.LTDIE_109_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM720
	.byte 2,35,24,6
	.string "m_KeyToSlotMap"

.LDIFF_SYM721=.LTDIE_110_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM721
	.byte 2,35,32,6
	.string "m_CookieGenerator"

.LDIFF_SYM722=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM722
	.byte 2,35,48,0,7
	.string "System_LocalDataStoreMgr"

.LDIFF_SYM723=.LTDIE_108 - .Ldebug_info_start
	.long .LDIFF_SYM723
.LTDIE_108_POINTER:

	.byte 13
.LDIFF_SYM724=.LTDIE_108 - .Ldebug_info_start
	.long .LDIFF_SYM724
.LTDIE_108_REFERENCE:

	.byte 14
.LDIFF_SYM725=.LTDIE_108 - .Ldebug_info_start
	.long .LDIFF_SYM725
.LTDIE_107:

	.byte 5
	.string "System_LocalDataStore"

	.byte 32,16
.LDIFF_SYM726=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM726
	.byte 2,35,0,6
	.string "m_DataTable"

.LDIFF_SYM727=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM727
	.byte 2,35,16,6
	.string "m_Manager"

.LDIFF_SYM728=.LTDIE_108_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM728
	.byte 2,35,24,0,7
	.string "System_LocalDataStore"

.LDIFF_SYM729=.LTDIE_107 - .Ldebug_info_start
	.long .LDIFF_SYM729
.LTDIE_107_POINTER:

	.byte 13
.LDIFF_SYM730=.LTDIE_107 - .Ldebug_info_start
	.long .LDIFF_SYM730
.LTDIE_107_REFERENCE:

	.byte 14
.LDIFF_SYM731=.LTDIE_107 - .Ldebug_info_start
	.long .LDIFF_SYM731
.LTDIE_106:

	.byte 5
	.string "System_LocalDataStoreHolder"

	.byte 24,16
.LDIFF_SYM732=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM732
	.byte 2,35,0,6
	.string "m_Store"

.LDIFF_SYM733=.LTDIE_107_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM733
	.byte 2,35,16,0,7
	.string "System_LocalDataStoreHolder"

.LDIFF_SYM734=.LTDIE_106 - .Ldebug_info_start
	.long .LDIFF_SYM734
.LTDIE_106_POINTER:

	.byte 13
.LDIFF_SYM735=.LTDIE_106 - .Ldebug_info_start
	.long .LDIFF_SYM735
.LTDIE_106_REFERENCE:

	.byte 14
.LDIFF_SYM736=.LTDIE_106 - .Ldebug_info_start
	.long .LDIFF_SYM736
.LTDIE_115:

	.byte 5
	.string "System_ContextBoundObject"

	.byte 24,16
.LDIFF_SYM737=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM737
	.byte 2,35,0,0,7
	.string "System_ContextBoundObject"

.LDIFF_SYM738=.LTDIE_115 - .Ldebug_info_start
	.long .LDIFF_SYM738
.LTDIE_115_POINTER:

	.byte 13
.LDIFF_SYM739=.LTDIE_115 - .Ldebug_info_start
	.long .LDIFF_SYM739
.LTDIE_115_REFERENCE:

	.byte 14
.LDIFF_SYM740=.LTDIE_115 - .Ldebug_info_start
	.long .LDIFF_SYM740
.LTDIE_114:

	.byte 5
	.string "System_Runtime_Remoting_Contexts_ContextCallbackObject"

	.byte 24,16
.LDIFF_SYM741=.LTDIE_115 - .Ldebug_info_start
	.long .LDIFF_SYM741
	.byte 2,35,0,0,7
	.string "System_Runtime_Remoting_Contexts_ContextCallbackObject"

.LDIFF_SYM742=.LTDIE_114 - .Ldebug_info_start
	.long .LDIFF_SYM742
.LTDIE_114_POINTER:

	.byte 13
.LDIFF_SYM743=.LTDIE_114 - .Ldebug_info_start
	.long .LDIFF_SYM743
.LTDIE_114_REFERENCE:

	.byte 14
.LDIFF_SYM744=.LTDIE_114 - .Ldebug_info_start
	.long .LDIFF_SYM744
.LTDIE_104:

	.byte 5
	.string "System_Runtime_Remoting_Contexts_Context"

	.byte 88,16
.LDIFF_SYM745=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM745
	.byte 2,35,0,6
	.string "domain_id"

.LDIFF_SYM746=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM746
	.byte 2,35,16,6
	.string "context_id"

.LDIFF_SYM747=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM747
	.byte 2,35,20,6
	.string "static_data"

.LDIFF_SYM748=.LDIE_U - .Ldebug_info_start
	.long .LDIFF_SYM748
	.byte 2,35,24,6
	.string "data"

.LDIFF_SYM749=.LDIE_U - .Ldebug_info_start
	.long .LDIFF_SYM749
	.byte 2,35,32,6
	.string "server_context_sink_chain"

.LDIFF_SYM750=.LTDIE_97_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM750
	.byte 2,35,40,6
	.string "client_context_sink_chain"

.LDIFF_SYM751=.LTDIE_97_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM751
	.byte 2,35,48,6
	.string "context_properties"

.LDIFF_SYM752=.LTDIE_105_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM752
	.byte 2,35,56,6
	.string "_localDataStore"

.LDIFF_SYM753=.LTDIE_106_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM753
	.byte 2,35,64,6
	.string "context_dynamic_properties"

.LDIFF_SYM754=.LTDIE_98_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM754
	.byte 2,35,72,6
	.string "callback_object"

.LDIFF_SYM755=.LTDIE_114_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM755
	.byte 2,35,80,0,7
	.string "System_Runtime_Remoting_Contexts_Context"

.LDIFF_SYM756=.LTDIE_104 - .Ldebug_info_start
	.long .LDIFF_SYM756
.LTDIE_104_POINTER:

	.byte 13
.LDIFF_SYM757=.LTDIE_104 - .Ldebug_info_start
	.long .LDIFF_SYM757
.LTDIE_104_REFERENCE:

	.byte 14
.LDIFF_SYM758=.LTDIE_104 - .Ldebug_info_start
	.long .LDIFF_SYM758
.LTDIE_117:

	.byte 8
	.string "System_Runtime_Remoting_Lifetime_LeaseState"

	.byte 4
.LDIFF_SYM759=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM759
	.byte 9
	.string "Null"

	.byte 0,9
	.string "Initial"

	.byte 1,9
	.string "Active"

	.byte 2,9
	.string "Renewing"

	.byte 3,9
	.string "Expired"

	.byte 4,0,7
	.string "System_Runtime_Remoting_Lifetime_LeaseState"

.LDIFF_SYM760=.LTDIE_117 - .Ldebug_info_start
	.long .LDIFF_SYM760
.LTDIE_117_POINTER:

	.byte 13
.LDIFF_SYM761=.LTDIE_117 - .Ldebug_info_start
	.long .LDIFF_SYM761
.LTDIE_117_REFERENCE:

	.byte 14
.LDIFF_SYM762=.LTDIE_117 - .Ldebug_info_start
	.long .LDIFF_SYM762
.LTDIE_118:

	.byte 5
	.string "System_Collections_Queue"

	.byte 56,16
.LDIFF_SYM763=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM763
	.byte 2,35,0,6
	.string "_array"

.LDIFF_SYM764=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM764
	.byte 2,35,16,6
	.string "_head"

.LDIFF_SYM765=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM765
	.byte 2,35,32,6
	.string "_tail"

.LDIFF_SYM766=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM766
	.byte 2,35,36,6
	.string "_size"

.LDIFF_SYM767=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM767
	.byte 2,35,40,6
	.string "_growFactor"

.LDIFF_SYM768=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM768
	.byte 2,35,44,6
	.string "_version"

.LDIFF_SYM769=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM769
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM770=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM770
	.byte 2,35,24,0,7
	.string "System_Collections_Queue"

.LDIFF_SYM771=.LTDIE_118 - .Ldebug_info_start
	.long .LDIFF_SYM771
.LTDIE_118_POINTER:

	.byte 13
.LDIFF_SYM772=.LTDIE_118 - .Ldebug_info_start
	.long .LDIFF_SYM772
.LTDIE_118_REFERENCE:

	.byte 14
.LDIFF_SYM773=.LTDIE_118 - .Ldebug_info_start
	.long .LDIFF_SYM773
.LTDIE_119:

	.byte 5
	.string "_RenewalDelegate"

	.byte 128,1,16
.LDIFF_SYM774=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM774
	.byte 2,35,0,0,7
	.string "_RenewalDelegate"

.LDIFF_SYM775=.LTDIE_119 - .Ldebug_info_start
	.long .LDIFF_SYM775
.LTDIE_119_POINTER:

	.byte 13
.LDIFF_SYM776=.LTDIE_119 - .Ldebug_info_start
	.long .LDIFF_SYM776
.LTDIE_119_REFERENCE:

	.byte 14
.LDIFF_SYM777=.LTDIE_119 - .Ldebug_info_start
	.long .LDIFF_SYM777
.LTDIE_116:

	.byte 5
	.string "System_Runtime_Remoting_Lifetime_Lease"

	.byte 88,16
.LDIFF_SYM778=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM778
	.byte 2,35,0,6
	.string "_leaseExpireTime"

.LDIFF_SYM779=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM779
	.byte 2,35,48,6
	.string "_currentState"

.LDIFF_SYM780=.LTDIE_117 - .Ldebug_info_start
	.long .LDIFF_SYM780
	.byte 2,35,56,6
	.string "_initialLeaseTime"

.LDIFF_SYM781=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM781
	.byte 2,35,64,6
	.string "_renewOnCallTime"

.LDIFF_SYM782=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM782
	.byte 2,35,72,6
	.string "_sponsorshipTimeout"

.LDIFF_SYM783=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM783
	.byte 2,35,80,6
	.string "_sponsors"

.LDIFF_SYM784=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM784
	.byte 2,35,24,6
	.string "_renewingSponsors"

.LDIFF_SYM785=.LTDIE_118_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM785
	.byte 2,35,32,6
	.string "_renewalDelegate"

.LDIFF_SYM786=.LTDIE_119_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM786
	.byte 2,35,40,0,7
	.string "System_Runtime_Remoting_Lifetime_Lease"

.LDIFF_SYM787=.LTDIE_116 - .Ldebug_info_start
	.long .LDIFF_SYM787
.LTDIE_116_POINTER:

	.byte 13
.LDIFF_SYM788=.LTDIE_116 - .Ldebug_info_start
	.long .LDIFF_SYM788
.LTDIE_116_REFERENCE:

	.byte 14
.LDIFF_SYM789=.LTDIE_116 - .Ldebug_info_start
	.long .LDIFF_SYM789
.LTDIE_95:

	.byte 5
	.string "System_Runtime_Remoting_ServerIdentity"

	.byte 112,16
.LDIFF_SYM790=.LTDIE_96 - .Ldebug_info_start
	.long .LDIFF_SYM790
	.byte 2,35,0,6
	.string "_objectType"

.LDIFF_SYM791=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM791
	.byte 2,35,72,6
	.string "_serverObject"

.LDIFF_SYM792=.LTDIE_94_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM792
	.byte 2,35,80,6
	.string "_serverSink"

.LDIFF_SYM793=.LTDIE_97_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM793
	.byte 2,35,88,6
	.string "_context"

.LDIFF_SYM794=.LTDIE_104_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM794
	.byte 2,35,96,6
	.string "_lease"

.LDIFF_SYM795=.LTDIE_116_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM795
	.byte 2,35,104,0,7
	.string "System_Runtime_Remoting_ServerIdentity"

.LDIFF_SYM796=.LTDIE_95 - .Ldebug_info_start
	.long .LDIFF_SYM796
.LTDIE_95_POINTER:

	.byte 13
.LDIFF_SYM797=.LTDIE_95 - .Ldebug_info_start
	.long .LDIFF_SYM797
.LTDIE_95_REFERENCE:

	.byte 14
.LDIFF_SYM798=.LTDIE_95 - .Ldebug_info_start
	.long .LDIFF_SYM798
.LTDIE_94:

	.byte 5
	.string "System_MarshalByRefObject"

	.byte 24,16
.LDIFF_SYM799=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM799
	.byte 2,35,0,6
	.string "_identity"

.LDIFF_SYM800=.LTDIE_95_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM800
	.byte 2,35,16,0,7
	.string "System_MarshalByRefObject"

.LDIFF_SYM801=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM801
.LTDIE_94_POINTER:

	.byte 13
.LDIFF_SYM802=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM802
.LTDIE_94_REFERENCE:

	.byte 14
.LDIFF_SYM803=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM803
.LTDIE_123:

	.byte 5
	.string "System_Threading_Tasks_TaskScheduler"

	.byte 20,16
.LDIFF_SYM804=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM804
	.byte 2,35,0,6
	.string "m_taskSchedulerId"

.LDIFF_SYM805=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM805
	.byte 2,35,16,0,7
	.string "System_Threading_Tasks_TaskScheduler"

.LDIFF_SYM806=.LTDIE_123 - .Ldebug_info_start
	.long .LDIFF_SYM806
.LTDIE_123_POINTER:

	.byte 13
.LDIFF_SYM807=.LTDIE_123 - .Ldebug_info_start
	.long .LDIFF_SYM807
.LTDIE_123_REFERENCE:

	.byte 14
.LDIFF_SYM808=.LTDIE_123 - .Ldebug_info_start
	.long .LDIFF_SYM808
.LTDIE_127:

	.byte 8
	.string "System_Threading_SynchronizationContextProperties"

	.byte 4
.LDIFF_SYM809=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM809
	.byte 9
	.string "None"

	.byte 0,9
	.string "RequireWaitNotification"

	.byte 1,0,7
	.string "System_Threading_SynchronizationContextProperties"

.LDIFF_SYM810=.LTDIE_127 - .Ldebug_info_start
	.long .LDIFF_SYM810
.LTDIE_127_POINTER:

	.byte 13
.LDIFF_SYM811=.LTDIE_127 - .Ldebug_info_start
	.long .LDIFF_SYM811
.LTDIE_127_REFERENCE:

	.byte 14
.LDIFF_SYM812=.LTDIE_127 - .Ldebug_info_start
	.long .LDIFF_SYM812
.LTDIE_126:

	.byte 5
	.string "System_Threading_SynchronizationContext"

	.byte 20,16
.LDIFF_SYM813=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM813
	.byte 2,35,0,6
	.string "_props"

.LDIFF_SYM814=.LTDIE_127 - .Ldebug_info_start
	.long .LDIFF_SYM814
	.byte 2,35,16,0,7
	.string "System_Threading_SynchronizationContext"

.LDIFF_SYM815=.LTDIE_126 - .Ldebug_info_start
	.long .LDIFF_SYM815
.LTDIE_126_POINTER:

	.byte 13
.LDIFF_SYM816=.LTDIE_126 - .Ldebug_info_start
	.long .LDIFF_SYM816
.LTDIE_126_REFERENCE:

	.byte 14
.LDIFF_SYM817=.LTDIE_126 - .Ldebug_info_start
	.long .LDIFF_SYM817
.LTDIE_130:

	.byte 5
	.string "System_Single"

	.byte 20,16
.LDIFF_SYM818=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM818
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM819=.LDIE_R4 - .Ldebug_info_start
	.long .LDIFF_SYM819
	.byte 2,35,16,0,7
	.string "System_Single"

.LDIFF_SYM820=.LTDIE_130 - .Ldebug_info_start
	.long .LDIFF_SYM820
.LTDIE_130_POINTER:

	.byte 13
.LDIFF_SYM821=.LTDIE_130 - .Ldebug_info_start
	.long .LDIFF_SYM821
.LTDIE_130_REFERENCE:

	.byte 14
.LDIFF_SYM822=.LTDIE_130 - .Ldebug_info_start
	.long .LDIFF_SYM822
.LTDIE_131:

	.byte 17
	.string "System_Collections_ICollection"

	.byte 16,7
	.string "System_Collections_ICollection"

.LDIFF_SYM823=.LTDIE_131 - .Ldebug_info_start
	.long .LDIFF_SYM823
.LTDIE_131_POINTER:

	.byte 13
.LDIFF_SYM824=.LTDIE_131 - .Ldebug_info_start
	.long .LDIFF_SYM824
.LTDIE_131_REFERENCE:

	.byte 14
.LDIFF_SYM825=.LTDIE_131 - .Ldebug_info_start
	.long .LDIFF_SYM825
.LTDIE_132:

	.byte 17
	.string "System_Collections_IEqualityComparer"

	.byte 16,7
	.string "System_Collections_IEqualityComparer"

.LDIFF_SYM826=.LTDIE_132 - .Ldebug_info_start
	.long .LDIFF_SYM826
.LTDIE_132_POINTER:

	.byte 13
.LDIFF_SYM827=.LTDIE_132 - .Ldebug_info_start
	.long .LDIFF_SYM827
.LTDIE_132_REFERENCE:

	.byte 14
.LDIFF_SYM828=.LTDIE_132 - .Ldebug_info_start
	.long .LDIFF_SYM828
.LTDIE_129:

	.byte 5
	.string "System_Collections_Hashtable"

	.byte 80,16
.LDIFF_SYM829=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM829
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM830=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM830
	.byte 2,35,16,6
	.string "_count"

.LDIFF_SYM831=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM831
	.byte 2,35,56,6
	.string "_occupancy"

.LDIFF_SYM832=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM832
	.byte 2,35,60,6
	.string "_loadsize"

.LDIFF_SYM833=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM833
	.byte 2,35,64,6
	.string "_loadFactor"

.LDIFF_SYM834=.LDIE_R4 - .Ldebug_info_start
	.long .LDIFF_SYM834
	.byte 2,35,68,6
	.string "_version"

.LDIFF_SYM835=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM835
	.byte 2,35,72,6
	.string "_isWriterInProgress"

.LDIFF_SYM836=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM836
	.byte 2,35,76,6
	.string "_keys"

.LDIFF_SYM837=.LTDIE_131_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM837
	.byte 2,35,24,6
	.string "_values"

.LDIFF_SYM838=.LTDIE_131_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM838
	.byte 2,35,32,6
	.string "_keycomparer"

.LDIFF_SYM839=.LTDIE_132_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM839
	.byte 2,35,40,6
	.string "_syncRoot"

.LDIFF_SYM840=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM840
	.byte 2,35,48,0,7
	.string "System_Collections_Hashtable"

.LDIFF_SYM841=.LTDIE_129 - .Ldebug_info_start
	.long .LDIFF_SYM841
.LTDIE_129_POINTER:

	.byte 13
.LDIFF_SYM842=.LTDIE_129 - .Ldebug_info_start
	.long .LDIFF_SYM842
.LTDIE_129_REFERENCE:

	.byte 14
.LDIFF_SYM843=.LTDIE_129 - .Ldebug_info_start
	.long .LDIFF_SYM843
.LTDIE_133:

	.byte 5
	.string "System_Runtime_Remoting_Messaging_CallContextRemotingData"

	.byte 24,16
.LDIFF_SYM844=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM844
	.byte 2,35,0,6
	.string "_logicalCallID"

.LDIFF_SYM845=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM845
	.byte 2,35,16,0,7
	.string "System_Runtime_Remoting_Messaging_CallContextRemotingData"

.LDIFF_SYM846=.LTDIE_133 - .Ldebug_info_start
	.long .LDIFF_SYM846
.LTDIE_133_POINTER:

	.byte 13
.LDIFF_SYM847=.LTDIE_133 - .Ldebug_info_start
	.long .LDIFF_SYM847
.LTDIE_133_REFERENCE:

	.byte 14
.LDIFF_SYM848=.LTDIE_133 - .Ldebug_info_start
	.long .LDIFF_SYM848
.LTDIE_135:

	.byte 17
	.string "System_Security_Principal_IPrincipal"

	.byte 16,7
	.string "System_Security_Principal_IPrincipal"

.LDIFF_SYM849=.LTDIE_135 - .Ldebug_info_start
	.long .LDIFF_SYM849
.LTDIE_135_POINTER:

	.byte 13
.LDIFF_SYM850=.LTDIE_135 - .Ldebug_info_start
	.long .LDIFF_SYM850
.LTDIE_135_REFERENCE:

	.byte 14
.LDIFF_SYM851=.LTDIE_135 - .Ldebug_info_start
	.long .LDIFF_SYM851
.LTDIE_134:

	.byte 5
	.string "System_Runtime_Remoting_Messaging_CallContextSecurityData"

	.byte 24,16
.LDIFF_SYM852=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM852
	.byte 2,35,0,6
	.string "_principal"

.LDIFF_SYM853=.LTDIE_135_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM853
	.byte 2,35,16,0,7
	.string "System_Runtime_Remoting_Messaging_CallContextSecurityData"

.LDIFF_SYM854=.LTDIE_134 - .Ldebug_info_start
	.long .LDIFF_SYM854
.LTDIE_134_POINTER:

	.byte 13
.LDIFF_SYM855=.LTDIE_134 - .Ldebug_info_start
	.long .LDIFF_SYM855
.LTDIE_134_REFERENCE:

	.byte 14
.LDIFF_SYM856=.LTDIE_134 - .Ldebug_info_start
	.long .LDIFF_SYM856
.LTDIE_128:

	.byte 5
	.string "System_Runtime_Remoting_Messaging_LogicalCallContext"

	.byte 72,16
.LDIFF_SYM857=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM857
	.byte 2,35,0,6
	.string "m_Datastore"

.LDIFF_SYM858=.LTDIE_129_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM858
	.byte 2,35,16,6
	.string "m_RemotingData"

.LDIFF_SYM859=.LTDIE_133_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM859
	.byte 2,35,24,6
	.string "m_SecurityData"

.LDIFF_SYM860=.LTDIE_134_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM860
	.byte 2,35,32,6
	.string "m_HostContext"

.LDIFF_SYM861=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM861
	.byte 2,35,40,6
	.string "m_IsCorrelationMgr"

.LDIFF_SYM862=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM862
	.byte 2,35,64,6
	.string "_sendHeaders"

.LDIFF_SYM863=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM863
	.byte 2,35,48,6
	.string "_recvHeaders"

.LDIFF_SYM864=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM864
	.byte 2,35,56,0,7
	.string "System_Runtime_Remoting_Messaging_LogicalCallContext"

.LDIFF_SYM865=.LTDIE_128 - .Ldebug_info_start
	.long .LDIFF_SYM865
.LTDIE_128_POINTER:

	.byte 13
.LDIFF_SYM866=.LTDIE_128 - .Ldebug_info_start
	.long .LDIFF_SYM866
.LTDIE_128_REFERENCE:

	.byte 14
.LDIFF_SYM867=.LTDIE_128 - .Ldebug_info_start
	.long .LDIFF_SYM867
.LTDIE_136:

	.byte 5
	.string "System_Runtime_Remoting_Messaging_IllogicalCallContext"

	.byte 32,16
.LDIFF_SYM868=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM868
	.byte 2,35,0,6
	.string "m_Datastore"

.LDIFF_SYM869=.LTDIE_129_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM869
	.byte 2,35,16,6
	.string "m_HostContext"

.LDIFF_SYM870=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM870
	.byte 2,35,24,0,7
	.string "System_Runtime_Remoting_Messaging_IllogicalCallContext"

.LDIFF_SYM871=.LTDIE_136 - .Ldebug_info_start
	.long .LDIFF_SYM871
.LTDIE_136_POINTER:

	.byte 13
.LDIFF_SYM872=.LTDIE_136 - .Ldebug_info_start
	.long .LDIFF_SYM872
.LTDIE_136_REFERENCE:

	.byte 14
.LDIFF_SYM873=.LTDIE_136 - .Ldebug_info_start
	.long .LDIFF_SYM873
.LTDIE_137:

	.byte 8
	.string "_Flags"

	.byte 4
.LDIFF_SYM874=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM874
	.byte 9
	.string "None"

	.byte 0,9
	.string "IsNewCapture"

	.byte 1,9
	.string "IsFlowSuppressed"

	.byte 2,9
	.string "IsPreAllocatedDefault"

	.byte 4,0,7
	.string "_Flags"

.LDIFF_SYM875=.LTDIE_137 - .Ldebug_info_start
	.long .LDIFF_SYM875
.LTDIE_137_POINTER:

	.byte 13
.LDIFF_SYM876=.LTDIE_137 - .Ldebug_info_start
	.long .LDIFF_SYM876
.LTDIE_137_REFERENCE:

	.byte 14
.LDIFF_SYM877=.LTDIE_137 - .Ldebug_info_start
	.long .LDIFF_SYM877
.LTDIE_139:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM878=.LTDIE_139 - .Ldebug_info_start
	.long .LDIFF_SYM878
.LTDIE_139_POINTER:

	.byte 13
.LDIFF_SYM879=.LTDIE_139 - .Ldebug_info_start
	.long .LDIFF_SYM879
.LTDIE_139_REFERENCE:

	.byte 14
.LDIFF_SYM880=.LTDIE_139 - .Ldebug_info_start
	.long .LDIFF_SYM880
.LTDIE_140:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM881=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM881
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM882=.LTDIE_138_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM882
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM883=.LTDIE_140 - .Ldebug_info_start
	.long .LDIFF_SYM883
.LTDIE_140_POINTER:

	.byte 13
.LDIFF_SYM884=.LTDIE_140 - .Ldebug_info_start
	.long .LDIFF_SYM884
.LTDIE_140_REFERENCE:

	.byte 14
.LDIFF_SYM885=.LTDIE_140 - .Ldebug_info_start
	.long .LDIFF_SYM885
.LTDIE_141:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM886=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM886
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM887=.LTDIE_138_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM887
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM888=.LTDIE_141 - .Ldebug_info_start
	.long .LDIFF_SYM888
.LTDIE_141_POINTER:

	.byte 13
.LDIFF_SYM889=.LTDIE_141 - .Ldebug_info_start
	.long .LDIFF_SYM889
.LTDIE_141_REFERENCE:

	.byte 14
.LDIFF_SYM890=.LTDIE_141 - .Ldebug_info_start
	.long .LDIFF_SYM890
.LTDIE_138:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM891=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM891
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM892=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM892
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM893=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM893
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM894=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM894
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM895=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM895
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM896=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM896
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM897=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM897
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM898=.LTDIE_139_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM898
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM899=.LTDIE_140_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM899
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM900=.LTDIE_141_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM900
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM901=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM901
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM902=.LTDIE_138 - .Ldebug_info_start
	.long .LDIFF_SYM902
.LTDIE_138_POINTER:

	.byte 13
.LDIFF_SYM903=.LTDIE_138 - .Ldebug_info_start
	.long .LDIFF_SYM903
.LTDIE_138_REFERENCE:

	.byte 14
.LDIFF_SYM904=.LTDIE_138 - .Ldebug_info_start
	.long .LDIFF_SYM904
.LTDIE_142:

	.byte 5
	.string "System_Collections_Generic_List`1"

	.byte 40,16
.LDIFF_SYM905=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM905
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM906=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM906
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM907=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM907
	.byte 2,35,32,6
	.string "_version"

.LDIFF_SYM908=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM908
	.byte 2,35,36,6
	.string "_syncRoot"

.LDIFF_SYM909=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM909
	.byte 2,35,24,0,7
	.string "System_Collections_Generic_List`1"

.LDIFF_SYM910=.LTDIE_142 - .Ldebug_info_start
	.long .LDIFF_SYM910
.LTDIE_142_POINTER:

	.byte 13
.LDIFF_SYM911=.LTDIE_142 - .Ldebug_info_start
	.long .LDIFF_SYM911
.LTDIE_142_REFERENCE:

	.byte 14
.LDIFF_SYM912=.LTDIE_142 - .Ldebug_info_start
	.long .LDIFF_SYM912
.LTDIE_125:

	.byte 5
	.string "System_Threading_ExecutionContext"

	.byte 72,16
.LDIFF_SYM913=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM913
	.byte 2,35,0,6
	.string "_syncContext"

.LDIFF_SYM914=.LTDIE_126_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM914
	.byte 2,35,16,6
	.string "_syncContextNoFlow"

.LDIFF_SYM915=.LTDIE_126_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM915
	.byte 2,35,24,6
	.string "_logicalCallContext"

.LDIFF_SYM916=.LTDIE_128_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM916
	.byte 2,35,32,6
	.string "_illogicalCallContext"

.LDIFF_SYM917=.LTDIE_136_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM917
	.byte 2,35,40,6
	.string "_flags"

.LDIFF_SYM918=.LTDIE_137 - .Ldebug_info_start
	.long .LDIFF_SYM918
	.byte 2,35,64,6
	.string "_localValues"

.LDIFF_SYM919=.LTDIE_138_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM919
	.byte 2,35,48,6
	.string "_localChangeNotifications"

.LDIFF_SYM920=.LTDIE_142_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM920
	.byte 2,35,56,0,7
	.string "System_Threading_ExecutionContext"

.LDIFF_SYM921=.LTDIE_125 - .Ldebug_info_start
	.long .LDIFF_SYM921
.LTDIE_125_POINTER:

	.byte 13
.LDIFF_SYM922=.LTDIE_125 - .Ldebug_info_start
	.long .LDIFF_SYM922
.LTDIE_125_REFERENCE:

	.byte 14
.LDIFF_SYM923=.LTDIE_125 - .Ldebug_info_start
	.long .LDIFF_SYM923
.LTDIE_150:

	.byte 5
	.string "System_Runtime_ConstrainedExecution_CriticalFinalizerObject"

	.byte 16,16
.LDIFF_SYM924=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM924
	.byte 2,35,0,0,7
	.string "System_Runtime_ConstrainedExecution_CriticalFinalizerObject"

.LDIFF_SYM925=.LTDIE_150 - .Ldebug_info_start
	.long .LDIFF_SYM925
.LTDIE_150_POINTER:

	.byte 13
.LDIFF_SYM926=.LTDIE_150 - .Ldebug_info_start
	.long .LDIFF_SYM926
.LTDIE_150_REFERENCE:

	.byte 14
.LDIFF_SYM927=.LTDIE_150 - .Ldebug_info_start
	.long .LDIFF_SYM927
.LTDIE_149:

	.byte 5
	.string "System_Runtime_InteropServices_SafeHandle"

	.byte 32,16
.LDIFF_SYM928=.LTDIE_150 - .Ldebug_info_start
	.long .LDIFF_SYM928
	.byte 2,35,0,6
	.string "handle"

.LDIFF_SYM929=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM929
	.byte 2,35,16,6
	.string "_state"

.LDIFF_SYM930=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM930
	.byte 2,35,24,6
	.string "_ownsHandle"

.LDIFF_SYM931=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM931
	.byte 2,35,28,6
	.string "_fullyInitialized"

.LDIFF_SYM932=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM932
	.byte 2,35,29,0,7
	.string "System_Runtime_InteropServices_SafeHandle"

.LDIFF_SYM933=.LTDIE_149 - .Ldebug_info_start
	.long .LDIFF_SYM933
.LTDIE_149_POINTER:

	.byte 13
.LDIFF_SYM934=.LTDIE_149 - .Ldebug_info_start
	.long .LDIFF_SYM934
.LTDIE_149_REFERENCE:

	.byte 14
.LDIFF_SYM935=.LTDIE_149 - .Ldebug_info_start
	.long .LDIFF_SYM935
.LTDIE_148:

	.byte 5
	.string "Microsoft_Win32_SafeHandles_SafeHandleZeroOrMinusOneIsInvalid"

	.byte 32,16
.LDIFF_SYM936=.LTDIE_149 - .Ldebug_info_start
	.long .LDIFF_SYM936
	.byte 2,35,0,0,7
	.string "Microsoft_Win32_SafeHandles_SafeHandleZeroOrMinusOneIsInvalid"

.LDIFF_SYM937=.LTDIE_148 - .Ldebug_info_start
	.long .LDIFF_SYM937
.LTDIE_148_POINTER:

	.byte 13
.LDIFF_SYM938=.LTDIE_148 - .Ldebug_info_start
	.long .LDIFF_SYM938
.LTDIE_148_REFERENCE:

	.byte 14
.LDIFF_SYM939=.LTDIE_148 - .Ldebug_info_start
	.long .LDIFF_SYM939
.LTDIE_147:

	.byte 5
	.string "Microsoft_Win32_SafeHandles_SafeWaitHandle"

	.byte 32,16
.LDIFF_SYM940=.LTDIE_148 - .Ldebug_info_start
	.long .LDIFF_SYM940
	.byte 2,35,0,0,7
	.string "Microsoft_Win32_SafeHandles_SafeWaitHandle"

.LDIFF_SYM941=.LTDIE_147 - .Ldebug_info_start
	.long .LDIFF_SYM941
.LTDIE_147_POINTER:

	.byte 13
.LDIFF_SYM942=.LTDIE_147 - .Ldebug_info_start
	.long .LDIFF_SYM942
.LTDIE_147_REFERENCE:

	.byte 14
.LDIFF_SYM943=.LTDIE_147 - .Ldebug_info_start
	.long .LDIFF_SYM943
.LTDIE_146:

	.byte 5
	.string "System_Threading_WaitHandle"

	.byte 48,16
.LDIFF_SYM944=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM944
	.byte 2,35,0,6
	.string "waitHandle"

.LDIFF_SYM945=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM945
	.byte 2,35,24,6
	.string "safeWaitHandle"

.LDIFF_SYM946=.LTDIE_147_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM946
	.byte 2,35,32,6
	.string "hasThreadAffinity"

.LDIFF_SYM947=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM947
	.byte 2,35,40,0,7
	.string "System_Threading_WaitHandle"

.LDIFF_SYM948=.LTDIE_146 - .Ldebug_info_start
	.long .LDIFF_SYM948
.LTDIE_146_POINTER:

	.byte 13
.LDIFF_SYM949=.LTDIE_146 - .Ldebug_info_start
	.long .LDIFF_SYM949
.LTDIE_146_REFERENCE:

	.byte 14
.LDIFF_SYM950=.LTDIE_146 - .Ldebug_info_start
	.long .LDIFF_SYM950
.LTDIE_145:

	.byte 5
	.string "System_Threading_EventWaitHandle"

	.byte 48,16
.LDIFF_SYM951=.LTDIE_146 - .Ldebug_info_start
	.long .LDIFF_SYM951
	.byte 2,35,0,0,7
	.string "System_Threading_EventWaitHandle"

.LDIFF_SYM952=.LTDIE_145 - .Ldebug_info_start
	.long .LDIFF_SYM952
.LTDIE_145_POINTER:

	.byte 13
.LDIFF_SYM953=.LTDIE_145 - .Ldebug_info_start
	.long .LDIFF_SYM953
.LTDIE_145_REFERENCE:

	.byte 14
.LDIFF_SYM954=.LTDIE_145 - .Ldebug_info_start
	.long .LDIFF_SYM954
.LTDIE_144:

	.byte 5
	.string "System_Threading_ManualResetEvent"

	.byte 48,16
.LDIFF_SYM955=.LTDIE_145 - .Ldebug_info_start
	.long .LDIFF_SYM955
	.byte 2,35,0,0,7
	.string "System_Threading_ManualResetEvent"

.LDIFF_SYM956=.LTDIE_144 - .Ldebug_info_start
	.long .LDIFF_SYM956
.LTDIE_144_POINTER:

	.byte 13
.LDIFF_SYM957=.LTDIE_144 - .Ldebug_info_start
	.long .LDIFF_SYM957
.LTDIE_144_REFERENCE:

	.byte 14
.LDIFF_SYM958=.LTDIE_144 - .Ldebug_info_start
	.long .LDIFF_SYM958
.LTDIE_143:

	.byte 5
	.string "System_Threading_ManualResetEventSlim"

	.byte 40,16
.LDIFF_SYM959=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM959
	.byte 2,35,0,6
	.string "m_lock"

.LDIFF_SYM960=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM960
	.byte 2,35,16,6
	.string "m_eventObj"

.LDIFF_SYM961=.LTDIE_144_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM961
	.byte 2,35,24,6
	.string "m_combinedState"

.LDIFF_SYM962=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM962
	.byte 2,35,32,0,7
	.string "System_Threading_ManualResetEventSlim"

.LDIFF_SYM963=.LTDIE_143 - .Ldebug_info_start
	.long .LDIFF_SYM963
.LTDIE_143_POINTER:

	.byte 13
.LDIFF_SYM964=.LTDIE_143 - .Ldebug_info_start
	.long .LDIFF_SYM964
.LTDIE_143_REFERENCE:

	.byte 14
.LDIFF_SYM965=.LTDIE_143 - .Ldebug_info_start
	.long .LDIFF_SYM965
.LTDIE_153:

	.byte 5
	.string "System_Collections_Generic_LowLevelList`1"

	.byte 32,16
.LDIFF_SYM966=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM966
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM967=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM967
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM968=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM968
	.byte 2,35,24,6
	.string "_version"

.LDIFF_SYM969=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM969
	.byte 2,35,28,0,7
	.string "System_Collections_Generic_LowLevelList`1"

.LDIFF_SYM970=.LTDIE_153 - .Ldebug_info_start
	.long .LDIFF_SYM970
.LTDIE_153_POINTER:

	.byte 13
.LDIFF_SYM971=.LTDIE_153 - .Ldebug_info_start
	.long .LDIFF_SYM971
.LTDIE_153_REFERENCE:

	.byte 14
.LDIFF_SYM972=.LTDIE_153 - .Ldebug_info_start
	.long .LDIFF_SYM972
.LTDIE_152:

	.byte 5
	.string "System_Collections_Generic_LowLevelListWithIList`1"

	.byte 32,16
.LDIFF_SYM973=.LTDIE_153 - .Ldebug_info_start
	.long .LDIFF_SYM973
	.byte 2,35,0,0,7
	.string "System_Collections_Generic_LowLevelListWithIList`1"

.LDIFF_SYM974=.LTDIE_152 - .Ldebug_info_start
	.long .LDIFF_SYM974
.LTDIE_152_POINTER:

	.byte 13
.LDIFF_SYM975=.LTDIE_152 - .Ldebug_info_start
	.long .LDIFF_SYM975
.LTDIE_152_REFERENCE:

	.byte 14
.LDIFF_SYM976=.LTDIE_152 - .Ldebug_info_start
	.long .LDIFF_SYM976
.LTDIE_156:

	.byte 17
	.string "System_Collections_IDictionary"

	.byte 16,7
	.string "System_Collections_IDictionary"

.LDIFF_SYM977=.LTDIE_156 - .Ldebug_info_start
	.long .LDIFF_SYM977
.LTDIE_156_POINTER:

	.byte 13
.LDIFF_SYM978=.LTDIE_156 - .Ldebug_info_start
	.long .LDIFF_SYM978
.LTDIE_156_REFERENCE:

	.byte 14
.LDIFF_SYM979=.LTDIE_156 - .Ldebug_info_start
	.long .LDIFF_SYM979
.LTDIE_158:

	.byte 17
	.string "System_Collections_Generic_IList`1"

	.byte 16,7
	.string "System_Collections_Generic_IList`1"

.LDIFF_SYM980=.LTDIE_158 - .Ldebug_info_start
	.long .LDIFF_SYM980
.LTDIE_158_POINTER:

	.byte 13
.LDIFF_SYM981=.LTDIE_158 - .Ldebug_info_start
	.long .LDIFF_SYM981
.LTDIE_158_REFERENCE:

	.byte 14
.LDIFF_SYM982=.LTDIE_158 - .Ldebug_info_start
	.long .LDIFF_SYM982
.LTDIE_161:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM983=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM983
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM984=.LTDIE_160_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM984
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM985=.LTDIE_161 - .Ldebug_info_start
	.long .LDIFF_SYM985
.LTDIE_161_POINTER:

	.byte 13
.LDIFF_SYM986=.LTDIE_161 - .Ldebug_info_start
	.long .LDIFF_SYM986
.LTDIE_161_REFERENCE:

	.byte 14
.LDIFF_SYM987=.LTDIE_161 - .Ldebug_info_start
	.long .LDIFF_SYM987
.LTDIE_162:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM988=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM988
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM989=.LTDIE_160_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM989
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM990=.LTDIE_162 - .Ldebug_info_start
	.long .LDIFF_SYM990
.LTDIE_162_POINTER:

	.byte 13
.LDIFF_SYM991=.LTDIE_162 - .Ldebug_info_start
	.long .LDIFF_SYM991
.LTDIE_162_REFERENCE:

	.byte 14
.LDIFF_SYM992=.LTDIE_162 - .Ldebug_info_start
	.long .LDIFF_SYM992
.LTDIE_160:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM993=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM993
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM994=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM994
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM995=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM995
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM996=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM996
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM997=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM997
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM998=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM998
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM999=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM999
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1000=.LTDIE_111_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1000
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1001=.LTDIE_161_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1001
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1002=.LTDIE_162_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1002
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1003=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1003
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1004=.LTDIE_160 - .Ldebug_info_start
	.long .LDIFF_SYM1004
.LTDIE_160_POINTER:

	.byte 13
.LDIFF_SYM1005=.LTDIE_160 - .Ldebug_info_start
	.long .LDIFF_SYM1005
.LTDIE_160_REFERENCE:

	.byte 14
.LDIFF_SYM1006=.LTDIE_160 - .Ldebug_info_start
	.long .LDIFF_SYM1006
.LTDIE_163:

	.byte 17
	.string "System_Runtime_Serialization_IFormatterConverter"

	.byte 16,7
	.string "System_Runtime_Serialization_IFormatterConverter"

.LDIFF_SYM1007=.LTDIE_163 - .Ldebug_info_start
	.long .LDIFF_SYM1007
.LTDIE_163_POINTER:

	.byte 13
.LDIFF_SYM1008=.LTDIE_163 - .Ldebug_info_start
	.long .LDIFF_SYM1008
.LTDIE_163_REFERENCE:

	.byte 14
.LDIFF_SYM1009=.LTDIE_163 - .Ldebug_info_start
	.long .LDIFF_SYM1009
.LTDIE_159:

	.byte 5
	.string "System_Runtime_Serialization_SerializationInfo"

	.byte 88,16
.LDIFF_SYM1010=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1010
	.byte 2,35,0,6
	.string "m_members"

.LDIFF_SYM1011=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1011
	.byte 2,35,16,6
	.string "m_data"

.LDIFF_SYM1012=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1012
	.byte 2,35,24,6
	.string "m_types"

.LDIFF_SYM1013=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1013
	.byte 2,35,32,6
	.string "m_nameToIndex"

.LDIFF_SYM1014=.LTDIE_160_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1014
	.byte 2,35,40,6
	.string "m_currMember"

.LDIFF_SYM1015=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1015
	.byte 2,35,80,6
	.string "m_converter"

.LDIFF_SYM1016=.LTDIE_163_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1016
	.byte 2,35,48,6
	.string "m_fullTypeName"

.LDIFF_SYM1017=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1017
	.byte 2,35,56,6
	.string "m_assemName"

.LDIFF_SYM1018=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1018
	.byte 2,35,64,6
	.string "objectType"

.LDIFF_SYM1019=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1019
	.byte 2,35,72,6
	.string "isFullTypeNameSetExplicit"

.LDIFF_SYM1020=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1020
	.byte 2,35,84,6
	.string "isAssemblyNameSetExplicit"

.LDIFF_SYM1021=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1021
	.byte 2,35,85,6
	.string "requireSameTokenInPartialTrust"

.LDIFF_SYM1022=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1022
	.byte 2,35,86,0,7
	.string "System_Runtime_Serialization_SerializationInfo"

.LDIFF_SYM1023=.LTDIE_159 - .Ldebug_info_start
	.long .LDIFF_SYM1023
.LTDIE_159_POINTER:

	.byte 13
.LDIFF_SYM1024=.LTDIE_159 - .Ldebug_info_start
	.long .LDIFF_SYM1024
.LTDIE_159_REFERENCE:

	.byte 14
.LDIFF_SYM1025=.LTDIE_159 - .Ldebug_info_start
	.long .LDIFF_SYM1025
.LTDIE_165:

	.byte 5
	.string "System_Reflection_TypeInfo"

	.byte 24,16
.LDIFF_SYM1026=.LTDIE_41 - .Ldebug_info_start
	.long .LDIFF_SYM1026
	.byte 2,35,0,0,7
	.string "System_Reflection_TypeInfo"

.LDIFF_SYM1027=.LTDIE_165 - .Ldebug_info_start
	.long .LDIFF_SYM1027
.LTDIE_165_POINTER:

	.byte 13
.LDIFF_SYM1028=.LTDIE_165 - .Ldebug_info_start
	.long .LDIFF_SYM1028
.LTDIE_165_REFERENCE:

	.byte 14
.LDIFF_SYM1029=.LTDIE_165 - .Ldebug_info_start
	.long .LDIFF_SYM1029
.LTDIE_168:

	.byte 5
	.string "System_Reflection_ConstructorInfo"

	.byte 16,16
.LDIFF_SYM1030=.LTDIE_38 - .Ldebug_info_start
	.long .LDIFF_SYM1030
	.byte 2,35,0,0,7
	.string "System_Reflection_ConstructorInfo"

.LDIFF_SYM1031=.LTDIE_168 - .Ldebug_info_start
	.long .LDIFF_SYM1031
.LTDIE_168_POINTER:

	.byte 13
.LDIFF_SYM1032=.LTDIE_168 - .Ldebug_info_start
	.long .LDIFF_SYM1032
.LTDIE_168_REFERENCE:

	.byte 14
.LDIFF_SYM1033=.LTDIE_168 - .Ldebug_info_start
	.long .LDIFF_SYM1033
.LTDIE_167:

	.byte 5
	.string "System_Reflection_RuntimeConstructorInfo"

	.byte 40,16
.LDIFF_SYM1034=.LTDIE_168 - .Ldebug_info_start
	.long .LDIFF_SYM1034
	.byte 2,35,0,6
	.string "mhandle"

.LDIFF_SYM1035=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM1035
	.byte 2,35,16,6
	.string "name"

.LDIFF_SYM1036=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1036
	.byte 2,35,24,6
	.string "reftype"

.LDIFF_SYM1037=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1037
	.byte 2,35,32,0,7
	.string "System_Reflection_RuntimeConstructorInfo"

.LDIFF_SYM1038=.LTDIE_167 - .Ldebug_info_start
	.long .LDIFF_SYM1038
.LTDIE_167_POINTER:

	.byte 13
.LDIFF_SYM1039=.LTDIE_167 - .Ldebug_info_start
	.long .LDIFF_SYM1039
.LTDIE_167_REFERENCE:

	.byte 14
.LDIFF_SYM1040=.LTDIE_167 - .Ldebug_info_start
	.long .LDIFF_SYM1040
.LTDIE_166:

	.byte 5
	.string "System_MonoTypeInfo"

	.byte 32,16
.LDIFF_SYM1041=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1041
	.byte 2,35,0,6
	.string "full_name"

.LDIFF_SYM1042=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1042
	.byte 2,35,16,6
	.string "default_ctor"

.LDIFF_SYM1043=.LTDIE_167_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1043
	.byte 2,35,24,0,7
	.string "System_MonoTypeInfo"

.LDIFF_SYM1044=.LTDIE_166 - .Ldebug_info_start
	.long .LDIFF_SYM1044
.LTDIE_166_POINTER:

	.byte 13
.LDIFF_SYM1045=.LTDIE_166 - .Ldebug_info_start
	.long .LDIFF_SYM1045
.LTDIE_166_REFERENCE:

	.byte 14
.LDIFF_SYM1046=.LTDIE_166 - .Ldebug_info_start
	.long .LDIFF_SYM1046
.LTDIE_164:

	.byte 5
	.string "System_RuntimeType"

	.byte 48,16
.LDIFF_SYM1047=.LTDIE_165 - .Ldebug_info_start
	.long .LDIFF_SYM1047
	.byte 2,35,0,6
	.string "type_info"

.LDIFF_SYM1048=.LTDIE_166_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1048
	.byte 2,35,24,6
	.string "GenericCache"

.LDIFF_SYM1049=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1049
	.byte 2,35,32,6
	.string "m_serializationCtor"

.LDIFF_SYM1050=.LTDIE_167_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1050
	.byte 2,35,40,0,7
	.string "System_RuntimeType"

.LDIFF_SYM1051=.LTDIE_164 - .Ldebug_info_start
	.long .LDIFF_SYM1051
.LTDIE_164_POINTER:

	.byte 13
.LDIFF_SYM1052=.LTDIE_164 - .Ldebug_info_start
	.long .LDIFF_SYM1052
.LTDIE_164_REFERENCE:

	.byte 14
.LDIFF_SYM1053=.LTDIE_164 - .Ldebug_info_start
	.long .LDIFF_SYM1053
.LTDIE_169:

	.byte 5
	.string "System_EventHandler`1"

	.byte 128,1,16
.LDIFF_SYM1054=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM1054
	.byte 2,35,0,0,7
	.string "System_EventHandler`1"

.LDIFF_SYM1055=.LTDIE_169 - .Ldebug_info_start
	.long .LDIFF_SYM1055
.LTDIE_169_POINTER:

	.byte 13
.LDIFF_SYM1056=.LTDIE_169 - .Ldebug_info_start
	.long .LDIFF_SYM1056
.LTDIE_169_REFERENCE:

	.byte 14
.LDIFF_SYM1057=.LTDIE_169 - .Ldebug_info_start
	.long .LDIFF_SYM1057
.LTDIE_157:

	.byte 5
	.string "System_Runtime_Serialization_SafeSerializationManager"

	.byte 56,16
.LDIFF_SYM1058=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1058
	.byte 2,35,0,6
	.string "m_serializedStates"

.LDIFF_SYM1059=.LTDIE_158_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1059
	.byte 2,35,16,6
	.string "m_savedSerializationInfo"

.LDIFF_SYM1060=.LTDIE_159_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1060
	.byte 2,35,24,6
	.string "m_realObject"

.LDIFF_SYM1061=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1061
	.byte 2,35,32,6
	.string "m_realType"

.LDIFF_SYM1062=.LTDIE_164_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1062
	.byte 2,35,40,6
	.string "SerializeObjectState"

.LDIFF_SYM1063=.LTDIE_169_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1063
	.byte 2,35,48,0,7
	.string "System_Runtime_Serialization_SafeSerializationManager"

.LDIFF_SYM1064=.LTDIE_157 - .Ldebug_info_start
	.long .LDIFF_SYM1064
.LTDIE_157_POINTER:

	.byte 13
.LDIFF_SYM1065=.LTDIE_157 - .Ldebug_info_start
	.long .LDIFF_SYM1065
.LTDIE_157_REFERENCE:

	.byte 14
.LDIFF_SYM1066=.LTDIE_157 - .Ldebug_info_start
	.long .LDIFF_SYM1066
.LTDIE_155:

	.byte 5
	.string "System_Exception"

	.byte 144,1,16
.LDIFF_SYM1067=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1067
	.byte 2,35,0,6
	.string "_className"

.LDIFF_SYM1068=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1068
	.byte 2,35,16,6
	.string "_message"

.LDIFF_SYM1069=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1069
	.byte 2,35,24,6
	.string "_data"

.LDIFF_SYM1070=.LTDIE_156_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1070
	.byte 2,35,32,6
	.string "_innerException"

.LDIFF_SYM1071=.LTDIE_155_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1071
	.byte 2,35,40,6
	.string "_helpURL"

.LDIFF_SYM1072=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1072
	.byte 2,35,48,6
	.string "_stackTrace"

.LDIFF_SYM1073=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1073
	.byte 2,35,56,6
	.string "_stackTraceString"

.LDIFF_SYM1074=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1074
	.byte 2,35,64,6
	.string "_remoteStackTraceString"

.LDIFF_SYM1075=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1075
	.byte 2,35,72,6
	.string "_remoteStackIndex"

.LDIFF_SYM1076=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1076
	.byte 2,35,80,6
	.string "_dynamicMethods"

.LDIFF_SYM1077=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1077
	.byte 2,35,88,6
	.string "_HResult"

.LDIFF_SYM1078=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1078
	.byte 2,35,96,6
	.string "_source"

.LDIFF_SYM1079=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1079
	.byte 2,35,104,6
	.string "_safeSerializationManager"

.LDIFF_SYM1080=.LTDIE_157_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1080
	.byte 2,35,112,6
	.string "captured_traces"

.LDIFF_SYM1081=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1081
	.byte 2,35,120,6
	.string "native_trace_ips"

.LDIFF_SYM1082=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1082
	.byte 3,35,128,1,6
	.string "caught_in_unmanaged"

.LDIFF_SYM1083=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1083
	.byte 3,35,136,1,0,7
	.string "System_Exception"

.LDIFF_SYM1084=.LTDIE_155 - .Ldebug_info_start
	.long .LDIFF_SYM1084
.LTDIE_155_POINTER:

	.byte 13
.LDIFF_SYM1085=.LTDIE_155 - .Ldebug_info_start
	.long .LDIFF_SYM1085
.LTDIE_155_REFERENCE:

	.byte 14
.LDIFF_SYM1086=.LTDIE_155 - .Ldebug_info_start
	.long .LDIFF_SYM1086
.LTDIE_154:

	.byte 5
	.string "System_Runtime_ExceptionServices_ExceptionDispatchInfo"

	.byte 32,16
.LDIFF_SYM1087=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1087
	.byte 2,35,0,6
	.string "m_Exception"

.LDIFF_SYM1088=.LTDIE_155_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1088
	.byte 2,35,16,6
	.string "m_stackTrace"

.LDIFF_SYM1089=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1089
	.byte 2,35,24,0,7
	.string "System_Runtime_ExceptionServices_ExceptionDispatchInfo"

.LDIFF_SYM1090=.LTDIE_154 - .Ldebug_info_start
	.long .LDIFF_SYM1090
.LTDIE_154_POINTER:

	.byte 13
.LDIFF_SYM1091=.LTDIE_154 - .Ldebug_info_start
	.long .LDIFF_SYM1091
.LTDIE_154_REFERENCE:

	.byte 14
.LDIFF_SYM1092=.LTDIE_154 - .Ldebug_info_start
	.long .LDIFF_SYM1092
.LTDIE_151:

	.byte 5
	.string "System_Threading_Tasks_TaskExceptionHolder"

	.byte 48,16
.LDIFF_SYM1093=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1093
	.byte 2,35,0,6
	.string "m_task"

.LDIFF_SYM1094=.LTDIE_122_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1094
	.byte 2,35,16,6
	.string "m_faultExceptions"

.LDIFF_SYM1095=.LTDIE_152_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1095
	.byte 2,35,24,6
	.string "m_cancellationException"

.LDIFF_SYM1096=.LTDIE_154_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1096
	.byte 2,35,32,6
	.string "m_isHandled"

.LDIFF_SYM1097=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1097
	.byte 2,35,40,0,7
	.string "System_Threading_Tasks_TaskExceptionHolder"

.LDIFF_SYM1098=.LTDIE_151 - .Ldebug_info_start
	.long .LDIFF_SYM1098
.LTDIE_151_POINTER:

	.byte 13
.LDIFF_SYM1099=.LTDIE_151 - .Ldebug_info_start
	.long .LDIFF_SYM1099
.LTDIE_151_REFERENCE:

	.byte 14
.LDIFF_SYM1100=.LTDIE_151 - .Ldebug_info_start
	.long .LDIFF_SYM1100
.LTDIE_171:

	.byte 5
	.string "System_Collections_Generic_LowLevelList`1"

	.byte 32,16
.LDIFF_SYM1101=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1101
	.byte 2,35,0,6
	.string "_items"

.LDIFF_SYM1102=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1102
	.byte 2,35,16,6
	.string "_size"

.LDIFF_SYM1103=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1103
	.byte 2,35,24,6
	.string "_version"

.LDIFF_SYM1104=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1104
	.byte 2,35,28,0,7
	.string "System_Collections_Generic_LowLevelList`1"

.LDIFF_SYM1105=.LTDIE_171 - .Ldebug_info_start
	.long .LDIFF_SYM1105
.LTDIE_171_POINTER:

	.byte 13
.LDIFF_SYM1106=.LTDIE_171 - .Ldebug_info_start
	.long .LDIFF_SYM1106
.LTDIE_171_REFERENCE:

	.byte 14
.LDIFF_SYM1107=.LTDIE_171 - .Ldebug_info_start
	.long .LDIFF_SYM1107
.LTDIE_170:

	.byte 5
	.string "System_Collections_Generic_LowLevelListWithIList`1"

	.byte 32,16
.LDIFF_SYM1108=.LTDIE_171 - .Ldebug_info_start
	.long .LDIFF_SYM1108
	.byte 2,35,0,0,7
	.string "System_Collections_Generic_LowLevelListWithIList`1"

.LDIFF_SYM1109=.LTDIE_170 - .Ldebug_info_start
	.long .LDIFF_SYM1109
.LTDIE_170_POINTER:

	.byte 13
.LDIFF_SYM1110=.LTDIE_170 - .Ldebug_info_start
	.long .LDIFF_SYM1110
.LTDIE_170_REFERENCE:

	.byte 14
.LDIFF_SYM1111=.LTDIE_170 - .Ldebug_info_start
	.long .LDIFF_SYM1111
.LTDIE_124:

	.byte 5
	.string "_ContingentProperties"

	.byte 72,16
.LDIFF_SYM1112=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1112
	.byte 2,35,0,6
	.string "m_capturedContext"

.LDIFF_SYM1113=.LTDIE_125_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1113
	.byte 2,35,16,6
	.string "m_completionEvent"

.LDIFF_SYM1114=.LTDIE_143_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1114
	.byte 2,35,24,6
	.string "m_exceptionsHolder"

.LDIFF_SYM1115=.LTDIE_151_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1115
	.byte 2,35,32,6
	.string "m_cancellationToken"

.LDIFF_SYM1116=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1116
	.byte 2,35,40,6
	.string "m_cancellationRegistration"

.LDIFF_SYM1117=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1117
	.byte 2,35,48,6
	.string "m_internalCancellationRequested"

.LDIFF_SYM1118=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1118
	.byte 2,35,64,6
	.string "m_completionCountdown"

.LDIFF_SYM1119=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1119
	.byte 2,35,68,6
	.string "m_exceptionalChildren"

.LDIFF_SYM1120=.LTDIE_170_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1120
	.byte 2,35,56,0,7
	.string "_ContingentProperties"

.LDIFF_SYM1121=.LTDIE_124 - .Ldebug_info_start
	.long .LDIFF_SYM1121
.LTDIE_124_POINTER:

	.byte 13
.LDIFF_SYM1122=.LTDIE_124 - .Ldebug_info_start
	.long .LDIFF_SYM1122
.LTDIE_124_REFERENCE:

	.byte 14
.LDIFF_SYM1123=.LTDIE_124 - .Ldebug_info_start
	.long .LDIFF_SYM1123
.LTDIE_122:

	.byte 5
	.string "System_Threading_Tasks_Task"

	.byte 72,16
.LDIFF_SYM1124=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1124
	.byte 2,35,0,6
	.string "m_taskId"

.LDIFF_SYM1125=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1125
	.byte 2,35,64,6
	.string "m_action"

.LDIFF_SYM1126=.LTDIE_36_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1126
	.byte 2,35,16,6
	.string "m_stateObject"

.LDIFF_SYM1127=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1127
	.byte 2,35,24,6
	.string "m_taskScheduler"

.LDIFF_SYM1128=.LTDIE_123_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1128
	.byte 2,35,32,6
	.string "m_parent"

.LDIFF_SYM1129=.LTDIE_122_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1129
	.byte 2,35,40,6
	.string "m_stateFlags"

.LDIFF_SYM1130=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1130
	.byte 2,35,68,6
	.string "m_continuationObject"

.LDIFF_SYM1131=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1131
	.byte 2,35,48,6
	.string "m_contingentProperties"

.LDIFF_SYM1132=.LTDIE_124_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1132
	.byte 2,35,56,0,7
	.string "System_Threading_Tasks_Task"

.LDIFF_SYM1133=.LTDIE_122 - .Ldebug_info_start
	.long .LDIFF_SYM1133
.LTDIE_122_POINTER:

	.byte 13
.LDIFF_SYM1134=.LTDIE_122 - .Ldebug_info_start
	.long .LDIFF_SYM1134
.LTDIE_122_REFERENCE:

	.byte 14
.LDIFF_SYM1135=.LTDIE_122 - .Ldebug_info_start
	.long .LDIFF_SYM1135
.LTDIE_121:

	.byte 5
	.string "System_Threading_Tasks_Task`1"

	.byte 80,16
.LDIFF_SYM1136=.LTDIE_122 - .Ldebug_info_start
	.long .LDIFF_SYM1136
	.byte 2,35,0,6
	.string "m_result"

.LDIFF_SYM1137=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1137
	.byte 2,35,72,0,7
	.string "System_Threading_Tasks_Task`1"

.LDIFF_SYM1138=.LTDIE_121 - .Ldebug_info_start
	.long .LDIFF_SYM1138
.LTDIE_121_POINTER:

	.byte 13
.LDIFF_SYM1139=.LTDIE_121 - .Ldebug_info_start
	.long .LDIFF_SYM1139
.LTDIE_121_REFERENCE:

	.byte 14
.LDIFF_SYM1140=.LTDIE_121 - .Ldebug_info_start
	.long .LDIFF_SYM1140
.LTDIE_172:

	.byte 5
	.string "System_AsyncCallback"

	.byte 128,1,16
.LDIFF_SYM1141=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM1141
	.byte 2,35,0,0,7
	.string "System_AsyncCallback"

.LDIFF_SYM1142=.LTDIE_172 - .Ldebug_info_start
	.long .LDIFF_SYM1142
.LTDIE_172_POINTER:

	.byte 13
.LDIFF_SYM1143=.LTDIE_172 - .Ldebug_info_start
	.long .LDIFF_SYM1143
.LTDIE_172_REFERENCE:

	.byte 14
.LDIFF_SYM1144=.LTDIE_172 - .Ldebug_info_start
	.long .LDIFF_SYM1144
.LTDIE_120:

	.byte 5
	.string "_ReadWriteTask"

	.byte 128,1,16
.LDIFF_SYM1145=.LTDIE_121 - .Ldebug_info_start
	.long .LDIFF_SYM1145
	.byte 2,35,0,6
	.string "_isRead"

.LDIFF_SYM1146=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1146
	.byte 2,35,112,6
	.string "_apm"

.LDIFF_SYM1147=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1147
	.byte 2,35,113,6
	.string "_stream"

.LDIFF_SYM1148=.LTDIE_93_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1148
	.byte 2,35,80,6
	.string "_buffer"

.LDIFF_SYM1149=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1149
	.byte 2,35,88,6
	.string "_offset"

.LDIFF_SYM1150=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1150
	.byte 2,35,116,6
	.string "_count"

.LDIFF_SYM1151=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1151
	.byte 2,35,120,6
	.string "_callback"

.LDIFF_SYM1152=.LTDIE_172_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1152
	.byte 2,35,96,6
	.string "_context"

.LDIFF_SYM1153=.LTDIE_125_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1153
	.byte 2,35,104,0,7
	.string "_ReadWriteTask"

.LDIFF_SYM1154=.LTDIE_120 - .Ldebug_info_start
	.long .LDIFF_SYM1154
.LTDIE_120_POINTER:

	.byte 13
.LDIFF_SYM1155=.LTDIE_120 - .Ldebug_info_start
	.long .LDIFF_SYM1155
.LTDIE_120_REFERENCE:

	.byte 14
.LDIFF_SYM1156=.LTDIE_120 - .Ldebug_info_start
	.long .LDIFF_SYM1156
.LTDIE_175:

	.byte 5
	.string "System_Threading_Tasks_Task`1"

	.byte 80,16
.LDIFF_SYM1157=.LTDIE_122 - .Ldebug_info_start
	.long .LDIFF_SYM1157
	.byte 2,35,0,6
	.string "m_result"

.LDIFF_SYM1158=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1158
	.byte 2,35,72,0,7
	.string "System_Threading_Tasks_Task`1"

.LDIFF_SYM1159=.LTDIE_175 - .Ldebug_info_start
	.long .LDIFF_SYM1159
.LTDIE_175_POINTER:

	.byte 13
.LDIFF_SYM1160=.LTDIE_175 - .Ldebug_info_start
	.long .LDIFF_SYM1160
.LTDIE_175_REFERENCE:

	.byte 14
.LDIFF_SYM1161=.LTDIE_175 - .Ldebug_info_start
	.long .LDIFF_SYM1161
.LTDIE_174:

	.byte 5
	.string "_TaskNode"

	.byte 96,16
.LDIFF_SYM1162=.LTDIE_175 - .Ldebug_info_start
	.long .LDIFF_SYM1162
	.byte 2,35,0,6
	.string "Prev"

.LDIFF_SYM1163=.LTDIE_174_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1163
	.byte 2,35,80,6
	.string "Next"

.LDIFF_SYM1164=.LTDIE_174_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1164
	.byte 2,35,88,0,7
	.string "_TaskNode"

.LDIFF_SYM1165=.LTDIE_174 - .Ldebug_info_start
	.long .LDIFF_SYM1165
.LTDIE_174_POINTER:

	.byte 13
.LDIFF_SYM1166=.LTDIE_174 - .Ldebug_info_start
	.long .LDIFF_SYM1166
.LTDIE_174_REFERENCE:

	.byte 14
.LDIFF_SYM1167=.LTDIE_174 - .Ldebug_info_start
	.long .LDIFF_SYM1167
.LTDIE_173:

	.byte 5
	.string "System_Threading_SemaphoreSlim"

	.byte 64,16
.LDIFF_SYM1168=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1168
	.byte 2,35,0,6
	.string "m_currentCount"

.LDIFF_SYM1169=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1169
	.byte 2,35,48,6
	.string "m_maxCount"

.LDIFF_SYM1170=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1170
	.byte 2,35,52,6
	.string "m_waitCount"

.LDIFF_SYM1171=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1171
	.byte 2,35,56,6
	.string "m_lockObj"

.LDIFF_SYM1172=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1172
	.byte 2,35,16,6
	.string "m_waitHandle"

.LDIFF_SYM1173=.LTDIE_144_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1173
	.byte 2,35,24,6
	.string "m_asyncHead"

.LDIFF_SYM1174=.LTDIE_174_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1174
	.byte 2,35,32,6
	.string "m_asyncTail"

.LDIFF_SYM1175=.LTDIE_174_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1175
	.byte 2,35,40,0,7
	.string "System_Threading_SemaphoreSlim"

.LDIFF_SYM1176=.LTDIE_173 - .Ldebug_info_start
	.long .LDIFF_SYM1176
.LTDIE_173_POINTER:

	.byte 13
.LDIFF_SYM1177=.LTDIE_173 - .Ldebug_info_start
	.long .LDIFF_SYM1177
.LTDIE_173_REFERENCE:

	.byte 14
.LDIFF_SYM1178=.LTDIE_173 - .Ldebug_info_start
	.long .LDIFF_SYM1178
.LTDIE_93:

	.byte 5
	.string "System_IO_Stream"

	.byte 40,16
.LDIFF_SYM1179=.LTDIE_94 - .Ldebug_info_start
	.long .LDIFF_SYM1179
	.byte 2,35,0,6
	.string "_activeReadWriteTask"

.LDIFF_SYM1180=.LTDIE_120_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1180
	.byte 2,35,24,6
	.string "_asyncActiveSemaphore"

.LDIFF_SYM1181=.LTDIE_173_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1181
	.byte 2,35,32,0,7
	.string "System_IO_Stream"

.LDIFF_SYM1182=.LTDIE_93 - .Ldebug_info_start
	.long .LDIFF_SYM1182
.LTDIE_93_POINTER:

	.byte 13
.LDIFF_SYM1183=.LTDIE_93 - .Ldebug_info_start
	.long .LDIFF_SYM1183
.LTDIE_93_REFERENCE:

	.byte 14
.LDIFF_SYM1184=.LTDIE_93 - .Ldebug_info_start
	.long .LDIFF_SYM1184
.LTDIE_177:

	.byte 5
	.string "System_Text_DecoderFallback"

	.byte 16,16
.LDIFF_SYM1185=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1185
	.byte 2,35,0,0,7
	.string "System_Text_DecoderFallback"

.LDIFF_SYM1186=.LTDIE_177 - .Ldebug_info_start
	.long .LDIFF_SYM1186
.LTDIE_177_POINTER:

	.byte 13
.LDIFF_SYM1187=.LTDIE_177 - .Ldebug_info_start
	.long .LDIFF_SYM1187
.LTDIE_177_REFERENCE:

	.byte 14
.LDIFF_SYM1188=.LTDIE_177 - .Ldebug_info_start
	.long .LDIFF_SYM1188
.LTDIE_178:

	.byte 5
	.string "System_Text_DecoderFallbackBuffer"

	.byte 32,16
.LDIFF_SYM1189=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1189
	.byte 2,35,0,6
	.string "byteStart"

.LDIFF_SYM1190=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM1190
	.byte 2,35,16,6
	.string "charEnd"

.LDIFF_SYM1191=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM1191
	.byte 2,35,24,0,7
	.string "System_Text_DecoderFallbackBuffer"

.LDIFF_SYM1192=.LTDIE_178 - .Ldebug_info_start
	.long .LDIFF_SYM1192
.LTDIE_178_POINTER:

	.byte 13
.LDIFF_SYM1193=.LTDIE_178 - .Ldebug_info_start
	.long .LDIFF_SYM1193
.LTDIE_178_REFERENCE:

	.byte 14
.LDIFF_SYM1194=.LTDIE_178 - .Ldebug_info_start
	.long .LDIFF_SYM1194
.LTDIE_176:

	.byte 5
	.string "System_Text_Decoder"

	.byte 32,16
.LDIFF_SYM1195=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1195
	.byte 2,35,0,6
	.string "_fallback"

.LDIFF_SYM1196=.LTDIE_177_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1196
	.byte 2,35,16,6
	.string "_fallbackBuffer"

.LDIFF_SYM1197=.LTDIE_178_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1197
	.byte 2,35,24,0,7
	.string "System_Text_Decoder"

.LDIFF_SYM1198=.LTDIE_176 - .Ldebug_info_start
	.long .LDIFF_SYM1198
.LTDIE_176_POINTER:

	.byte 13
.LDIFF_SYM1199=.LTDIE_176 - .Ldebug_info_start
	.long .LDIFF_SYM1199
.LTDIE_176_REFERENCE:

	.byte 14
.LDIFF_SYM1200=.LTDIE_176 - .Ldebug_info_start
	.long .LDIFF_SYM1200
.LTDIE_92:

	.byte 5
	.string "System_IO_BinaryReader"

	.byte 72,16
.LDIFF_SYM1201=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1201
	.byte 2,35,0,6
	.string "m_stream"

.LDIFF_SYM1202=.LTDIE_93_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1202
	.byte 2,35,16,6
	.string "m_buffer"

.LDIFF_SYM1203=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1203
	.byte 2,35,24,6
	.string "m_decoder"

.LDIFF_SYM1204=.LTDIE_176_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1204
	.byte 2,35,32,6
	.string "m_charBytes"

.LDIFF_SYM1205=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1205
	.byte 2,35,40,6
	.string "m_singleChar"

.LDIFF_SYM1206=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1206
	.byte 2,35,48,6
	.string "m_charBuffer"

.LDIFF_SYM1207=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1207
	.byte 2,35,56,6
	.string "m_maxCharsSize"

.LDIFF_SYM1208=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1208
	.byte 2,35,64,6
	.string "m_2BytesPerChar"

.LDIFF_SYM1209=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1209
	.byte 2,35,68,6
	.string "m_isMemoryStream"

.LDIFF_SYM1210=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1210
	.byte 2,35,69,6
	.string "m_leaveOpen"

.LDIFF_SYM1211=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1211
	.byte 2,35,70,0,7
	.string "System_IO_BinaryReader"

.LDIFF_SYM1212=.LTDIE_92 - .Ldebug_info_start
	.long .LDIFF_SYM1212
.LTDIE_92_POINTER:

	.byte 13
.LDIFF_SYM1213=.LTDIE_92 - .Ldebug_info_start
	.long .LDIFF_SYM1213
.LTDIE_92_REFERENCE:

	.byte 14
.LDIFF_SYM1214=.LTDIE_92 - .Ldebug_info_start
	.long .LDIFF_SYM1214
.LTDIE_91:

	.byte 5
	.string "Mono_Cecil_PE_BinaryStreamReader"

	.byte 72,16
.LDIFF_SYM1215=.LTDIE_92 - .Ldebug_info_start
	.long .LDIFF_SYM1215
	.byte 2,35,0,0,7
	.string "Mono_Cecil_PE_BinaryStreamReader"

.LDIFF_SYM1216=.LTDIE_91 - .Ldebug_info_start
	.long .LDIFF_SYM1216
.LTDIE_91_POINTER:

	.byte 13
.LDIFF_SYM1217=.LTDIE_91 - .Ldebug_info_start
	.long .LDIFF_SYM1217
.LTDIE_91_REFERENCE:

	.byte 14
.LDIFF_SYM1218=.LTDIE_91 - .Ldebug_info_start
	.long .LDIFF_SYM1218
.LTDIE_182:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1219=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1219
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1220=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1220
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1221=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1221
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1222=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1222
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1223=.LTDIE_182 - .Ldebug_info_start
	.long .LDIFF_SYM1223
.LTDIE_182_POINTER:

	.byte 13
.LDIFF_SYM1224=.LTDIE_182 - .Ldebug_info_start
	.long .LDIFF_SYM1224
.LTDIE_182_REFERENCE:

	.byte 14
.LDIFF_SYM1225=.LTDIE_182 - .Ldebug_info_start
	.long .LDIFF_SYM1225
.LTDIE_183:

	.byte 17
	.string "Mono_Cecil_IMethodSignature"

	.byte 16,7
	.string "Mono_Cecil_IMethodSignature"

.LDIFF_SYM1226=.LTDIE_183 - .Ldebug_info_start
	.long .LDIFF_SYM1226
.LTDIE_183_POINTER:

	.byte 13
.LDIFF_SYM1227=.LTDIE_183 - .Ldebug_info_start
	.long .LDIFF_SYM1227
.LTDIE_183_REFERENCE:

	.byte 14
.LDIFF_SYM1228=.LTDIE_183 - .Ldebug_info_start
	.long .LDIFF_SYM1228
.LTDIE_181:

	.byte 5
	.string "Mono_Cecil_ParameterDefinitionCollection"

	.byte 40,16
.LDIFF_SYM1229=.LTDIE_182 - .Ldebug_info_start
	.long .LDIFF_SYM1229
	.byte 2,35,0,6
	.string "method"

.LDIFF_SYM1230=.LTDIE_183_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1230
	.byte 2,35,32,0,7
	.string "Mono_Cecil_ParameterDefinitionCollection"

.LDIFF_SYM1231=.LTDIE_181 - .Ldebug_info_start
	.long .LDIFF_SYM1231
.LTDIE_181_POINTER:

	.byte 13
.LDIFF_SYM1232=.LTDIE_181 - .Ldebug_info_start
	.long .LDIFF_SYM1232
.LTDIE_181_REFERENCE:

	.byte 14
.LDIFF_SYM1233=.LTDIE_181 - .Ldebug_info_start
	.long .LDIFF_SYM1233
.LTDIE_186:

	.byte 5
	.string "Mono_Cecil_ParameterReference"

	.byte 40,16
.LDIFF_SYM1234=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1234
	.byte 2,35,0,6
	.string "name"

.LDIFF_SYM1235=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1235
	.byte 2,35,16,6
	.string "index"

.LDIFF_SYM1236=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1236
	.byte 2,35,32,6
	.string "parameter_type"

.LDIFF_SYM1237=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1237
	.byte 2,35,24,6
	.string "token"

.LDIFF_SYM1238=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1238
	.byte 2,35,36,0,7
	.string "Mono_Cecil_ParameterReference"

.LDIFF_SYM1239=.LTDIE_186 - .Ldebug_info_start
	.long .LDIFF_SYM1239
.LTDIE_186_POINTER:

	.byte 13
.LDIFF_SYM1240=.LTDIE_186 - .Ldebug_info_start
	.long .LDIFF_SYM1240
.LTDIE_186_REFERENCE:

	.byte 14
.LDIFF_SYM1241=.LTDIE_186 - .Ldebug_info_start
	.long .LDIFF_SYM1241
.LTDIE_187:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1242=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1242
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1243=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1243
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1244=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1244
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1245=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1245
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1246=.LTDIE_187 - .Ldebug_info_start
	.long .LDIFF_SYM1246
.LTDIE_187_POINTER:

	.byte 13
.LDIFF_SYM1247=.LTDIE_187 - .Ldebug_info_start
	.long .LDIFF_SYM1247
.LTDIE_187_REFERENCE:

	.byte 14
.LDIFF_SYM1248=.LTDIE_187 - .Ldebug_info_start
	.long .LDIFF_SYM1248
.LTDIE_189:

	.byte 8
	.string "Mono_Cecil_NativeType"

	.byte 4
.LDIFF_SYM1249=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1249
	.byte 9
	.string "None"

	.byte 230,0,9
	.string "Boolean"

	.byte 2,9
	.string "I1"

	.byte 3,9
	.string "U1"

	.byte 4,9
	.string "I2"

	.byte 5,9
	.string "U2"

	.byte 6,9
	.string "I4"

	.byte 7,9
	.string "U4"

	.byte 8,9
	.string "I8"

	.byte 9,9
	.string "U8"

	.byte 10,9
	.string "R4"

	.byte 11,9
	.string "R8"

	.byte 12,9
	.string "LPStr"

	.byte 20,9
	.string "Int"

	.byte 31,9
	.string "UInt"

	.byte 32,9
	.string "Func"

	.byte 38,9
	.string "Array"

	.byte 42,9
	.string "Currency"

	.byte 15,9
	.string "BStr"

	.byte 19,9
	.string "LPWStr"

	.byte 21,9
	.string "LPTStr"

	.byte 22,9
	.string "FixedSysString"

	.byte 23,9
	.string "IUnknown"

	.byte 25,9
	.string "IDispatch"

	.byte 26,9
	.string "Struct"

	.byte 27,9
	.string "IntF"

	.byte 28,9
	.string "SafeArray"

	.byte 29,9
	.string "FixedArray"

	.byte 30,9
	.string "ByValStr"

	.byte 34,9
	.string "ANSIBStr"

	.byte 35,9
	.string "TBStr"

	.byte 36,9
	.string "VariantBool"

	.byte 37,9
	.string "ASAny"

	.byte 40,9
	.string "LPStruct"

	.byte 43,9
	.string "CustomMarshaler"

	.byte 44,9
	.string "Error"

	.byte 45,9
	.string "Max"

	.byte 208,0,0,7
	.string "Mono_Cecil_NativeType"

.LDIFF_SYM1250=.LTDIE_189 - .Ldebug_info_start
	.long .LDIFF_SYM1250
.LTDIE_189_POINTER:

	.byte 13
.LDIFF_SYM1251=.LTDIE_189 - .Ldebug_info_start
	.long .LDIFF_SYM1251
.LTDIE_189_REFERENCE:

	.byte 14
.LDIFF_SYM1252=.LTDIE_189 - .Ldebug_info_start
	.long .LDIFF_SYM1252
.LTDIE_188:

	.byte 5
	.string "Mono_Cecil_MarshalInfo"

	.byte 20,16
.LDIFF_SYM1253=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1253
	.byte 2,35,0,6
	.string "native"

.LDIFF_SYM1254=.LTDIE_189 - .Ldebug_info_start
	.long .LDIFF_SYM1254
	.byte 2,35,16,0,7
	.string "Mono_Cecil_MarshalInfo"

.LDIFF_SYM1255=.LTDIE_188 - .Ldebug_info_start
	.long .LDIFF_SYM1255
.LTDIE_188_POINTER:

	.byte 13
.LDIFF_SYM1256=.LTDIE_188 - .Ldebug_info_start
	.long .LDIFF_SYM1256
.LTDIE_188_REFERENCE:

	.byte 14
.LDIFF_SYM1257=.LTDIE_188 - .Ldebug_info_start
	.long .LDIFF_SYM1257
.LTDIE_185:

	.byte 5
	.string "Mono_Cecil_ParameterDefinition"

	.byte 80,16
.LDIFF_SYM1258=.LTDIE_186 - .Ldebug_info_start
	.long .LDIFF_SYM1258
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM1259=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM1259
	.byte 2,35,72,6
	.string "method"

.LDIFF_SYM1260=.LTDIE_183_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1260
	.byte 2,35,40,6
	.string "constant"

.LDIFF_SYM1261=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1261
	.byte 2,35,48,6
	.string "custom_attributes"

.LDIFF_SYM1262=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1262
	.byte 2,35,56,6
	.string "marshal_info"

.LDIFF_SYM1263=.LTDIE_188_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1263
	.byte 2,35,64,0,7
	.string "Mono_Cecil_ParameterDefinition"

.LDIFF_SYM1264=.LTDIE_185 - .Ldebug_info_start
	.long .LDIFF_SYM1264
.LTDIE_185_POINTER:

	.byte 13
.LDIFF_SYM1265=.LTDIE_185 - .Ldebug_info_start
	.long .LDIFF_SYM1265
.LTDIE_185_REFERENCE:

	.byte 14
.LDIFF_SYM1266=.LTDIE_185 - .Ldebug_info_start
	.long .LDIFF_SYM1266
.LTDIE_184:

	.byte 5
	.string "Mono_Cecil_MethodReturnType"

	.byte 40,16
.LDIFF_SYM1267=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1267
	.byte 2,35,0,6
	.string "method"

.LDIFF_SYM1268=.LTDIE_183_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1268
	.byte 2,35,16,6
	.string "parameter"

.LDIFF_SYM1269=.LTDIE_185_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1269
	.byte 2,35,24,6
	.string "return_type"

.LDIFF_SYM1270=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1270
	.byte 2,35,32,0,7
	.string "Mono_Cecil_MethodReturnType"

.LDIFF_SYM1271=.LTDIE_184 - .Ldebug_info_start
	.long .LDIFF_SYM1271
.LTDIE_184_POINTER:

	.byte 13
.LDIFF_SYM1272=.LTDIE_184 - .Ldebug_info_start
	.long .LDIFF_SYM1272
.LTDIE_184_REFERENCE:

	.byte 14
.LDIFF_SYM1273=.LTDIE_184 - .Ldebug_info_start
	.long .LDIFF_SYM1273
.LTDIE_190:

	.byte 8
	.string "Mono_Cecil_MethodCallingConvention"

	.byte 1
.LDIFF_SYM1274=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM1274
	.byte 9
	.string "Default"

	.byte 0,9
	.string "C"

	.byte 1,9
	.string "StdCall"

	.byte 2,9
	.string "ThisCall"

	.byte 3,9
	.string "FastCall"

	.byte 4,9
	.string "VarArg"

	.byte 5,9
	.string "Generic"

	.byte 16,0,7
	.string "Mono_Cecil_MethodCallingConvention"

.LDIFF_SYM1275=.LTDIE_190 - .Ldebug_info_start
	.long .LDIFF_SYM1275
.LTDIE_190_POINTER:

	.byte 13
.LDIFF_SYM1276=.LTDIE_190 - .Ldebug_info_start
	.long .LDIFF_SYM1276
.LTDIE_190_REFERENCE:

	.byte 14
.LDIFF_SYM1277=.LTDIE_190 - .Ldebug_info_start
	.long .LDIFF_SYM1277
.LTDIE_191:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1278=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1278
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1279=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1279
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1280=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1280
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1281=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1281
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1282=.LTDIE_191 - .Ldebug_info_start
	.long .LDIFF_SYM1282
.LTDIE_191_POINTER:

	.byte 13
.LDIFF_SYM1283=.LTDIE_191 - .Ldebug_info_start
	.long .LDIFF_SYM1283
.LTDIE_191_REFERENCE:

	.byte 14
.LDIFF_SYM1284=.LTDIE_191 - .Ldebug_info_start
	.long .LDIFF_SYM1284
.LTDIE_180:

	.byte 5
	.string "Mono_Cecil_MethodReference"

	.byte 80,16
.LDIFF_SYM1285=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM1285
	.byte 2,35,0,6
	.string "parameters"

.LDIFF_SYM1286=.LTDIE_181_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1286
	.byte 2,35,48,6
	.string "return_type"

.LDIFF_SYM1287=.LTDIE_184_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1287
	.byte 2,35,56,6
	.string "has_this"

.LDIFF_SYM1288=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1288
	.byte 2,35,72,6
	.string "explicit_this"

.LDIFF_SYM1289=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1289
	.byte 2,35,73,6
	.string "calling_convention"

.LDIFF_SYM1290=.LTDIE_190 - .Ldebug_info_start
	.long .LDIFF_SYM1290
	.byte 2,35,74,6
	.string "generic_parameters"

.LDIFF_SYM1291=.LTDIE_191_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1291
	.byte 2,35,64,0,7
	.string "Mono_Cecil_MethodReference"

.LDIFF_SYM1292=.LTDIE_180 - .Ldebug_info_start
	.long .LDIFF_SYM1292
.LTDIE_180_POINTER:

	.byte 13
.LDIFF_SYM1293=.LTDIE_180 - .Ldebug_info_start
	.long .LDIFF_SYM1293
.LTDIE_180_REFERENCE:

	.byte 14
.LDIFF_SYM1294=.LTDIE_180 - .Ldebug_info_start
	.long .LDIFF_SYM1294
.LTDIE_192:

	.byte 8
	.string "Mono_Cecil_MethodSemanticsAttributes"

	.byte 2
.LDIFF_SYM1295=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM1295
	.byte 9
	.string "None"

	.byte 0,9
	.string "Setter"

	.byte 1,9
	.string "Getter"

	.byte 2,9
	.string "Other"

	.byte 4,9
	.string "AddOn"

	.byte 8,9
	.string "RemoveOn"

	.byte 16,9
	.string "Fire"

	.byte 32,0,7
	.string "Mono_Cecil_MethodSemanticsAttributes"

.LDIFF_SYM1296=.LTDIE_192 - .Ldebug_info_start
	.long .LDIFF_SYM1296
.LTDIE_192_POINTER:

	.byte 13
.LDIFF_SYM1297=.LTDIE_192 - .Ldebug_info_start
	.long .LDIFF_SYM1297
.LTDIE_192_REFERENCE:

	.byte 14
.LDIFF_SYM1298=.LTDIE_192 - .Ldebug_info_start
	.long .LDIFF_SYM1298
.LTDIE_193:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1299=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1299
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1300=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1300
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1301=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1301
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1302=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1302
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1303=.LTDIE_193 - .Ldebug_info_start
	.long .LDIFF_SYM1303
.LTDIE_193_POINTER:

	.byte 13
.LDIFF_SYM1304=.LTDIE_193 - .Ldebug_info_start
	.long .LDIFF_SYM1304
.LTDIE_193_REFERENCE:

	.byte 14
.LDIFF_SYM1305=.LTDIE_193 - .Ldebug_info_start
	.long .LDIFF_SYM1305
.LTDIE_194:

	.byte 5
	.string "Mono_Cecil_PInvokeInfo"

	.byte 40,16
.LDIFF_SYM1306=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1306
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM1307=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM1307
	.byte 2,35,32,6
	.string "entry_point"

.LDIFF_SYM1308=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1308
	.byte 2,35,16,6
	.string "module"

.LDIFF_SYM1309=.LTDIE_12_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1309
	.byte 2,35,24,0,7
	.string "Mono_Cecil_PInvokeInfo"

.LDIFF_SYM1310=.LTDIE_194 - .Ldebug_info_start
	.long .LDIFF_SYM1310
.LTDIE_194_POINTER:

	.byte 13
.LDIFF_SYM1311=.LTDIE_194 - .Ldebug_info_start
	.long .LDIFF_SYM1311
.LTDIE_194_REFERENCE:

	.byte 14
.LDIFF_SYM1312=.LTDIE_194 - .Ldebug_info_start
	.long .LDIFF_SYM1312
.LTDIE_195:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1313=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1313
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1314=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1314
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1315=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1315
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1316=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1316
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1317=.LTDIE_195 - .Ldebug_info_start
	.long .LDIFF_SYM1317
.LTDIE_195_POINTER:

	.byte 13
.LDIFF_SYM1318=.LTDIE_195 - .Ldebug_info_start
	.long .LDIFF_SYM1318
.LTDIE_195_REFERENCE:

	.byte 14
.LDIFF_SYM1319=.LTDIE_195 - .Ldebug_info_start
	.long .LDIFF_SYM1319
.LTDIE_197:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1320=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1320
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1321=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1321
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1322=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1322
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1323=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1323
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1324=.LTDIE_197 - .Ldebug_info_start
	.long .LDIFF_SYM1324
.LTDIE_197_POINTER:

	.byte 13
.LDIFF_SYM1325=.LTDIE_197 - .Ldebug_info_start
	.long .LDIFF_SYM1325
.LTDIE_197_REFERENCE:

	.byte 14
.LDIFF_SYM1326=.LTDIE_197 - .Ldebug_info_start
	.long .LDIFF_SYM1326
.LTDIE_198:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1327=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1327
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1328=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1328
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1329=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1329
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1330=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1330
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1331=.LTDIE_198 - .Ldebug_info_start
	.long .LDIFF_SYM1331
.LTDIE_198_POINTER:

	.byte 13
.LDIFF_SYM1332=.LTDIE_198 - .Ldebug_info_start
	.long .LDIFF_SYM1332
.LTDIE_198_REFERENCE:

	.byte 14
.LDIFF_SYM1333=.LTDIE_198 - .Ldebug_info_start
	.long .LDIFF_SYM1333
.LTDIE_199:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1334=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1334
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1335=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1335
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1336=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1336
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1337=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1337
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1338=.LTDIE_199 - .Ldebug_info_start
	.long .LDIFF_SYM1338
.LTDIE_199_POINTER:

	.byte 13
.LDIFF_SYM1339=.LTDIE_199 - .Ldebug_info_start
	.long .LDIFF_SYM1339
.LTDIE_199_REFERENCE:

	.byte 14
.LDIFF_SYM1340=.LTDIE_199 - .Ldebug_info_start
	.long .LDIFF_SYM1340
.LTDIE_196:

	.byte 5
	.string "Mono_Cecil_Cil_MethodBody"

	.byte 72,16
.LDIFF_SYM1341=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1341
	.byte 2,35,0,6
	.string "method"

.LDIFF_SYM1342=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1342
	.byte 2,35,16,6
	.string "this_parameter"

.LDIFF_SYM1343=.LTDIE_185_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1343
	.byte 2,35,24,6
	.string "max_stack_size"

.LDIFF_SYM1344=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1344
	.byte 2,35,56,6
	.string "code_size"

.LDIFF_SYM1345=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1345
	.byte 2,35,60,6
	.string "init_locals"

.LDIFF_SYM1346=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1346
	.byte 2,35,64,6
	.string "local_var_token"

.LDIFF_SYM1347=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1347
	.byte 2,35,68,6
	.string "instructions"

.LDIFF_SYM1348=.LTDIE_197_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1348
	.byte 2,35,32,6
	.string "exceptions"

.LDIFF_SYM1349=.LTDIE_198_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1349
	.byte 2,35,40,6
	.string "variables"

.LDIFF_SYM1350=.LTDIE_199_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1350
	.byte 2,35,48,0,7
	.string "Mono_Cecil_Cil_MethodBody"

.LDIFF_SYM1351=.LTDIE_196 - .Ldebug_info_start
	.long .LDIFF_SYM1351
.LTDIE_196_POINTER:

	.byte 13
.LDIFF_SYM1352=.LTDIE_196 - .Ldebug_info_start
	.long .LDIFF_SYM1352
.LTDIE_196_REFERENCE:

	.byte 14
.LDIFF_SYM1353=.LTDIE_196 - .Ldebug_info_start
	.long .LDIFF_SYM1353
.LTDIE_202:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1354=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1354
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1355=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1355
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1356=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1356
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1357=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1357
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1358=.LTDIE_202 - .Ldebug_info_start
	.long .LDIFF_SYM1358
.LTDIE_202_POINTER:

	.byte 13
.LDIFF_SYM1359=.LTDIE_202 - .Ldebug_info_start
	.long .LDIFF_SYM1359
.LTDIE_202_REFERENCE:

	.byte 14
.LDIFF_SYM1360=.LTDIE_202 - .Ldebug_info_start
	.long .LDIFF_SYM1360
.LTDIE_201:

	.byte 5
	.string "Mono_Cecil_Cil_DebugInformation"

	.byte 32,16
.LDIFF_SYM1361=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1361
	.byte 2,35,0,6
	.string "token"

.LDIFF_SYM1362=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1362
	.byte 2,35,24,6
	.string "custom_infos"

.LDIFF_SYM1363=.LTDIE_202_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1363
	.byte 2,35,16,0,7
	.string "Mono_Cecil_Cil_DebugInformation"

.LDIFF_SYM1364=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1364
.LTDIE_201_POINTER:

	.byte 13
.LDIFF_SYM1365=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1365
.LTDIE_201_REFERENCE:

	.byte 14
.LDIFF_SYM1366=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1366
.LTDIE_203:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1367=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1367
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1368=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1368
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1369=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1369
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1370=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1370
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1371=.LTDIE_203 - .Ldebug_info_start
	.long .LDIFF_SYM1371
.LTDIE_203_POINTER:

	.byte 13
.LDIFF_SYM1372=.LTDIE_203 - .Ldebug_info_start
	.long .LDIFF_SYM1372
.LTDIE_203_REFERENCE:

	.byte 14
.LDIFF_SYM1373=.LTDIE_203 - .Ldebug_info_start
	.long .LDIFF_SYM1373
.LTDIE_206:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1374=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1374
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1375=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1375
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1376=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1376
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1377=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1377
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1378=.LTDIE_206 - .Ldebug_info_start
	.long .LDIFF_SYM1378
.LTDIE_206_POINTER:

	.byte 13
.LDIFF_SYM1379=.LTDIE_206 - .Ldebug_info_start
	.long .LDIFF_SYM1379
.LTDIE_206_REFERENCE:

	.byte 14
.LDIFF_SYM1380=.LTDIE_206 - .Ldebug_info_start
	.long .LDIFF_SYM1380
.LTDIE_205:

	.byte 5
	.string "Mono_Cecil_Cil_ImportDebugInformation"

	.byte 48,16
.LDIFF_SYM1381=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1381
	.byte 2,35,0,6
	.string "parent"

.LDIFF_SYM1382=.LTDIE_205_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1382
	.byte 2,35,32,6
	.string "targets"

.LDIFF_SYM1383=.LTDIE_206_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1383
	.byte 2,35,40,0,7
	.string "Mono_Cecil_Cil_ImportDebugInformation"

.LDIFF_SYM1384=.LTDIE_205 - .Ldebug_info_start
	.long .LDIFF_SYM1384
.LTDIE_205_POINTER:

	.byte 13
.LDIFF_SYM1385=.LTDIE_205 - .Ldebug_info_start
	.long .LDIFF_SYM1385
.LTDIE_205_REFERENCE:

	.byte 14
.LDIFF_SYM1386=.LTDIE_205 - .Ldebug_info_start
	.long .LDIFF_SYM1386
.LTDIE_207:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1387=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1387
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1388=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1388
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1389=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1389
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1390=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1390
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1391=.LTDIE_207 - .Ldebug_info_start
	.long .LDIFF_SYM1391
.LTDIE_207_POINTER:

	.byte 13
.LDIFF_SYM1392=.LTDIE_207 - .Ldebug_info_start
	.long .LDIFF_SYM1392
.LTDIE_207_REFERENCE:

	.byte 14
.LDIFF_SYM1393=.LTDIE_207 - .Ldebug_info_start
	.long .LDIFF_SYM1393
.LTDIE_208:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1394=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1394
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1395=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1395
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1396=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1396
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1397=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1397
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1398=.LTDIE_208 - .Ldebug_info_start
	.long .LDIFF_SYM1398
.LTDIE_208_POINTER:

	.byte 13
.LDIFF_SYM1399=.LTDIE_208 - .Ldebug_info_start
	.long .LDIFF_SYM1399
.LTDIE_208_REFERENCE:

	.byte 14
.LDIFF_SYM1400=.LTDIE_208 - .Ldebug_info_start
	.long .LDIFF_SYM1400
.LTDIE_209:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1401=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1401
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1402=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1402
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1403=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1403
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1404=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1404
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1405=.LTDIE_209 - .Ldebug_info_start
	.long .LDIFF_SYM1405
.LTDIE_209_POINTER:

	.byte 13
.LDIFF_SYM1406=.LTDIE_209 - .Ldebug_info_start
	.long .LDIFF_SYM1406
.LTDIE_209_REFERENCE:

	.byte 14
.LDIFF_SYM1407=.LTDIE_209 - .Ldebug_info_start
	.long .LDIFF_SYM1407
.LTDIE_204:

	.byte 5
	.string "Mono_Cecil_Cil_ScopeDebugInformation"

	.byte 96,16
.LDIFF_SYM1408=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1408
	.byte 2,35,0,6
	.string "start"

.LDIFF_SYM1409=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1409
	.byte 2,35,32,6
	.string "end"

.LDIFF_SYM1410=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1410
	.byte 2,35,48,6
	.string "import"

.LDIFF_SYM1411=.LTDIE_205_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1411
	.byte 2,35,64,6
	.string "scopes"

.LDIFF_SYM1412=.LTDIE_207_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1412
	.byte 2,35,72,6
	.string "variables"

.LDIFF_SYM1413=.LTDIE_208_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1413
	.byte 2,35,80,6
	.string "constants"

.LDIFF_SYM1414=.LTDIE_209_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1414
	.byte 2,35,88,0,7
	.string "Mono_Cecil_Cil_ScopeDebugInformation"

.LDIFF_SYM1415=.LTDIE_204 - .Ldebug_info_start
	.long .LDIFF_SYM1415
.LTDIE_204_POINTER:

	.byte 13
.LDIFF_SYM1416=.LTDIE_204 - .Ldebug_info_start
	.long .LDIFF_SYM1416
.LTDIE_204_REFERENCE:

	.byte 14
.LDIFF_SYM1417=.LTDIE_204 - .Ldebug_info_start
	.long .LDIFF_SYM1417
.LTDIE_200:

	.byte 5
	.string "Mono_Cecil_Cil_MethodDebugInformation"

	.byte 72,16
.LDIFF_SYM1418=.LTDIE_201 - .Ldebug_info_start
	.long .LDIFF_SYM1418
	.byte 2,35,0,6
	.string "method"

.LDIFF_SYM1419=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1419
	.byte 2,35,32,6
	.string "sequence_points"

.LDIFF_SYM1420=.LTDIE_203_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1420
	.byte 2,35,40,6
	.string "scope"

.LDIFF_SYM1421=.LTDIE_204_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1421
	.byte 2,35,48,6
	.string "kickoff_method"

.LDIFF_SYM1422=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1422
	.byte 2,35,56,6
	.string "code_size"

.LDIFF_SYM1423=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1423
	.byte 2,35,64,6
	.string "local_var_token"

.LDIFF_SYM1424=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1424
	.byte 2,35,68,0,7
	.string "Mono_Cecil_Cil_MethodDebugInformation"

.LDIFF_SYM1425=.LTDIE_200 - .Ldebug_info_start
	.long .LDIFF_SYM1425
.LTDIE_200_POINTER:

	.byte 13
.LDIFF_SYM1426=.LTDIE_200 - .Ldebug_info_start
	.long .LDIFF_SYM1426
.LTDIE_200_REFERENCE:

	.byte 14
.LDIFF_SYM1427=.LTDIE_200 - .Ldebug_info_start
	.long .LDIFF_SYM1427
.LTDIE_179:

	.byte 5
	.string "Mono_Cecil_MethodDefinition"

	.byte 152,1,16
.LDIFF_SYM1428=.LTDIE_180 - .Ldebug_info_start
	.long .LDIFF_SYM1428
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM1429=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM1429
	.byte 3,35,136,1,6
	.string "impl_attributes"

.LDIFF_SYM1430=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM1430
	.byte 3,35,138,1,6
	.string "sem_attrs_ready"

.LDIFF_SYM1431=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1431
	.byte 3,35,140,1,6
	.string "sem_attrs"

.LDIFF_SYM1432=.LTDIE_192 - .Ldebug_info_start
	.long .LDIFF_SYM1432
	.byte 3,35,142,1,6
	.string "custom_attributes"

.LDIFF_SYM1433=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1433
	.byte 2,35,80,6
	.string "security_declarations"

.LDIFF_SYM1434=.LTDIE_193_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1434
	.byte 2,35,88,6
	.string "rva"

.LDIFF_SYM1435=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM1435
	.byte 3,35,144,1,6
	.string "pinvoke"

.LDIFF_SYM1436=.LTDIE_194_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1436
	.byte 2,35,96,6
	.string "overrides"

.LDIFF_SYM1437=.LTDIE_195_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1437
	.byte 2,35,104,6
	.string "body"

.LDIFF_SYM1438=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1438
	.byte 2,35,112,6
	.string "debug_info"

.LDIFF_SYM1439=.LTDIE_200_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1439
	.byte 2,35,120,6
	.string "custom_infos"

.LDIFF_SYM1440=.LTDIE_202_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1440
	.byte 3,35,128,1,0,7
	.string "Mono_Cecil_MethodDefinition"

.LDIFF_SYM1441=.LTDIE_179 - .Ldebug_info_start
	.long .LDIFF_SYM1441
.LTDIE_179_POINTER:

	.byte 13
.LDIFF_SYM1442=.LTDIE_179 - .Ldebug_info_start
	.long .LDIFF_SYM1442
.LTDIE_179_REFERENCE:

	.byte 14
.LDIFF_SYM1443=.LTDIE_179 - .Ldebug_info_start
	.long .LDIFF_SYM1443
.LTDIE_90:

	.byte 5
	.string "Mono_Cecil_Cil_CodeReader"

	.byte 104,16
.LDIFF_SYM1444=.LTDIE_91 - .Ldebug_info_start
	.long .LDIFF_SYM1444
	.byte 2,35,0,6
	.string "reader"

.LDIFF_SYM1445=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1445
	.byte 2,35,72,6
	.string "start"

.LDIFF_SYM1446=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1446
	.byte 2,35,96,6
	.string "method"

.LDIFF_SYM1447=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1447
	.byte 2,35,80,6
	.string "body"

.LDIFF_SYM1448=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1448
	.byte 2,35,88,0,7
	.string "Mono_Cecil_Cil_CodeReader"

.LDIFF_SYM1449=.LTDIE_90 - .Ldebug_info_start
	.long .LDIFF_SYM1449
.LTDIE_90_POINTER:

	.byte 13
.LDIFF_SYM1450=.LTDIE_90 - .Ldebug_info_start
	.long .LDIFF_SYM1450
.LTDIE_90_REFERENCE:

	.byte 14
.LDIFF_SYM1451=.LTDIE_90 - .Ldebug_info_start
	.long .LDIFF_SYM1451
.LTDIE_210:

	.byte 17
	.string "Mono_Cecil_IGenericContext"

	.byte 16,7
	.string "Mono_Cecil_IGenericContext"

.LDIFF_SYM1452=.LTDIE_210 - .Ldebug_info_start
	.long .LDIFF_SYM1452
.LTDIE_210_POINTER:

	.byte 13
.LDIFF_SYM1453=.LTDIE_210 - .Ldebug_info_start
	.long .LDIFF_SYM1453
.LTDIE_210_REFERENCE:

	.byte 14
.LDIFF_SYM1454=.LTDIE_210 - .Ldebug_info_start
	.long .LDIFF_SYM1454
.LTDIE_88:

	.byte 5
	.string "Mono_Cecil_MetadataReader"

	.byte 80,16
.LDIFF_SYM1455=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM1455
	.byte 2,35,0,6
	.string "image"

.LDIFF_SYM1456=.LTDIE_13_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1456
	.byte 2,35,32,6
	.string "module"

.LDIFF_SYM1457=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1457
	.byte 2,35,40,6
	.string "metadata"

.LDIFF_SYM1458=.LTDIE_42_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1458
	.byte 2,35,48,6
	.string "code"

.LDIFF_SYM1459=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1459
	.byte 2,35,56,6
	.string "context"

.LDIFF_SYM1460=.LTDIE_210_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1460
	.byte 2,35,64,6
	.string "metadata_reader"

.LDIFF_SYM1461=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1461
	.byte 2,35,72,0,7
	.string "Mono_Cecil_MetadataReader"

.LDIFF_SYM1462=.LTDIE_88 - .Ldebug_info_start
	.long .LDIFF_SYM1462
.LTDIE_88_POINTER:

	.byte 13
.LDIFF_SYM1463=.LTDIE_88 - .Ldebug_info_start
	.long .LDIFF_SYM1463
.LTDIE_88_REFERENCE:

	.byte 14
.LDIFF_SYM1464=.LTDIE_88 - .Ldebug_info_start
	.long .LDIFF_SYM1464
.LTDIE_212:

	.byte 5
	.string "System_Version"

	.byte 32,16
.LDIFF_SYM1465=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1465
	.byte 2,35,0,6
	.string "_Major"

.LDIFF_SYM1466=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1466
	.byte 2,35,16,6
	.string "_Minor"

.LDIFF_SYM1467=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1467
	.byte 2,35,20,6
	.string "_Build"

.LDIFF_SYM1468=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1468
	.byte 2,35,24,6
	.string "_Revision"

.LDIFF_SYM1469=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1469
	.byte 2,35,28,0,7
	.string "System_Version"

.LDIFF_SYM1470=.LTDIE_212 - .Ldebug_info_start
	.long .LDIFF_SYM1470
.LTDIE_212_POINTER:

	.byte 13
.LDIFF_SYM1471=.LTDIE_212 - .Ldebug_info_start
	.long .LDIFF_SYM1471
.LTDIE_212_REFERENCE:

	.byte 14
.LDIFF_SYM1472=.LTDIE_212 - .Ldebug_info_start
	.long .LDIFF_SYM1472
.LTDIE_211:

	.byte 5
	.string "Mono_Cecil_WindowsRuntimeProjections"

	.byte 40,16
.LDIFF_SYM1473=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1473
	.byte 2,35,0,6
	.string "module"

.LDIFF_SYM1474=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1474
	.byte 2,35,16,6
	.string "corlib_version"

.LDIFF_SYM1475=.LTDIE_212_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1475
	.byte 2,35,24,6
	.string "virtual_references"

.LDIFF_SYM1476=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1476
	.byte 2,35,32,0,7
	.string "Mono_Cecil_WindowsRuntimeProjections"

.LDIFF_SYM1477=.LTDIE_211 - .Ldebug_info_start
	.long .LDIFF_SYM1477
.LTDIE_211_POINTER:

	.byte 13
.LDIFF_SYM1478=.LTDIE_211 - .Ldebug_info_start
	.long .LDIFF_SYM1478
.LTDIE_211_REFERENCE:

	.byte 14
.LDIFF_SYM1479=.LTDIE_211 - .Ldebug_info_start
	.long .LDIFF_SYM1479
.LTDIE_213:

	.byte 8
	.string "Mono_Cecil_MetadataKind"

	.byte 4
.LDIFF_SYM1480=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1480
	.byte 9
	.string "Ecma335"

	.byte 0,9
	.string "WindowsMetadata"

	.byte 1,9
	.string "ManagedWindowsMetadata"

	.byte 2,0,7
	.string "Mono_Cecil_MetadataKind"

.LDIFF_SYM1481=.LTDIE_213 - .Ldebug_info_start
	.long .LDIFF_SYM1481
.LTDIE_213_POINTER:

	.byte 13
.LDIFF_SYM1482=.LTDIE_213 - .Ldebug_info_start
	.long .LDIFF_SYM1482
.LTDIE_213_REFERENCE:

	.byte 14
.LDIFF_SYM1483=.LTDIE_213 - .Ldebug_info_start
	.long .LDIFF_SYM1483
.LTDIE_214:

	.byte 8
	.string "Mono_Cecil_TargetRuntime"

	.byte 4
.LDIFF_SYM1484=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1484
	.byte 9
	.string "Net_1_0"

	.byte 0,9
	.string "Net_1_1"

	.byte 1,9
	.string "Net_2_0"

	.byte 2,9
	.string "Net_4_0"

	.byte 3,0,7
	.string "Mono_Cecil_TargetRuntime"

.LDIFF_SYM1485=.LTDIE_214 - .Ldebug_info_start
	.long .LDIFF_SYM1485
.LTDIE_214_POINTER:

	.byte 13
.LDIFF_SYM1486=.LTDIE_214 - .Ldebug_info_start
	.long .LDIFF_SYM1486
.LTDIE_214_REFERENCE:

	.byte 14
.LDIFF_SYM1487=.LTDIE_214 - .Ldebug_info_start
	.long .LDIFF_SYM1487
.LTDIE_218:

	.byte 8
	.string "Mono_Cecil_AssemblyHashAlgorithm"

	.byte 4
.LDIFF_SYM1488=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM1488
	.byte 9
	.string "None"

	.byte 0,9
	.string "Reserved"

	.byte 131,128,2,9
	.string "SHA1"

	.byte 132,128,2,0,7
	.string "Mono_Cecil_AssemblyHashAlgorithm"

.LDIFF_SYM1489=.LTDIE_218 - .Ldebug_info_start
	.long .LDIFF_SYM1489
.LTDIE_218_POINTER:

	.byte 13
.LDIFF_SYM1490=.LTDIE_218 - .Ldebug_info_start
	.long .LDIFF_SYM1490
.LTDIE_218_REFERENCE:

	.byte 14
.LDIFF_SYM1491=.LTDIE_218 - .Ldebug_info_start
	.long .LDIFF_SYM1491
.LTDIE_217:

	.byte 5
	.string "Mono_Cecil_AssemblyNameReference"

	.byte 88,16
.LDIFF_SYM1492=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1492
	.byte 2,35,0,6
	.string "name"

.LDIFF_SYM1493=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1493
	.byte 2,35,16,6
	.string "culture"

.LDIFF_SYM1494=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1494
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1495=.LTDIE_212_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1495
	.byte 2,35,32,6
	.string "attributes"

.LDIFF_SYM1496=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM1496
	.byte 2,35,72,6
	.string "public_key"

.LDIFF_SYM1497=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1497
	.byte 2,35,40,6
	.string "public_key_token"

.LDIFF_SYM1498=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1498
	.byte 2,35,48,6
	.string "hash_algorithm"

.LDIFF_SYM1499=.LTDIE_218 - .Ldebug_info_start
	.long .LDIFF_SYM1499
	.byte 2,35,76,6
	.string "hash"

.LDIFF_SYM1500=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1500
	.byte 2,35,56,6
	.string "token"

.LDIFF_SYM1501=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1501
	.byte 2,35,80,6
	.string "full_name"

.LDIFF_SYM1502=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM1502
	.byte 2,35,64,0,7
	.string "Mono_Cecil_AssemblyNameReference"

.LDIFF_SYM1503=.LTDIE_217 - .Ldebug_info_start
	.long .LDIFF_SYM1503
.LTDIE_217_POINTER:

	.byte 13
.LDIFF_SYM1504=.LTDIE_217 - .Ldebug_info_start
	.long .LDIFF_SYM1504
.LTDIE_217_REFERENCE:

	.byte 14
.LDIFF_SYM1505=.LTDIE_217 - .Ldebug_info_start
	.long .LDIFF_SYM1505
.LTDIE_216:

	.byte 5
	.string "Mono_Cecil_AssemblyNameDefinition"

	.byte 88,16
.LDIFF_SYM1506=.LTDIE_217 - .Ldebug_info_start
	.long .LDIFF_SYM1506
	.byte 2,35,0,0,7
	.string "Mono_Cecil_AssemblyNameDefinition"

.LDIFF_SYM1507=.LTDIE_216 - .Ldebug_info_start
	.long .LDIFF_SYM1507
.LTDIE_216_POINTER:

	.byte 13
.LDIFF_SYM1508=.LTDIE_216 - .Ldebug_info_start
	.long .LDIFF_SYM1508
.LTDIE_216_REFERENCE:

	.byte 14
.LDIFF_SYM1509=.LTDIE_216 - .Ldebug_info_start
	.long .LDIFF_SYM1509
.LTDIE_219:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1510=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1510
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1511=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1511
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1512=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1512
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1513=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1513
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1514=.LTDIE_219 - .Ldebug_info_start
	.long .LDIFF_SYM1514
.LTDIE_219_POINTER:

	.byte 13
.LDIFF_SYM1515=.LTDIE_219 - .Ldebug_info_start
	.long .LDIFF_SYM1515
.LTDIE_219_REFERENCE:

	.byte 14
.LDIFF_SYM1516=.LTDIE_219 - .Ldebug_info_start
	.long .LDIFF_SYM1516
.LTDIE_215:

	.byte 5
	.string "Mono_Cecil_AssemblyDefinition"

	.byte 56,16
.LDIFF_SYM1517=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1517
	.byte 2,35,0,6
	.string "name"

.LDIFF_SYM1518=.LTDIE_216_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1518
	.byte 2,35,16,6
	.string "main_module"

.LDIFF_SYM1519=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1519
	.byte 2,35,24,6
	.string "modules"

.LDIFF_SYM1520=.LTDIE_219_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1520
	.byte 2,35,32,6
	.string "custom_attributes"

.LDIFF_SYM1521=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1521
	.byte 2,35,40,6
	.string "security_declarations"

.LDIFF_SYM1522=.LTDIE_193_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1522
	.byte 2,35,48,0,7
	.string "Mono_Cecil_AssemblyDefinition"

.LDIFF_SYM1523=.LTDIE_215 - .Ldebug_info_start
	.long .LDIFF_SYM1523
.LTDIE_215_POINTER:

	.byte 13
.LDIFF_SYM1524=.LTDIE_215 - .Ldebug_info_start
	.long .LDIFF_SYM1524
.LTDIE_215_REFERENCE:

	.byte 14
.LDIFF_SYM1525=.LTDIE_215 - .Ldebug_info_start
	.long .LDIFF_SYM1525
.LTDIE_220:

	.byte 17
	.string "Mono_Cecil_IReflectionImporter"

	.byte 16,7
	.string "Mono_Cecil_IReflectionImporter"

.LDIFF_SYM1526=.LTDIE_220 - .Ldebug_info_start
	.long .LDIFF_SYM1526
.LTDIE_220_POINTER:

	.byte 13
.LDIFF_SYM1527=.LTDIE_220 - .Ldebug_info_start
	.long .LDIFF_SYM1527
.LTDIE_220_REFERENCE:

	.byte 14
.LDIFF_SYM1528=.LTDIE_220 - .Ldebug_info_start
	.long .LDIFF_SYM1528
.LTDIE_221:

	.byte 17
	.string "Mono_Cecil_IMetadataImporter"

	.byte 16,7
	.string "Mono_Cecil_IMetadataImporter"

.LDIFF_SYM1529=.LTDIE_221 - .Ldebug_info_start
	.long .LDIFF_SYM1529
.LTDIE_221_POINTER:

	.byte 13
.LDIFF_SYM1530=.LTDIE_221 - .Ldebug_info_start
	.long .LDIFF_SYM1530
.LTDIE_221_REFERENCE:

	.byte 14
.LDIFF_SYM1531=.LTDIE_221 - .Ldebug_info_start
	.long .LDIFF_SYM1531
.LTDIE_222:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1532=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1532
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1533=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1533
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1534=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1534
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1535=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1535
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1536=.LTDIE_222 - .Ldebug_info_start
	.long .LDIFF_SYM1536
.LTDIE_222_POINTER:

	.byte 13
.LDIFF_SYM1537=.LTDIE_222 - .Ldebug_info_start
	.long .LDIFF_SYM1537
.LTDIE_222_REFERENCE:

	.byte 14
.LDIFF_SYM1538=.LTDIE_222 - .Ldebug_info_start
	.long .LDIFF_SYM1538
.LTDIE_223:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1539=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1539
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1540=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1540
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1541=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1541
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1542=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1542
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1543=.LTDIE_223 - .Ldebug_info_start
	.long .LDIFF_SYM1543
.LTDIE_223_POINTER:

	.byte 13
.LDIFF_SYM1544=.LTDIE_223 - .Ldebug_info_start
	.long .LDIFF_SYM1544
.LTDIE_223_REFERENCE:

	.byte 14
.LDIFF_SYM1545=.LTDIE_223 - .Ldebug_info_start
	.long .LDIFF_SYM1545
.LTDIE_224:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1546=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1546
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1547=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1547
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1548=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1548
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1549=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1549
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1550=.LTDIE_224 - .Ldebug_info_start
	.long .LDIFF_SYM1550
.LTDIE_224_POINTER:

	.byte 13
.LDIFF_SYM1551=.LTDIE_224 - .Ldebug_info_start
	.long .LDIFF_SYM1551
.LTDIE_224_REFERENCE:

	.byte 14
.LDIFF_SYM1552=.LTDIE_224 - .Ldebug_info_start
	.long .LDIFF_SYM1552
.LTDIE_225:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1553=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1553
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1554=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1554
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1555=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1555
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1556=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1556
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1557=.LTDIE_225 - .Ldebug_info_start
	.long .LDIFF_SYM1557
.LTDIE_225_POINTER:

	.byte 13
.LDIFF_SYM1558=.LTDIE_225 - .Ldebug_info_start
	.long .LDIFF_SYM1558
.LTDIE_225_REFERENCE:

	.byte 14
.LDIFF_SYM1559=.LTDIE_225 - .Ldebug_info_start
	.long .LDIFF_SYM1559
.LTDIE_227:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM1560=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1560
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM1561=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1561
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM1562=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1562
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM1563=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1563
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM1564=.LTDIE_227 - .Ldebug_info_start
	.long .LDIFF_SYM1564
.LTDIE_227_POINTER:

	.byte 13
.LDIFF_SYM1565=.LTDIE_227 - .Ldebug_info_start
	.long .LDIFF_SYM1565
.LTDIE_227_REFERENCE:

	.byte 14
.LDIFF_SYM1566=.LTDIE_227 - .Ldebug_info_start
	.long .LDIFF_SYM1566
.LTDIE_229:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM1567=.LTDIE_229 - .Ldebug_info_start
	.long .LDIFF_SYM1567
.LTDIE_229_POINTER:

	.byte 13
.LDIFF_SYM1568=.LTDIE_229 - .Ldebug_info_start
	.long .LDIFF_SYM1568
.LTDIE_229_REFERENCE:

	.byte 14
.LDIFF_SYM1569=.LTDIE_229 - .Ldebug_info_start
	.long .LDIFF_SYM1569
.LTDIE_230:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1570=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1570
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1571=.LTDIE_228_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1571
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1572=.LTDIE_230 - .Ldebug_info_start
	.long .LDIFF_SYM1572
.LTDIE_230_POINTER:

	.byte 13
.LDIFF_SYM1573=.LTDIE_230 - .Ldebug_info_start
	.long .LDIFF_SYM1573
.LTDIE_230_REFERENCE:

	.byte 14
.LDIFF_SYM1574=.LTDIE_230 - .Ldebug_info_start
	.long .LDIFF_SYM1574
.LTDIE_231:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1575=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1575
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1576=.LTDIE_228_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1576
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1577=.LTDIE_231 - .Ldebug_info_start
	.long .LDIFF_SYM1577
.LTDIE_231_POINTER:

	.byte 13
.LDIFF_SYM1578=.LTDIE_231 - .Ldebug_info_start
	.long .LDIFF_SYM1578
.LTDIE_231_REFERENCE:

	.byte 14
.LDIFF_SYM1579=.LTDIE_231 - .Ldebug_info_start
	.long .LDIFF_SYM1579
.LTDIE_228:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1580=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1580
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1581=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1581
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1582=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1582
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1583=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1583
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1584=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1584
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1585=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1585
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1586=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1586
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1587=.LTDIE_229_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1587
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1588=.LTDIE_230_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1588
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1589=.LTDIE_231_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1589
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1590=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1590
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1591=.LTDIE_228 - .Ldebug_info_start
	.long .LDIFF_SYM1591
.LTDIE_228_POINTER:

	.byte 13
.LDIFF_SYM1592=.LTDIE_228 - .Ldebug_info_start
	.long .LDIFF_SYM1592
.LTDIE_228_REFERENCE:

	.byte 14
.LDIFF_SYM1593=.LTDIE_228 - .Ldebug_info_start
	.long .LDIFF_SYM1593
.LTDIE_226:

	.byte 5
	.string "Mono_Cecil_TypeDefinitionCollection"

	.byte 48,16
.LDIFF_SYM1594=.LTDIE_227 - .Ldebug_info_start
	.long .LDIFF_SYM1594
	.byte 2,35,0,6
	.string "container"

.LDIFF_SYM1595=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1595
	.byte 2,35,32,6
	.string "name_cache"

.LDIFF_SYM1596=.LTDIE_228_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1596
	.byte 2,35,40,0,7
	.string "Mono_Cecil_TypeDefinitionCollection"

.LDIFF_SYM1597=.LTDIE_226 - .Ldebug_info_start
	.long .LDIFF_SYM1597
.LTDIE_226_POINTER:

	.byte 13
.LDIFF_SYM1598=.LTDIE_226 - .Ldebug_info_start
	.long .LDIFF_SYM1598
.LTDIE_226_REFERENCE:

	.byte 14
.LDIFF_SYM1599=.LTDIE_226 - .Ldebug_info_start
	.long .LDIFF_SYM1599
.LTDIE_233:

	.byte 17
	.string "Mono_Cecil_Cil_ISymbolWriterProvider"

	.byte 16,7
	.string "Mono_Cecil_Cil_ISymbolWriterProvider"

.LDIFF_SYM1600=.LTDIE_233 - .Ldebug_info_start
	.long .LDIFF_SYM1600
.LTDIE_233_POINTER:

	.byte 13
.LDIFF_SYM1601=.LTDIE_233 - .Ldebug_info_start
	.long .LDIFF_SYM1601
.LTDIE_233_REFERENCE:

	.byte 14
.LDIFF_SYM1602=.LTDIE_233 - .Ldebug_info_start
	.long .LDIFF_SYM1602
.LTDIE_234:

	.byte 17
	.string "Mono_Cecil_Cil_ISymbolWriter"

	.byte 16,7
	.string "Mono_Cecil_Cil_ISymbolWriter"

.LDIFF_SYM1603=.LTDIE_234 - .Ldebug_info_start
	.long .LDIFF_SYM1603
.LTDIE_234_POINTER:

	.byte 13
.LDIFF_SYM1604=.LTDIE_234 - .Ldebug_info_start
	.long .LDIFF_SYM1604
.LTDIE_234_REFERENCE:

	.byte 14
.LDIFF_SYM1605=.LTDIE_234 - .Ldebug_info_start
	.long .LDIFF_SYM1605
.LTDIE_235:

	.byte 5
	.string "Mono_Cecil_PE_TextMap"

	.byte 24,16
.LDIFF_SYM1606=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1606
	.byte 2,35,0,6
	.string "map"

.LDIFF_SYM1607=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1607
	.byte 2,35,16,0,7
	.string "Mono_Cecil_PE_TextMap"

.LDIFF_SYM1608=.LTDIE_235 - .Ldebug_info_start
	.long .LDIFF_SYM1608
.LTDIE_235_POINTER:

	.byte 13
.LDIFF_SYM1609=.LTDIE_235 - .Ldebug_info_start
	.long .LDIFF_SYM1609
.LTDIE_235_REFERENCE:

	.byte 14
.LDIFF_SYM1610=.LTDIE_235 - .Ldebug_info_start
	.long .LDIFF_SYM1610
.LTDIE_237:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM1611=.LTDIE_237 - .Ldebug_info_start
	.long .LDIFF_SYM1611
.LTDIE_237_POINTER:

	.byte 13
.LDIFF_SYM1612=.LTDIE_237 - .Ldebug_info_start
	.long .LDIFF_SYM1612
.LTDIE_237_REFERENCE:

	.byte 14
.LDIFF_SYM1613=.LTDIE_237 - .Ldebug_info_start
	.long .LDIFF_SYM1613
.LTDIE_238:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1614=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1614
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1615=.LTDIE_236_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1615
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1616=.LTDIE_238 - .Ldebug_info_start
	.long .LDIFF_SYM1616
.LTDIE_238_POINTER:

	.byte 13
.LDIFF_SYM1617=.LTDIE_238 - .Ldebug_info_start
	.long .LDIFF_SYM1617
.LTDIE_238_REFERENCE:

	.byte 14
.LDIFF_SYM1618=.LTDIE_238 - .Ldebug_info_start
	.long .LDIFF_SYM1618
.LTDIE_239:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1619=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1619
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1620=.LTDIE_236_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1620
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1621=.LTDIE_239 - .Ldebug_info_start
	.long .LDIFF_SYM1621
.LTDIE_239_POINTER:

	.byte 13
.LDIFF_SYM1622=.LTDIE_239 - .Ldebug_info_start
	.long .LDIFF_SYM1622
.LTDIE_239_REFERENCE:

	.byte 14
.LDIFF_SYM1623=.LTDIE_239 - .Ldebug_info_start
	.long .LDIFF_SYM1623
.LTDIE_236:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1624=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1624
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1625=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1625
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1626=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1626
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1627=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1627
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1628=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1628
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1629=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1629
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1630=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1630
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1631=.LTDIE_237_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1631
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1632=.LTDIE_238_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1632
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1633=.LTDIE_239_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1633
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1634=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1634
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1635=.LTDIE_236 - .Ldebug_info_start
	.long .LDIFF_SYM1635
.LTDIE_236_POINTER:

	.byte 13
.LDIFF_SYM1636=.LTDIE_236 - .Ldebug_info_start
	.long .LDIFF_SYM1636
.LTDIE_236_REFERENCE:

	.byte 14
.LDIFF_SYM1637=.LTDIE_236 - .Ldebug_info_start
	.long .LDIFF_SYM1637
.LTDIE_241:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1638=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1638
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1639=.LTDIE_240_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1639
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1640=.LTDIE_241 - .Ldebug_info_start
	.long .LDIFF_SYM1640
.LTDIE_241_POINTER:

	.byte 13
.LDIFF_SYM1641=.LTDIE_241 - .Ldebug_info_start
	.long .LDIFF_SYM1641
.LTDIE_241_REFERENCE:

	.byte 14
.LDIFF_SYM1642=.LTDIE_241 - .Ldebug_info_start
	.long .LDIFF_SYM1642
.LTDIE_242:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1643=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1643
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1644=.LTDIE_240_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1644
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1645=.LTDIE_242 - .Ldebug_info_start
	.long .LDIFF_SYM1645
.LTDIE_242_POINTER:

	.byte 13
.LDIFF_SYM1646=.LTDIE_242 - .Ldebug_info_start
	.long .LDIFF_SYM1646
.LTDIE_242_REFERENCE:

	.byte 14
.LDIFF_SYM1647=.LTDIE_242 - .Ldebug_info_start
	.long .LDIFF_SYM1647
.LTDIE_240:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1648=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1648
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1649=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1649
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1650=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1650
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1651=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1651
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1652=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1652
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1653=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1653
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1654=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1654
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1655=.LTDIE_25_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1655
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1656=.LTDIE_241_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1656
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1657=.LTDIE_242_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1657
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1658=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1658
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1659=.LTDIE_240 - .Ldebug_info_start
	.long .LDIFF_SYM1659
.LTDIE_240_POINTER:

	.byte 13
.LDIFF_SYM1660=.LTDIE_240 - .Ldebug_info_start
	.long .LDIFF_SYM1660
.LTDIE_240_REFERENCE:

	.byte 14
.LDIFF_SYM1661=.LTDIE_240 - .Ldebug_info_start
	.long .LDIFF_SYM1661
.LTDIE_244:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM1662=.LTDIE_244 - .Ldebug_info_start
	.long .LDIFF_SYM1662
.LTDIE_244_POINTER:

	.byte 13
.LDIFF_SYM1663=.LTDIE_244 - .Ldebug_info_start
	.long .LDIFF_SYM1663
.LTDIE_244_REFERENCE:

	.byte 14
.LDIFF_SYM1664=.LTDIE_244 - .Ldebug_info_start
	.long .LDIFF_SYM1664
.LTDIE_245:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1665=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1665
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1666=.LTDIE_243_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1666
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1667=.LTDIE_245 - .Ldebug_info_start
	.long .LDIFF_SYM1667
.LTDIE_245_POINTER:

	.byte 13
.LDIFF_SYM1668=.LTDIE_245 - .Ldebug_info_start
	.long .LDIFF_SYM1668
.LTDIE_245_REFERENCE:

	.byte 14
.LDIFF_SYM1669=.LTDIE_245 - .Ldebug_info_start
	.long .LDIFF_SYM1669
.LTDIE_246:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1670=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1670
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1671=.LTDIE_243_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1671
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1672=.LTDIE_246 - .Ldebug_info_start
	.long .LDIFF_SYM1672
.LTDIE_246_POINTER:

	.byte 13
.LDIFF_SYM1673=.LTDIE_246 - .Ldebug_info_start
	.long .LDIFF_SYM1673
.LTDIE_246_REFERENCE:

	.byte 14
.LDIFF_SYM1674=.LTDIE_246 - .Ldebug_info_start
	.long .LDIFF_SYM1674
.LTDIE_243:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1675=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1675
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1676=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1676
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1677=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1677
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1678=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1678
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1679=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1679
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1680=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1680
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1681=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1681
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1682=.LTDIE_244_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1682
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1683=.LTDIE_245_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1683
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1684=.LTDIE_246_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1684
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1685=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1685
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1686=.LTDIE_243 - .Ldebug_info_start
	.long .LDIFF_SYM1686
.LTDIE_243_POINTER:

	.byte 13
.LDIFF_SYM1687=.LTDIE_243 - .Ldebug_info_start
	.long .LDIFF_SYM1687
.LTDIE_243_REFERENCE:

	.byte 14
.LDIFF_SYM1688=.LTDIE_243 - .Ldebug_info_start
	.long .LDIFF_SYM1688
.LTDIE_249:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM1689=.LTDIE_249 - .Ldebug_info_start
	.long .LDIFF_SYM1689
.LTDIE_249_POINTER:

	.byte 13
.LDIFF_SYM1690=.LTDIE_249 - .Ldebug_info_start
	.long .LDIFF_SYM1690
.LTDIE_249_REFERENCE:

	.byte 14
.LDIFF_SYM1691=.LTDIE_249 - .Ldebug_info_start
	.long .LDIFF_SYM1691
.LTDIE_250:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1692=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1692
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1693=.LTDIE_248_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1693
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1694=.LTDIE_250 - .Ldebug_info_start
	.long .LDIFF_SYM1694
.LTDIE_250_POINTER:

	.byte 13
.LDIFF_SYM1695=.LTDIE_250 - .Ldebug_info_start
	.long .LDIFF_SYM1695
.LTDIE_250_REFERENCE:

	.byte 14
.LDIFF_SYM1696=.LTDIE_250 - .Ldebug_info_start
	.long .LDIFF_SYM1696
.LTDIE_251:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1697=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1697
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1698=.LTDIE_248_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1698
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1699=.LTDIE_251 - .Ldebug_info_start
	.long .LDIFF_SYM1699
.LTDIE_251_POINTER:

	.byte 13
.LDIFF_SYM1700=.LTDIE_251 - .Ldebug_info_start
	.long .LDIFF_SYM1700
.LTDIE_251_REFERENCE:

	.byte 14
.LDIFF_SYM1701=.LTDIE_251 - .Ldebug_info_start
	.long .LDIFF_SYM1701
.LTDIE_248:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1702=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1702
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1703=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1703
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1704=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1704
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1705=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1705
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1706=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1706
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1707=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1707
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1708=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1708
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1709=.LTDIE_249_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1709
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1710=.LTDIE_250_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1710
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1711=.LTDIE_251_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1711
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1712=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1712
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1713=.LTDIE_248 - .Ldebug_info_start
	.long .LDIFF_SYM1713
.LTDIE_248_POINTER:

	.byte 13
.LDIFF_SYM1714=.LTDIE_248 - .Ldebug_info_start
	.long .LDIFF_SYM1714
.LTDIE_248_REFERENCE:

	.byte 14
.LDIFF_SYM1715=.LTDIE_248 - .Ldebug_info_start
	.long .LDIFF_SYM1715
.LTDIE_247:

	.byte 5
	.string "Mono_Cecil_Cil_CodeWriter"

	.byte 72,16
.LDIFF_SYM1716=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM1716
	.byte 2,35,0,6
	.string "code_base"

.LDIFF_SYM1717=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM1717
	.byte 2,35,64,6
	.string "metadata"

.LDIFF_SYM1718=.LTDIE_232_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1718
	.byte 2,35,32,6
	.string "standalone_signatures"

.LDIFF_SYM1719=.LTDIE_240_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1719
	.byte 2,35,40,6
	.string "tiny_method_bodies"

.LDIFF_SYM1720=.LTDIE_248_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1720
	.byte 2,35,48,6
	.string "body"

.LDIFF_SYM1721=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1721
	.byte 2,35,56,0,7
	.string "Mono_Cecil_Cil_CodeWriter"

.LDIFF_SYM1722=.LTDIE_247 - .Ldebug_info_start
	.long .LDIFF_SYM1722
.LTDIE_247_POINTER:

	.byte 13
.LDIFF_SYM1723=.LTDIE_247 - .Ldebug_info_start
	.long .LDIFF_SYM1723
.LTDIE_247_REFERENCE:

	.byte 14
.LDIFF_SYM1724=.LTDIE_247 - .Ldebug_info_start
	.long .LDIFF_SYM1724
.LTDIE_252:

	.byte 5
	.string "Mono_Cecil_Metadata_DataBuffer"

	.byte 32,16
.LDIFF_SYM1725=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM1725
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_DataBuffer"

.LDIFF_SYM1726=.LTDIE_252 - .Ldebug_info_start
	.long .LDIFF_SYM1726
.LTDIE_252_POINTER:

	.byte 13
.LDIFF_SYM1727=.LTDIE_252 - .Ldebug_info_start
	.long .LDIFF_SYM1727
.LTDIE_252_REFERENCE:

	.byte 14
.LDIFF_SYM1728=.LTDIE_252 - .Ldebug_info_start
	.long .LDIFF_SYM1728
.LTDIE_253:

	.byte 5
	.string "Mono_Cecil_Metadata_ResourceBuffer"

	.byte 32,16
.LDIFF_SYM1729=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM1729
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_ResourceBuffer"

.LDIFF_SYM1730=.LTDIE_253 - .Ldebug_info_start
	.long .LDIFF_SYM1730
.LTDIE_253_POINTER:

	.byte 13
.LDIFF_SYM1731=.LTDIE_253 - .Ldebug_info_start
	.long .LDIFF_SYM1731
.LTDIE_253_REFERENCE:

	.byte 14
.LDIFF_SYM1732=.LTDIE_253 - .Ldebug_info_start
	.long .LDIFF_SYM1732
.LTDIE_255:

	.byte 5
	.string "Mono_Cecil_Metadata_HeapBuffer"

	.byte 32,16
.LDIFF_SYM1733=.LTDIE_89 - .Ldebug_info_start
	.long .LDIFF_SYM1733
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_HeapBuffer"

.LDIFF_SYM1734=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1734
.LTDIE_255_POINTER:

	.byte 13
.LDIFF_SYM1735=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1735
.LTDIE_255_REFERENCE:

	.byte 14
.LDIFF_SYM1736=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1736
.LTDIE_257:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1737=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1737
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1738=.LTDIE_256_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1738
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1739=.LTDIE_257 - .Ldebug_info_start
	.long .LDIFF_SYM1739
.LTDIE_257_POINTER:

	.byte 13
.LDIFF_SYM1740=.LTDIE_257 - .Ldebug_info_start
	.long .LDIFF_SYM1740
.LTDIE_257_REFERENCE:

	.byte 14
.LDIFF_SYM1741=.LTDIE_257 - .Ldebug_info_start
	.long .LDIFF_SYM1741
.LTDIE_258:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1742=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1742
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1743=.LTDIE_256_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1743
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1744=.LTDIE_258 - .Ldebug_info_start
	.long .LDIFF_SYM1744
.LTDIE_258_POINTER:

	.byte 13
.LDIFF_SYM1745=.LTDIE_258 - .Ldebug_info_start
	.long .LDIFF_SYM1745
.LTDIE_258_REFERENCE:

	.byte 14
.LDIFF_SYM1746=.LTDIE_258 - .Ldebug_info_start
	.long .LDIFF_SYM1746
.LTDIE_256:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1747=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1747
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1748=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1748
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1749=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1749
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1750=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1750
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1751=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1751
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1752=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1752
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1753=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1753
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1754=.LTDIE_111_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1754
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1755=.LTDIE_257_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1755
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1756=.LTDIE_258_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1756
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1757=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1757
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1758=.LTDIE_256 - .Ldebug_info_start
	.long .LDIFF_SYM1758
.LTDIE_256_POINTER:

	.byte 13
.LDIFF_SYM1759=.LTDIE_256 - .Ldebug_info_start
	.long .LDIFF_SYM1759
.LTDIE_256_REFERENCE:

	.byte 14
.LDIFF_SYM1760=.LTDIE_256 - .Ldebug_info_start
	.long .LDIFF_SYM1760
.LTDIE_254:

	.byte 5
	.string "Mono_Cecil_Metadata_StringHeapBuffer"

	.byte 40,16
.LDIFF_SYM1761=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1761
	.byte 2,35,0,6
	.string "strings"

.LDIFF_SYM1762=.LTDIE_256_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1762
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Metadata_StringHeapBuffer"

.LDIFF_SYM1763=.LTDIE_254 - .Ldebug_info_start
	.long .LDIFF_SYM1763
.LTDIE_254_POINTER:

	.byte 13
.LDIFF_SYM1764=.LTDIE_254 - .Ldebug_info_start
	.long .LDIFF_SYM1764
.LTDIE_254_REFERENCE:

	.byte 14
.LDIFF_SYM1765=.LTDIE_254 - .Ldebug_info_start
	.long .LDIFF_SYM1765
.LTDIE_261:

	.byte 17
	.string "System_Collections_Generic_IEqualityComparer`1"

	.byte 16,7
	.string "System_Collections_Generic_IEqualityComparer`1"

.LDIFF_SYM1766=.LTDIE_261 - .Ldebug_info_start
	.long .LDIFF_SYM1766
.LTDIE_261_POINTER:

	.byte 13
.LDIFF_SYM1767=.LTDIE_261 - .Ldebug_info_start
	.long .LDIFF_SYM1767
.LTDIE_261_REFERENCE:

	.byte 14
.LDIFF_SYM1768=.LTDIE_261 - .Ldebug_info_start
	.long .LDIFF_SYM1768
.LTDIE_262:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM1769=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1769
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1770=.LTDIE_260_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1770
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM1771=.LTDIE_262 - .Ldebug_info_start
	.long .LDIFF_SYM1771
.LTDIE_262_POINTER:

	.byte 13
.LDIFF_SYM1772=.LTDIE_262 - .Ldebug_info_start
	.long .LDIFF_SYM1772
.LTDIE_262_REFERENCE:

	.byte 14
.LDIFF_SYM1773=.LTDIE_262 - .Ldebug_info_start
	.long .LDIFF_SYM1773
.LTDIE_263:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM1774=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1774
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM1775=.LTDIE_260_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1775
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM1776=.LTDIE_263 - .Ldebug_info_start
	.long .LDIFF_SYM1776
.LTDIE_263_POINTER:

	.byte 13
.LDIFF_SYM1777=.LTDIE_263 - .Ldebug_info_start
	.long .LDIFF_SYM1777
.LTDIE_263_REFERENCE:

	.byte 14
.LDIFF_SYM1778=.LTDIE_263 - .Ldebug_info_start
	.long .LDIFF_SYM1778
.LTDIE_260:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM1779=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1779
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM1780=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1780
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM1781=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1781
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM1782=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1782
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM1783=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1783
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM1784=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1784
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM1785=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1785
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM1786=.LTDIE_261_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1786
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM1787=.LTDIE_262_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1787
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM1788=.LTDIE_263_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1788
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM1789=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM1789
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM1790=.LTDIE_260 - .Ldebug_info_start
	.long .LDIFF_SYM1790
.LTDIE_260_POINTER:

	.byte 13
.LDIFF_SYM1791=.LTDIE_260 - .Ldebug_info_start
	.long .LDIFF_SYM1791
.LTDIE_260_REFERENCE:

	.byte 14
.LDIFF_SYM1792=.LTDIE_260 - .Ldebug_info_start
	.long .LDIFF_SYM1792
.LTDIE_259:

	.byte 5
	.string "Mono_Cecil_Metadata_GuidHeapBuffer"

	.byte 40,16
.LDIFF_SYM1793=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1793
	.byte 2,35,0,6
	.string "guids"

.LDIFF_SYM1794=.LTDIE_260_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1794
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Metadata_GuidHeapBuffer"

.LDIFF_SYM1795=.LTDIE_259 - .Ldebug_info_start
	.long .LDIFF_SYM1795
.LTDIE_259_POINTER:

	.byte 13
.LDIFF_SYM1796=.LTDIE_259 - .Ldebug_info_start
	.long .LDIFF_SYM1796
.LTDIE_259_REFERENCE:

	.byte 14
.LDIFF_SYM1797=.LTDIE_259 - .Ldebug_info_start
	.long .LDIFF_SYM1797
.LTDIE_264:

	.byte 5
	.string "Mono_Cecil_Metadata_UserStringHeapBuffer"

	.byte 40,16
.LDIFF_SYM1798=.LTDIE_254 - .Ldebug_info_start
	.long .LDIFF_SYM1798
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_UserStringHeapBuffer"

.LDIFF_SYM1799=.LTDIE_264 - .Ldebug_info_start
	.long .LDIFF_SYM1799
.LTDIE_264_POINTER:

	.byte 13
.LDIFF_SYM1800=.LTDIE_264 - .Ldebug_info_start
	.long .LDIFF_SYM1800
.LTDIE_264_REFERENCE:

	.byte 14
.LDIFF_SYM1801=.LTDIE_264 - .Ldebug_info_start
	.long .LDIFF_SYM1801
.LTDIE_265:

	.byte 5
	.string "Mono_Cecil_Metadata_BlobHeapBuffer"

	.byte 40,16
.LDIFF_SYM1802=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1802
	.byte 2,35,0,6
	.string "blobs"

.LDIFF_SYM1803=.LTDIE_248_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1803
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Metadata_BlobHeapBuffer"

.LDIFF_SYM1804=.LTDIE_265 - .Ldebug_info_start
	.long .LDIFF_SYM1804
.LTDIE_265_POINTER:

	.byte 13
.LDIFF_SYM1805=.LTDIE_265 - .Ldebug_info_start
	.long .LDIFF_SYM1805
.LTDIE_265_REFERENCE:

	.byte 14
.LDIFF_SYM1806=.LTDIE_265 - .Ldebug_info_start
	.long .LDIFF_SYM1806
.LTDIE_266:

	.byte 5
	.string "Mono_Cecil_Metadata_TableHeapBuffer"

	.byte 96,16
.LDIFF_SYM1807=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1807
	.byte 2,35,0,6
	.string "module"

.LDIFF_SYM1808=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1808
	.byte 2,35,32,6
	.string "metadata"

.LDIFF_SYM1809=.LTDIE_232_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1809
	.byte 2,35,40,6
	.string "table_infos"

.LDIFF_SYM1810=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1810
	.byte 2,35,48,6
	.string "tables"

.LDIFF_SYM1811=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1811
	.byte 2,35,56,6
	.string "large_string"

.LDIFF_SYM1812=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1812
	.byte 2,35,88,6
	.string "large_blob"

.LDIFF_SYM1813=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1813
	.byte 2,35,89,6
	.string "large_guid"

.LDIFF_SYM1814=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM1814
	.byte 2,35,90,6
	.string "coded_index_sizes"

.LDIFF_SYM1815=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1815
	.byte 2,35,64,6
	.string "counter"

.LDIFF_SYM1816=.LTDIE_34_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM1816
	.byte 2,35,72,6
	.string "string_offsets"

.LDIFF_SYM1817=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1817
	.byte 2,35,80,0,7
	.string "Mono_Cecil_Metadata_TableHeapBuffer"

.LDIFF_SYM1818=.LTDIE_266 - .Ldebug_info_start
	.long .LDIFF_SYM1818
.LTDIE_266_POINTER:

	.byte 13
.LDIFF_SYM1819=.LTDIE_266 - .Ldebug_info_start
	.long .LDIFF_SYM1819
.LTDIE_266_REFERENCE:

	.byte 14
.LDIFF_SYM1820=.LTDIE_266 - .Ldebug_info_start
	.long .LDIFF_SYM1820
.LTDIE_267:

	.byte 5
	.string "Mono_Cecil_Metadata_PdbHeapBuffer"

	.byte 32,16
.LDIFF_SYM1821=.LTDIE_255 - .Ldebug_info_start
	.long .LDIFF_SYM1821
	.byte 2,35,0,0,7
	.string "Mono_Cecil_Metadata_PdbHeapBuffer"

.LDIFF_SYM1822=.LTDIE_267 - .Ldebug_info_start
	.long .LDIFF_SYM1822
.LTDIE_267_POINTER:

	.byte 13
.LDIFF_SYM1823=.LTDIE_267 - .Ldebug_info_start
	.long .LDIFF_SYM1823
.LTDIE_267_REFERENCE:

	.byte 14
.LDIFF_SYM1824=.LTDIE_267 - .Ldebug_info_start
	.long .LDIFF_SYM1824
.LTDIE_270:

	.byte 5
	.string "Mono_Cecil_MetadataTable"

	.byte 16,16
.LDIFF_SYM1825=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM1825
	.byte 2,35,0,0,7
	.string "Mono_Cecil_MetadataTable"

.LDIFF_SYM1826=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1826
.LTDIE_270_POINTER:

	.byte 13
.LDIFF_SYM1827=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1827
.LTDIE_270_REFERENCE:

	.byte 14
.LDIFF_SYM1828=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1828
.LTDIE_269:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1829=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1829
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1830=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1830
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1831=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1831
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1832=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1832
.LTDIE_269_POINTER:

	.byte 13
.LDIFF_SYM1833=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1833
.LTDIE_269_REFERENCE:

	.byte 14
.LDIFF_SYM1834=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1834
.LTDIE_268:

	.byte 5
	.string "Mono_Cecil_TypeRefTable"

	.byte 32,16
.LDIFF_SYM1835=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1835
	.byte 2,35,0,0,7
	.string "Mono_Cecil_TypeRefTable"

.LDIFF_SYM1836=.LTDIE_268 - .Ldebug_info_start
	.long .LDIFF_SYM1836
.LTDIE_268_POINTER:

	.byte 13
.LDIFF_SYM1837=.LTDIE_268 - .Ldebug_info_start
	.long .LDIFF_SYM1837
.LTDIE_268_REFERENCE:

	.byte 14
.LDIFF_SYM1838=.LTDIE_268 - .Ldebug_info_start
	.long .LDIFF_SYM1838
.LTDIE_272:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1839=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1839
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1840=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1840
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1841=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1841
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1842=.LTDIE_272 - .Ldebug_info_start
	.long .LDIFF_SYM1842
.LTDIE_272_POINTER:

	.byte 13
.LDIFF_SYM1843=.LTDIE_272 - .Ldebug_info_start
	.long .LDIFF_SYM1843
.LTDIE_272_REFERENCE:

	.byte 14
.LDIFF_SYM1844=.LTDIE_272 - .Ldebug_info_start
	.long .LDIFF_SYM1844
.LTDIE_271:

	.byte 5
	.string "Mono_Cecil_TypeDefTable"

	.byte 32,16
.LDIFF_SYM1845=.LTDIE_272 - .Ldebug_info_start
	.long .LDIFF_SYM1845
	.byte 2,35,0,0,7
	.string "Mono_Cecil_TypeDefTable"

.LDIFF_SYM1846=.LTDIE_271 - .Ldebug_info_start
	.long .LDIFF_SYM1846
.LTDIE_271_POINTER:

	.byte 13
.LDIFF_SYM1847=.LTDIE_271 - .Ldebug_info_start
	.long .LDIFF_SYM1847
.LTDIE_271_REFERENCE:

	.byte 14
.LDIFF_SYM1848=.LTDIE_271 - .Ldebug_info_start
	.long .LDIFF_SYM1848
.LTDIE_274:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1849=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1849
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1850=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1850
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1851=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1851
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1852=.LTDIE_274 - .Ldebug_info_start
	.long .LDIFF_SYM1852
.LTDIE_274_POINTER:

	.byte 13
.LDIFF_SYM1853=.LTDIE_274 - .Ldebug_info_start
	.long .LDIFF_SYM1853
.LTDIE_274_REFERENCE:

	.byte 14
.LDIFF_SYM1854=.LTDIE_274 - .Ldebug_info_start
	.long .LDIFF_SYM1854
.LTDIE_273:

	.byte 5
	.string "Mono_Cecil_FieldTable"

	.byte 32,16
.LDIFF_SYM1855=.LTDIE_274 - .Ldebug_info_start
	.long .LDIFF_SYM1855
	.byte 2,35,0,0,7
	.string "Mono_Cecil_FieldTable"

.LDIFF_SYM1856=.LTDIE_273 - .Ldebug_info_start
	.long .LDIFF_SYM1856
.LTDIE_273_POINTER:

	.byte 13
.LDIFF_SYM1857=.LTDIE_273 - .Ldebug_info_start
	.long .LDIFF_SYM1857
.LTDIE_273_REFERENCE:

	.byte 14
.LDIFF_SYM1858=.LTDIE_273 - .Ldebug_info_start
	.long .LDIFF_SYM1858
.LTDIE_276:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1859=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1859
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1860=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1860
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1861=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1861
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1862=.LTDIE_276 - .Ldebug_info_start
	.long .LDIFF_SYM1862
.LTDIE_276_POINTER:

	.byte 13
.LDIFF_SYM1863=.LTDIE_276 - .Ldebug_info_start
	.long .LDIFF_SYM1863
.LTDIE_276_REFERENCE:

	.byte 14
.LDIFF_SYM1864=.LTDIE_276 - .Ldebug_info_start
	.long .LDIFF_SYM1864
.LTDIE_275:

	.byte 5
	.string "Mono_Cecil_MethodTable"

	.byte 32,16
.LDIFF_SYM1865=.LTDIE_276 - .Ldebug_info_start
	.long .LDIFF_SYM1865
	.byte 2,35,0,0,7
	.string "Mono_Cecil_MethodTable"

.LDIFF_SYM1866=.LTDIE_275 - .Ldebug_info_start
	.long .LDIFF_SYM1866
.LTDIE_275_POINTER:

	.byte 13
.LDIFF_SYM1867=.LTDIE_275 - .Ldebug_info_start
	.long .LDIFF_SYM1867
.LTDIE_275_REFERENCE:

	.byte 14
.LDIFF_SYM1868=.LTDIE_275 - .Ldebug_info_start
	.long .LDIFF_SYM1868
.LTDIE_278:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1869=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1869
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1870=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1870
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1871=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1871
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1872=.LTDIE_278 - .Ldebug_info_start
	.long .LDIFF_SYM1872
.LTDIE_278_POINTER:

	.byte 13
.LDIFF_SYM1873=.LTDIE_278 - .Ldebug_info_start
	.long .LDIFF_SYM1873
.LTDIE_278_REFERENCE:

	.byte 14
.LDIFF_SYM1874=.LTDIE_278 - .Ldebug_info_start
	.long .LDIFF_SYM1874
.LTDIE_277:

	.byte 5
	.string "Mono_Cecil_ParamTable"

	.byte 32,16
.LDIFF_SYM1875=.LTDIE_278 - .Ldebug_info_start
	.long .LDIFF_SYM1875
	.byte 2,35,0,0,7
	.string "Mono_Cecil_ParamTable"

.LDIFF_SYM1876=.LTDIE_277 - .Ldebug_info_start
	.long .LDIFF_SYM1876
.LTDIE_277_POINTER:

	.byte 13
.LDIFF_SYM1877=.LTDIE_277 - .Ldebug_info_start
	.long .LDIFF_SYM1877
.LTDIE_277_REFERENCE:

	.byte 14
.LDIFF_SYM1878=.LTDIE_277 - .Ldebug_info_start
	.long .LDIFF_SYM1878
.LTDIE_280:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1879=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1879
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1880=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1880
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1881=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1881
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1882=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1882
.LTDIE_280_POINTER:

	.byte 13
.LDIFF_SYM1883=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1883
.LTDIE_280_REFERENCE:

	.byte 14
.LDIFF_SYM1884=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1884
.LTDIE_279:

	.byte 5
	.string "Mono_Cecil_InterfaceImplTable"

	.byte 32,16
.LDIFF_SYM1885=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1885
	.byte 2,35,0,0,7
	.string "Mono_Cecil_InterfaceImplTable"

.LDIFF_SYM1886=.LTDIE_279 - .Ldebug_info_start
	.long .LDIFF_SYM1886
.LTDIE_279_POINTER:

	.byte 13
.LDIFF_SYM1887=.LTDIE_279 - .Ldebug_info_start
	.long .LDIFF_SYM1887
.LTDIE_279_REFERENCE:

	.byte 14
.LDIFF_SYM1888=.LTDIE_279 - .Ldebug_info_start
	.long .LDIFF_SYM1888
.LTDIE_281:

	.byte 5
	.string "Mono_Cecil_MemberRefTable"

	.byte 32,16
.LDIFF_SYM1889=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1889
	.byte 2,35,0,0,7
	.string "Mono_Cecil_MemberRefTable"

.LDIFF_SYM1890=.LTDIE_281 - .Ldebug_info_start
	.long .LDIFF_SYM1890
.LTDIE_281_POINTER:

	.byte 13
.LDIFF_SYM1891=.LTDIE_281 - .Ldebug_info_start
	.long .LDIFF_SYM1891
.LTDIE_281_REFERENCE:

	.byte 14
.LDIFF_SYM1892=.LTDIE_281 - .Ldebug_info_start
	.long .LDIFF_SYM1892
.LTDIE_284:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1893=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1893
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1894=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1894
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1895=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1895
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1896=.LTDIE_284 - .Ldebug_info_start
	.long .LDIFF_SYM1896
.LTDIE_284_POINTER:

	.byte 13
.LDIFF_SYM1897=.LTDIE_284 - .Ldebug_info_start
	.long .LDIFF_SYM1897
.LTDIE_284_REFERENCE:

	.byte 14
.LDIFF_SYM1898=.LTDIE_284 - .Ldebug_info_start
	.long .LDIFF_SYM1898
.LTDIE_283:

	.byte 5
	.string "Mono_Cecil_SortedTable`1"

	.byte 32,16
.LDIFF_SYM1899=.LTDIE_284 - .Ldebug_info_start
	.long .LDIFF_SYM1899
	.byte 2,35,0,0,7
	.string "Mono_Cecil_SortedTable`1"

.LDIFF_SYM1900=.LTDIE_283 - .Ldebug_info_start
	.long .LDIFF_SYM1900
.LTDIE_283_POINTER:

	.byte 13
.LDIFF_SYM1901=.LTDIE_283 - .Ldebug_info_start
	.long .LDIFF_SYM1901
.LTDIE_283_REFERENCE:

	.byte 14
.LDIFF_SYM1902=.LTDIE_283 - .Ldebug_info_start
	.long .LDIFF_SYM1902
.LTDIE_282:

	.byte 5
	.string "Mono_Cecil_ConstantTable"

	.byte 32,16
.LDIFF_SYM1903=.LTDIE_283 - .Ldebug_info_start
	.long .LDIFF_SYM1903
	.byte 2,35,0,0,7
	.string "Mono_Cecil_ConstantTable"

.LDIFF_SYM1904=.LTDIE_282 - .Ldebug_info_start
	.long .LDIFF_SYM1904
.LTDIE_282_POINTER:

	.byte 13
.LDIFF_SYM1905=.LTDIE_282 - .Ldebug_info_start
	.long .LDIFF_SYM1905
.LTDIE_282_REFERENCE:

	.byte 14
.LDIFF_SYM1906=.LTDIE_282 - .Ldebug_info_start
	.long .LDIFF_SYM1906
.LTDIE_286:

	.byte 5
	.string "Mono_Cecil_SortedTable`1"

	.byte 32,16
.LDIFF_SYM1907=.LTDIE_269 - .Ldebug_info_start
	.long .LDIFF_SYM1907
	.byte 2,35,0,0,7
	.string "Mono_Cecil_SortedTable`1"

.LDIFF_SYM1908=.LTDIE_286 - .Ldebug_info_start
	.long .LDIFF_SYM1908
.LTDIE_286_POINTER:

	.byte 13
.LDIFF_SYM1909=.LTDIE_286 - .Ldebug_info_start
	.long .LDIFF_SYM1909
.LTDIE_286_REFERENCE:

	.byte 14
.LDIFF_SYM1910=.LTDIE_286 - .Ldebug_info_start
	.long .LDIFF_SYM1910
.LTDIE_285:

	.byte 5
	.string "Mono_Cecil_CustomAttributeTable"

	.byte 32,16
.LDIFF_SYM1911=.LTDIE_286 - .Ldebug_info_start
	.long .LDIFF_SYM1911
	.byte 2,35,0,0,7
	.string "Mono_Cecil_CustomAttributeTable"

.LDIFF_SYM1912=.LTDIE_285 - .Ldebug_info_start
	.long .LDIFF_SYM1912
.LTDIE_285_POINTER:

	.byte 13
.LDIFF_SYM1913=.LTDIE_285 - .Ldebug_info_start
	.long .LDIFF_SYM1913
.LTDIE_285_REFERENCE:

	.byte 14
.LDIFF_SYM1914=.LTDIE_285 - .Ldebug_info_start
	.long .LDIFF_SYM1914
.LTDIE_289:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1915=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1915
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1916=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1916
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1917=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1917
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1918=.LTDIE_289 - .Ldebug_info_start
	.long .LDIFF_SYM1918
.LTDIE_289_POINTER:

	.byte 13
.LDIFF_SYM1919=.LTDIE_289 - .Ldebug_info_start
	.long .LDIFF_SYM1919
.LTDIE_289_REFERENCE:

	.byte 14
.LDIFF_SYM1920=.LTDIE_289 - .Ldebug_info_start
	.long .LDIFF_SYM1920
.LTDIE_288:

	.byte 5
	.string "Mono_Cecil_SortedTable`1"

	.byte 32,16
.LDIFF_SYM1921=.LTDIE_289 - .Ldebug_info_start
	.long .LDIFF_SYM1921
	.byte 2,35,0,0,7
	.string "Mono_Cecil_SortedTable`1"

.LDIFF_SYM1922=.LTDIE_288 - .Ldebug_info_start
	.long .LDIFF_SYM1922
.LTDIE_288_POINTER:

	.byte 13
.LDIFF_SYM1923=.LTDIE_288 - .Ldebug_info_start
	.long .LDIFF_SYM1923
.LTDIE_288_REFERENCE:

	.byte 14
.LDIFF_SYM1924=.LTDIE_288 - .Ldebug_info_start
	.long .LDIFF_SYM1924
.LTDIE_287:

	.byte 5
	.string "Mono_Cecil_DeclSecurityTable"

	.byte 32,16
.LDIFF_SYM1925=.LTDIE_288 - .Ldebug_info_start
	.long .LDIFF_SYM1925
	.byte 2,35,0,0,7
	.string "Mono_Cecil_DeclSecurityTable"

.LDIFF_SYM1926=.LTDIE_287 - .Ldebug_info_start
	.long .LDIFF_SYM1926
.LTDIE_287_POINTER:

	.byte 13
.LDIFF_SYM1927=.LTDIE_287 - .Ldebug_info_start
	.long .LDIFF_SYM1927
.LTDIE_287_REFERENCE:

	.byte 14
.LDIFF_SYM1928=.LTDIE_287 - .Ldebug_info_start
	.long .LDIFF_SYM1928
.LTDIE_291:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1929=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1929
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1930=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1930
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1931=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1931
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1932=.LTDIE_291 - .Ldebug_info_start
	.long .LDIFF_SYM1932
.LTDIE_291_POINTER:

	.byte 13
.LDIFF_SYM1933=.LTDIE_291 - .Ldebug_info_start
	.long .LDIFF_SYM1933
.LTDIE_291_REFERENCE:

	.byte 14
.LDIFF_SYM1934=.LTDIE_291 - .Ldebug_info_start
	.long .LDIFF_SYM1934
.LTDIE_290:

	.byte 5
	.string "Mono_Cecil_StandAloneSigTable"

	.byte 32,16
.LDIFF_SYM1935=.LTDIE_291 - .Ldebug_info_start
	.long .LDIFF_SYM1935
	.byte 2,35,0,0,7
	.string "Mono_Cecil_StandAloneSigTable"

.LDIFF_SYM1936=.LTDIE_290 - .Ldebug_info_start
	.long .LDIFF_SYM1936
.LTDIE_290_POINTER:

	.byte 13
.LDIFF_SYM1937=.LTDIE_290 - .Ldebug_info_start
	.long .LDIFF_SYM1937
.LTDIE_290_REFERENCE:

	.byte 14
.LDIFF_SYM1938=.LTDIE_290 - .Ldebug_info_start
	.long .LDIFF_SYM1938
.LTDIE_292:

	.byte 5
	.string "Mono_Cecil_EventMapTable"

	.byte 32,16
.LDIFF_SYM1939=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1939
	.byte 2,35,0,0,7
	.string "Mono_Cecil_EventMapTable"

.LDIFF_SYM1940=.LTDIE_292 - .Ldebug_info_start
	.long .LDIFF_SYM1940
.LTDIE_292_POINTER:

	.byte 13
.LDIFF_SYM1941=.LTDIE_292 - .Ldebug_info_start
	.long .LDIFF_SYM1941
.LTDIE_292_REFERENCE:

	.byte 14
.LDIFF_SYM1942=.LTDIE_292 - .Ldebug_info_start
	.long .LDIFF_SYM1942
.LTDIE_294:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1943=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1943
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1944=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1944
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1945=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1945
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1946=.LTDIE_294 - .Ldebug_info_start
	.long .LDIFF_SYM1946
.LTDIE_294_POINTER:

	.byte 13
.LDIFF_SYM1947=.LTDIE_294 - .Ldebug_info_start
	.long .LDIFF_SYM1947
.LTDIE_294_REFERENCE:

	.byte 14
.LDIFF_SYM1948=.LTDIE_294 - .Ldebug_info_start
	.long .LDIFF_SYM1948
.LTDIE_293:

	.byte 5
	.string "Mono_Cecil_EventTable"

	.byte 32,16
.LDIFF_SYM1949=.LTDIE_294 - .Ldebug_info_start
	.long .LDIFF_SYM1949
	.byte 2,35,0,0,7
	.string "Mono_Cecil_EventTable"

.LDIFF_SYM1950=.LTDIE_293 - .Ldebug_info_start
	.long .LDIFF_SYM1950
.LTDIE_293_POINTER:

	.byte 13
.LDIFF_SYM1951=.LTDIE_293 - .Ldebug_info_start
	.long .LDIFF_SYM1951
.LTDIE_293_REFERENCE:

	.byte 14
.LDIFF_SYM1952=.LTDIE_293 - .Ldebug_info_start
	.long .LDIFF_SYM1952
.LTDIE_295:

	.byte 5
	.string "Mono_Cecil_PropertyMapTable"

	.byte 32,16
.LDIFF_SYM1953=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1953
	.byte 2,35,0,0,7
	.string "Mono_Cecil_PropertyMapTable"

.LDIFF_SYM1954=.LTDIE_295 - .Ldebug_info_start
	.long .LDIFF_SYM1954
.LTDIE_295_POINTER:

	.byte 13
.LDIFF_SYM1955=.LTDIE_295 - .Ldebug_info_start
	.long .LDIFF_SYM1955
.LTDIE_295_REFERENCE:

	.byte 14
.LDIFF_SYM1956=.LTDIE_295 - .Ldebug_info_start
	.long .LDIFF_SYM1956
.LTDIE_297:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1957=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1957
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1958=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1958
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1959=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1959
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1960=.LTDIE_297 - .Ldebug_info_start
	.long .LDIFF_SYM1960
.LTDIE_297_POINTER:

	.byte 13
.LDIFF_SYM1961=.LTDIE_297 - .Ldebug_info_start
	.long .LDIFF_SYM1961
.LTDIE_297_REFERENCE:

	.byte 14
.LDIFF_SYM1962=.LTDIE_297 - .Ldebug_info_start
	.long .LDIFF_SYM1962
.LTDIE_296:

	.byte 5
	.string "Mono_Cecil_PropertyTable"

	.byte 32,16
.LDIFF_SYM1963=.LTDIE_297 - .Ldebug_info_start
	.long .LDIFF_SYM1963
	.byte 2,35,0,0,7
	.string "Mono_Cecil_PropertyTable"

.LDIFF_SYM1964=.LTDIE_296 - .Ldebug_info_start
	.long .LDIFF_SYM1964
.LTDIE_296_POINTER:

	.byte 13
.LDIFF_SYM1965=.LTDIE_296 - .Ldebug_info_start
	.long .LDIFF_SYM1965
.LTDIE_296_REFERENCE:

	.byte 14
.LDIFF_SYM1966=.LTDIE_296 - .Ldebug_info_start
	.long .LDIFF_SYM1966
.LTDIE_298:

	.byte 5
	.string "Mono_Cecil_TypeSpecTable"

	.byte 32,16
.LDIFF_SYM1967=.LTDIE_291 - .Ldebug_info_start
	.long .LDIFF_SYM1967
	.byte 2,35,0,0,7
	.string "Mono_Cecil_TypeSpecTable"

.LDIFF_SYM1968=.LTDIE_298 - .Ldebug_info_start
	.long .LDIFF_SYM1968
.LTDIE_298_POINTER:

	.byte 13
.LDIFF_SYM1969=.LTDIE_298 - .Ldebug_info_start
	.long .LDIFF_SYM1969
.LTDIE_298_REFERENCE:

	.byte 14
.LDIFF_SYM1970=.LTDIE_298 - .Ldebug_info_start
	.long .LDIFF_SYM1970
.LTDIE_299:

	.byte 5
	.string "Mono_Cecil_MethodSpecTable"

	.byte 32,16
.LDIFF_SYM1971=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1971
	.byte 2,35,0,0,7
	.string "Mono_Cecil_MethodSpecTable"

.LDIFF_SYM1972=.LTDIE_299 - .Ldebug_info_start
	.long .LDIFF_SYM1972
.LTDIE_299_POINTER:

	.byte 13
.LDIFF_SYM1973=.LTDIE_299 - .Ldebug_info_start
	.long .LDIFF_SYM1973
.LTDIE_299_REFERENCE:

	.byte 14
.LDIFF_SYM1974=.LTDIE_299 - .Ldebug_info_start
	.long .LDIFF_SYM1974
.LTDIE_301:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1975=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1975
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1976=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1976
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1977=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1977
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1978=.LTDIE_301 - .Ldebug_info_start
	.long .LDIFF_SYM1978
.LTDIE_301_POINTER:

	.byte 13
.LDIFF_SYM1979=.LTDIE_301 - .Ldebug_info_start
	.long .LDIFF_SYM1979
.LTDIE_301_REFERENCE:

	.byte 14
.LDIFF_SYM1980=.LTDIE_301 - .Ldebug_info_start
	.long .LDIFF_SYM1980
.LTDIE_300:

	.byte 5
	.string "Mono_Cecil_DocumentTable"

	.byte 32,16
.LDIFF_SYM1981=.LTDIE_301 - .Ldebug_info_start
	.long .LDIFF_SYM1981
	.byte 2,35,0,0,7
	.string "Mono_Cecil_DocumentTable"

.LDIFF_SYM1982=.LTDIE_300 - .Ldebug_info_start
	.long .LDIFF_SYM1982
.LTDIE_300_POINTER:

	.byte 13
.LDIFF_SYM1983=.LTDIE_300 - .Ldebug_info_start
	.long .LDIFF_SYM1983
.LTDIE_300_REFERENCE:

	.byte 14
.LDIFF_SYM1984=.LTDIE_300 - .Ldebug_info_start
	.long .LDIFF_SYM1984
.LTDIE_302:

	.byte 5
	.string "Mono_Cecil_MethodDebugInformationTable"

	.byte 32,16
.LDIFF_SYM1985=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM1985
	.byte 2,35,0,0,7
	.string "Mono_Cecil_MethodDebugInformationTable"

.LDIFF_SYM1986=.LTDIE_302 - .Ldebug_info_start
	.long .LDIFF_SYM1986
.LTDIE_302_POINTER:

	.byte 13
.LDIFF_SYM1987=.LTDIE_302 - .Ldebug_info_start
	.long .LDIFF_SYM1987
.LTDIE_302_REFERENCE:

	.byte 14
.LDIFF_SYM1988=.LTDIE_302 - .Ldebug_info_start
	.long .LDIFF_SYM1988
.LTDIE_304:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1989=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1989
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM1990=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM1990
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM1991=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM1991
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM1992=.LTDIE_304 - .Ldebug_info_start
	.long .LDIFF_SYM1992
.LTDIE_304_POINTER:

	.byte 13
.LDIFF_SYM1993=.LTDIE_304 - .Ldebug_info_start
	.long .LDIFF_SYM1993
.LTDIE_304_REFERENCE:

	.byte 14
.LDIFF_SYM1994=.LTDIE_304 - .Ldebug_info_start
	.long .LDIFF_SYM1994
.LTDIE_303:

	.byte 5
	.string "Mono_Cecil_LocalScopeTable"

	.byte 32,16
.LDIFF_SYM1995=.LTDIE_304 - .Ldebug_info_start
	.long .LDIFF_SYM1995
	.byte 2,35,0,0,7
	.string "Mono_Cecil_LocalScopeTable"

.LDIFF_SYM1996=.LTDIE_303 - .Ldebug_info_start
	.long .LDIFF_SYM1996
.LTDIE_303_POINTER:

	.byte 13
.LDIFF_SYM1997=.LTDIE_303 - .Ldebug_info_start
	.long .LDIFF_SYM1997
.LTDIE_303_REFERENCE:

	.byte 14
.LDIFF_SYM1998=.LTDIE_303 - .Ldebug_info_start
	.long .LDIFF_SYM1998
.LTDIE_306:

	.byte 5
	.string "Mono_Cecil_MetadataTable`1"

	.byte 32,16
.LDIFF_SYM1999=.LTDIE_270 - .Ldebug_info_start
	.long .LDIFF_SYM1999
	.byte 2,35,0,6
	.string "rows"

.LDIFF_SYM2000=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2000
	.byte 2,35,16,6
	.string "length"

.LDIFF_SYM2001=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2001
	.byte 2,35,24,0,7
	.string "Mono_Cecil_MetadataTable`1"

.LDIFF_SYM2002=.LTDIE_306 - .Ldebug_info_start
	.long .LDIFF_SYM2002
.LTDIE_306_POINTER:

	.byte 13
.LDIFF_SYM2003=.LTDIE_306 - .Ldebug_info_start
	.long .LDIFF_SYM2003
.LTDIE_306_REFERENCE:

	.byte 14
.LDIFF_SYM2004=.LTDIE_306 - .Ldebug_info_start
	.long .LDIFF_SYM2004
.LTDIE_305:

	.byte 5
	.string "Mono_Cecil_LocalVariableTable"

	.byte 32,16
.LDIFF_SYM2005=.LTDIE_306 - .Ldebug_info_start
	.long .LDIFF_SYM2005
	.byte 2,35,0,0,7
	.string "Mono_Cecil_LocalVariableTable"

.LDIFF_SYM2006=.LTDIE_305 - .Ldebug_info_start
	.long .LDIFF_SYM2006
.LTDIE_305_POINTER:

	.byte 13
.LDIFF_SYM2007=.LTDIE_305 - .Ldebug_info_start
	.long .LDIFF_SYM2007
.LTDIE_305_REFERENCE:

	.byte 14
.LDIFF_SYM2008=.LTDIE_305 - .Ldebug_info_start
	.long .LDIFF_SYM2008
.LTDIE_307:

	.byte 5
	.string "Mono_Cecil_LocalConstantTable"

	.byte 32,16
.LDIFF_SYM2009=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM2009
	.byte 2,35,0,0,7
	.string "Mono_Cecil_LocalConstantTable"

.LDIFF_SYM2010=.LTDIE_307 - .Ldebug_info_start
	.long .LDIFF_SYM2010
.LTDIE_307_POINTER:

	.byte 13
.LDIFF_SYM2011=.LTDIE_307 - .Ldebug_info_start
	.long .LDIFF_SYM2011
.LTDIE_307_REFERENCE:

	.byte 14
.LDIFF_SYM2012=.LTDIE_307 - .Ldebug_info_start
	.long .LDIFF_SYM2012
.LTDIE_308:

	.byte 5
	.string "Mono_Cecil_ImportScopeTable"

	.byte 32,16
.LDIFF_SYM2013=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM2013
	.byte 2,35,0,0,7
	.string "Mono_Cecil_ImportScopeTable"

.LDIFF_SYM2014=.LTDIE_308 - .Ldebug_info_start
	.long .LDIFF_SYM2014
.LTDIE_308_POINTER:

	.byte 13
.LDIFF_SYM2015=.LTDIE_308 - .Ldebug_info_start
	.long .LDIFF_SYM2015
.LTDIE_308_REFERENCE:

	.byte 14
.LDIFF_SYM2016=.LTDIE_308 - .Ldebug_info_start
	.long .LDIFF_SYM2016
.LTDIE_309:

	.byte 5
	.string "Mono_Cecil_StateMachineMethodTable"

	.byte 32,16
.LDIFF_SYM2017=.LTDIE_280 - .Ldebug_info_start
	.long .LDIFF_SYM2017
	.byte 2,35,0,0,7
	.string "Mono_Cecil_StateMachineMethodTable"

.LDIFF_SYM2018=.LTDIE_309 - .Ldebug_info_start
	.long .LDIFF_SYM2018
.LTDIE_309_POINTER:

	.byte 13
.LDIFF_SYM2019=.LTDIE_309 - .Ldebug_info_start
	.long .LDIFF_SYM2019
.LTDIE_309_REFERENCE:

	.byte 14
.LDIFF_SYM2020=.LTDIE_309 - .Ldebug_info_start
	.long .LDIFF_SYM2020
.LTDIE_310:

	.byte 5
	.string "Mono_Cecil_CustomDebugInformationTable"

	.byte 32,16
.LDIFF_SYM2021=.LTDIE_286 - .Ldebug_info_start
	.long .LDIFF_SYM2021
	.byte 2,35,0,0,7
	.string "Mono_Cecil_CustomDebugInformationTable"

.LDIFF_SYM2022=.LTDIE_310 - .Ldebug_info_start
	.long .LDIFF_SYM2022
.LTDIE_310_POINTER:

	.byte 13
.LDIFF_SYM2023=.LTDIE_310 - .Ldebug_info_start
	.long .LDIFF_SYM2023
.LTDIE_310_REFERENCE:

	.byte 14
.LDIFF_SYM2024=.LTDIE_310 - .Ldebug_info_start
	.long .LDIFF_SYM2024
.LTDIE_312:

	.byte 5
	.string "_KeyCollection"

	.byte 24,16
.LDIFF_SYM2025=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2025
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM2026=.LTDIE_311_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2026
	.byte 2,35,16,0,7
	.string "_KeyCollection"

.LDIFF_SYM2027=.LTDIE_312 - .Ldebug_info_start
	.long .LDIFF_SYM2027
.LTDIE_312_POINTER:

	.byte 13
.LDIFF_SYM2028=.LTDIE_312 - .Ldebug_info_start
	.long .LDIFF_SYM2028
.LTDIE_312_REFERENCE:

	.byte 14
.LDIFF_SYM2029=.LTDIE_312 - .Ldebug_info_start
	.long .LDIFF_SYM2029
.LTDIE_313:

	.byte 5
	.string "_ValueCollection"

	.byte 24,16
.LDIFF_SYM2030=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2030
	.byte 2,35,0,6
	.string "_dictionary"

.LDIFF_SYM2031=.LTDIE_311_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2031
	.byte 2,35,16,0,7
	.string "_ValueCollection"

.LDIFF_SYM2032=.LTDIE_313 - .Ldebug_info_start
	.long .LDIFF_SYM2032
.LTDIE_313_POINTER:

	.byte 13
.LDIFF_SYM2033=.LTDIE_313 - .Ldebug_info_start
	.long .LDIFF_SYM2033
.LTDIE_313_REFERENCE:

	.byte 14
.LDIFF_SYM2034=.LTDIE_313 - .Ldebug_info_start
	.long .LDIFF_SYM2034
.LTDIE_311:

	.byte 5
	.string "System_Collections_Generic_Dictionary`2"

	.byte 80,16
.LDIFF_SYM2035=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2035
	.byte 2,35,0,6
	.string "_buckets"

.LDIFF_SYM2036=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2036
	.byte 2,35,16,6
	.string "_entries"

.LDIFF_SYM2037=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2037
	.byte 2,35,24,6
	.string "_count"

.LDIFF_SYM2038=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2038
	.byte 2,35,64,6
	.string "_freeList"

.LDIFF_SYM2039=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2039
	.byte 2,35,68,6
	.string "_freeCount"

.LDIFF_SYM2040=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2040
	.byte 2,35,72,6
	.string "_version"

.LDIFF_SYM2041=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2041
	.byte 2,35,76,6
	.string "_comparer"

.LDIFF_SYM2042=.LTDIE_111_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2042
	.byte 2,35,32,6
	.string "_keys"

.LDIFF_SYM2043=.LTDIE_312_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2043
	.byte 2,35,40,6
	.string "_values"

.LDIFF_SYM2044=.LTDIE_313_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2044
	.byte 2,35,48,6
	.string "_syncRoot"

.LDIFF_SYM2045=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2045
	.byte 2,35,56,0,7
	.string "System_Collections_Generic_Dictionary`2"

.LDIFF_SYM2046=.LTDIE_311 - .Ldebug_info_start
	.long .LDIFF_SYM2046
.LTDIE_311_POINTER:

	.byte 13
.LDIFF_SYM2047=.LTDIE_311 - .Ldebug_info_start
	.long .LDIFF_SYM2047
.LTDIE_311_REFERENCE:

	.byte 14
.LDIFF_SYM2048=.LTDIE_311 - .Ldebug_info_start
	.long .LDIFF_SYM2048
.LTDIE_232:

	.byte 5
	.string "Mono_Cecil_MetadataBuilder"

	.byte 176,3,16
.LDIFF_SYM2049=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2049
	.byte 2,35,0,6
	.string "module"

.LDIFF_SYM2050=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2050
	.byte 2,35,16,6
	.string "symbol_writer_provider"

.LDIFF_SYM2051=.LTDIE_233_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2051
	.byte 2,35,24,6
	.string "symbol_writer"

.LDIFF_SYM2052=.LTDIE_234_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2052
	.byte 2,35,32,6
	.string "text_map"

.LDIFF_SYM2053=.LTDIE_235_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2053
	.byte 2,35,40,6
	.string "fq_name"

.LDIFF_SYM2054=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2054
	.byte 2,35,48,6
	.string "timestamp"

.LDIFF_SYM2055=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2055
	.byte 3,35,136,3,6
	.string "type_ref_map"

.LDIFF_SYM2056=.LTDIE_236_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2056
	.byte 2,35,56,6
	.string "type_spec_map"

.LDIFF_SYM2057=.LTDIE_240_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2057
	.byte 2,35,64,6
	.string "member_ref_map"

.LDIFF_SYM2058=.LTDIE_236_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2058
	.byte 2,35,72,6
	.string "method_spec_map"

.LDIFF_SYM2059=.LTDIE_243_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2059
	.byte 2,35,80,6
	.string "generic_parameters"

.LDIFF_SYM2060=.LTDIE_191_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2060
	.byte 2,35,88,6
	.string "code"

.LDIFF_SYM2061=.LTDIE_247_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2061
	.byte 2,35,96,6
	.string "data"

.LDIFF_SYM2062=.LTDIE_252_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2062
	.byte 2,35,104,6
	.string "resources"

.LDIFF_SYM2063=.LTDIE_253_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2063
	.byte 2,35,112,6
	.string "string_heap"

.LDIFF_SYM2064=.LTDIE_254_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2064
	.byte 2,35,120,6
	.string "guid_heap"

.LDIFF_SYM2065=.LTDIE_259_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2065
	.byte 3,35,128,1,6
	.string "user_string_heap"

.LDIFF_SYM2066=.LTDIE_264_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2066
	.byte 3,35,136,1,6
	.string "blob_heap"

.LDIFF_SYM2067=.LTDIE_265_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2067
	.byte 3,35,144,1,6
	.string "table_heap"

.LDIFF_SYM2068=.LTDIE_266_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2068
	.byte 3,35,152,1,6
	.string "pdb_heap"

.LDIFF_SYM2069=.LTDIE_267_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2069
	.byte 3,35,160,1,6
	.string "entry_point"

.LDIFF_SYM2070=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2070
	.byte 3,35,140,3,6
	.string "type_rid"

.LDIFF_SYM2071=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2071
	.byte 3,35,144,3,6
	.string "field_rid"

.LDIFF_SYM2072=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2072
	.byte 3,35,148,3,6
	.string "method_rid"

.LDIFF_SYM2073=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2073
	.byte 3,35,152,3,6
	.string "param_rid"

.LDIFF_SYM2074=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2074
	.byte 3,35,156,3,6
	.string "property_rid"

.LDIFF_SYM2075=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2075
	.byte 3,35,160,3,6
	.string "event_rid"

.LDIFF_SYM2076=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2076
	.byte 3,35,164,3,6
	.string "local_variable_rid"

.LDIFF_SYM2077=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2077
	.byte 3,35,168,3,6
	.string "local_constant_rid"

.LDIFF_SYM2078=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2078
	.byte 3,35,172,3,6
	.string "type_ref_table"

.LDIFF_SYM2079=.LTDIE_268_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2079
	.byte 3,35,168,1,6
	.string "type_def_table"

.LDIFF_SYM2080=.LTDIE_271_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2080
	.byte 3,35,176,1,6
	.string "field_table"

.LDIFF_SYM2081=.LTDIE_273_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2081
	.byte 3,35,184,1,6
	.string "method_table"

.LDIFF_SYM2082=.LTDIE_275_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2082
	.byte 3,35,192,1,6
	.string "param_table"

.LDIFF_SYM2083=.LTDIE_277_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2083
	.byte 3,35,200,1,6
	.string "iface_impl_table"

.LDIFF_SYM2084=.LTDIE_279_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2084
	.byte 3,35,208,1,6
	.string "member_ref_table"

.LDIFF_SYM2085=.LTDIE_281_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2085
	.byte 3,35,216,1,6
	.string "constant_table"

.LDIFF_SYM2086=.LTDIE_282_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2086
	.byte 3,35,224,1,6
	.string "custom_attribute_table"

.LDIFF_SYM2087=.LTDIE_285_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2087
	.byte 3,35,232,1,6
	.string "declsec_table"

.LDIFF_SYM2088=.LTDIE_287_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2088
	.byte 3,35,240,1,6
	.string "standalone_sig_table"

.LDIFF_SYM2089=.LTDIE_290_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2089
	.byte 3,35,248,1,6
	.string "event_map_table"

.LDIFF_SYM2090=.LTDIE_292_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2090
	.byte 3,35,128,2,6
	.string "event_table"

.LDIFF_SYM2091=.LTDIE_293_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2091
	.byte 3,35,136,2,6
	.string "property_map_table"

.LDIFF_SYM2092=.LTDIE_295_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2092
	.byte 3,35,144,2,6
	.string "property_table"

.LDIFF_SYM2093=.LTDIE_296_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2093
	.byte 3,35,152,2,6
	.string "typespec_table"

.LDIFF_SYM2094=.LTDIE_298_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2094
	.byte 3,35,160,2,6
	.string "method_spec_table"

.LDIFF_SYM2095=.LTDIE_299_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2095
	.byte 3,35,168,2,6
	.string "metadata_builder"

.LDIFF_SYM2096=.LTDIE_232_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2096
	.byte 3,35,176,2,6
	.string "document_table"

.LDIFF_SYM2097=.LTDIE_300_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2097
	.byte 3,35,184,2,6
	.string "method_debug_information_table"

.LDIFF_SYM2098=.LTDIE_302_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2098
	.byte 3,35,192,2,6
	.string "local_scope_table"

.LDIFF_SYM2099=.LTDIE_303_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2099
	.byte 3,35,200,2,6
	.string "local_variable_table"

.LDIFF_SYM2100=.LTDIE_305_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2100
	.byte 3,35,208,2,6
	.string "local_constant_table"

.LDIFF_SYM2101=.LTDIE_307_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2101
	.byte 3,35,216,2,6
	.string "import_scope_table"

.LDIFF_SYM2102=.LTDIE_308_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2102
	.byte 3,35,224,2,6
	.string "state_machine_method_table"

.LDIFF_SYM2103=.LTDIE_309_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2103
	.byte 3,35,232,2,6
	.string "custom_debug_information_table"

.LDIFF_SYM2104=.LTDIE_310_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2104
	.byte 3,35,240,2,6
	.string "import_scope_map"

.LDIFF_SYM2105=.LTDIE_243_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2105
	.byte 3,35,248,2,6
	.string "document_map"

.LDIFF_SYM2106=.LTDIE_311_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2106
	.byte 3,35,128,3,0,7
	.string "Mono_Cecil_MetadataBuilder"

.LDIFF_SYM2107=.LTDIE_232 - .Ldebug_info_start
	.long .LDIFF_SYM2107
.LTDIE_232_POINTER:

	.byte 13
.LDIFF_SYM2108=.LTDIE_232 - .Ldebug_info_start
	.long .LDIFF_SYM2108
.LTDIE_232_REFERENCE:

	.byte 14
.LDIFF_SYM2109=.LTDIE_232 - .Ldebug_info_start
	.long .LDIFF_SYM2109
.LTDIE_11:

	.byte 5
	.string "Mono_Cecil_ModuleDefinition"

	.byte 160,2,16
.LDIFF_SYM2110=.LTDIE_12 - .Ldebug_info_start
	.long .LDIFF_SYM2110
	.byte 2,35,0,6
	.string "Image"

.LDIFF_SYM2111=.LTDIE_13_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2111
	.byte 2,35,32,6
	.string "MetadataSystem"

.LDIFF_SYM2112=.LTDIE_42_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2112
	.byte 2,35,40,6
	.string "ReadingMode"

.LDIFF_SYM2113=.LTDIE_83 - .Ldebug_info_start
	.long .LDIFF_SYM2113
	.byte 3,35,232,1,6
	.string "SymbolReaderProvider"

.LDIFF_SYM2114=.LTDIE_84_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2114
	.byte 2,35,48,6
	.string "symbol_reader"

.LDIFF_SYM2115=.LTDIE_85_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2115
	.byte 2,35,56,6
	.string "assembly_resolver"

.LDIFF_SYM2116=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2116
	.byte 2,35,64,6
	.string "metadata_resolver"

.LDIFF_SYM2117=.LTDIE_86_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2117
	.byte 2,35,80,6
	.string "type_system"

.LDIFF_SYM2118=.LTDIE_87_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2118
	.byte 2,35,88,6
	.string "reader"

.LDIFF_SYM2119=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2119
	.byte 2,35,96,6
	.string "file_name"

.LDIFF_SYM2120=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2120
	.byte 2,35,104,6
	.string "runtime_version"

.LDIFF_SYM2121=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2121
	.byte 2,35,112,6
	.string "kind"

.LDIFF_SYM2122=.LTDIE_14 - .Ldebug_info_start
	.long .LDIFF_SYM2122
	.byte 3,35,236,1,6
	.string "projections"

.LDIFF_SYM2123=.LTDIE_211_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2123
	.byte 2,35,120,6
	.string "metadata_kind"

.LDIFF_SYM2124=.LTDIE_213 - .Ldebug_info_start
	.long .LDIFF_SYM2124
	.byte 3,35,240,1,6
	.string "runtime"

.LDIFF_SYM2125=.LTDIE_214 - .Ldebug_info_start
	.long .LDIFF_SYM2125
	.byte 3,35,244,1,6
	.string "architecture"

.LDIFF_SYM2126=.LTDIE_15 - .Ldebug_info_start
	.long .LDIFF_SYM2126
	.byte 3,35,248,1,6
	.string "attributes"

.LDIFF_SYM2127=.LTDIE_21 - .Ldebug_info_start
	.long .LDIFF_SYM2127
	.byte 3,35,252,1,6
	.string "characteristics"

.LDIFF_SYM2128=.LTDIE_16 - .Ldebug_info_start
	.long .LDIFF_SYM2128
	.byte 3,35,128,2,6
	.string "mvid"

.LDIFF_SYM2129=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2129
	.byte 3,35,132,2,6
	.string "linker_version"

.LDIFF_SYM2130=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2130
	.byte 3,35,148,2,6
	.string "subsystem_major"

.LDIFF_SYM2131=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2131
	.byte 3,35,150,2,6
	.string "subsystem_minor"

.LDIFF_SYM2132=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2132
	.byte 3,35,152,2,6
	.string "timestamp"

.LDIFF_SYM2133=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2133
	.byte 3,35,156,2,6
	.string "assembly"

.LDIFF_SYM2134=.LTDIE_215_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2134
	.byte 3,35,128,1,6
	.string "entry_point"

.LDIFF_SYM2135=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2135
	.byte 3,35,136,1,6
	.string "reflection_importer"

.LDIFF_SYM2136=.LTDIE_220_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2136
	.byte 3,35,144,1,6
	.string "metadata_importer"

.LDIFF_SYM2137=.LTDIE_221_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2137
	.byte 3,35,152,1,6
	.string "custom_attributes"

.LDIFF_SYM2138=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2138
	.byte 3,35,160,1,6
	.string "references"

.LDIFF_SYM2139=.LTDIE_222_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2139
	.byte 3,35,168,1,6
	.string "modules"

.LDIFF_SYM2140=.LTDIE_223_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2140
	.byte 3,35,176,1,6
	.string "resources"

.LDIFF_SYM2141=.LTDIE_224_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2141
	.byte 3,35,184,1,6
	.string "exported_types"

.LDIFF_SYM2142=.LTDIE_225_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2142
	.byte 3,35,192,1,6
	.string "types"

.LDIFF_SYM2143=.LTDIE_226_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2143
	.byte 3,35,200,1,6
	.string "custom_infos"

.LDIFF_SYM2144=.LTDIE_202_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2144
	.byte 3,35,208,1,6
	.string "metadata_builder"

.LDIFF_SYM2145=.LTDIE_232_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2145
	.byte 3,35,216,1,6
	.string "module_lock"

.LDIFF_SYM2146=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2146
	.byte 3,35,224,1,0,7
	.string "Mono_Cecil_ModuleDefinition"

.LDIFF_SYM2147=.LTDIE_11 - .Ldebug_info_start
	.long .LDIFF_SYM2147
.LTDIE_11_POINTER:

	.byte 13
.LDIFF_SYM2148=.LTDIE_11 - .Ldebug_info_start
	.long .LDIFF_SYM2148
.LTDIE_11_REFERENCE:

	.byte 14
.LDIFF_SYM2149=.LTDIE_11 - .Ldebug_info_start
	.long .LDIFF_SYM2149
.LTDIE_314:

	.byte 8
	.string "Mono_Cecil_Metadata_ElementType"

	.byte 1
.LDIFF_SYM2150=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM2150
	.byte 9
	.string "None"

	.byte 0,9
	.string "Void"

	.byte 1,9
	.string "Boolean"

	.byte 2,9
	.string "Char"

	.byte 3,9
	.string "I1"

	.byte 4,9
	.string "U1"

	.byte 5,9
	.string "I2"

	.byte 6,9
	.string "U2"

	.byte 7,9
	.string "I4"

	.byte 8,9
	.string "U4"

	.byte 9,9
	.string "I8"

	.byte 10,9
	.string "U8"

	.byte 11,9
	.string "R4"

	.byte 12,9
	.string "R8"

	.byte 13,9
	.string "String"

	.byte 14,9
	.string "Ptr"

	.byte 15,9
	.string "ByRef"

	.byte 16,9
	.string "ValueType"

	.byte 17,9
	.string "Class"

	.byte 18,9
	.string "Var"

	.byte 19,9
	.string "Array"

	.byte 20,9
	.string "GenericInst"

	.byte 21,9
	.string "TypedByRef"

	.byte 22,9
	.string "I"

	.byte 24,9
	.string "U"

	.byte 25,9
	.string "FnPtr"

	.byte 27,9
	.string "Object"

	.byte 28,9
	.string "SzArray"

	.byte 29,9
	.string "MVar"

	.byte 30,9
	.string "CModReqD"

	.byte 31,9
	.string "CModOpt"

	.byte 32,9
	.string "Internal"

	.byte 33,9
	.string "Modifier"

	.byte 192,0,9
	.string "Sentinel"

	.byte 193,0,9
	.string "Pinned"

	.byte 197,0,9
	.string "Type"

	.byte 208,0,9
	.string "Boxed"

	.byte 209,0,9
	.string "Enum"

	.byte 213,0,0,7
	.string "Mono_Cecil_Metadata_ElementType"

.LDIFF_SYM2151=.LTDIE_314 - .Ldebug_info_start
	.long .LDIFF_SYM2151
.LTDIE_314_POINTER:

	.byte 13
.LDIFF_SYM2152=.LTDIE_314 - .Ldebug_info_start
	.long .LDIFF_SYM2152
.LTDIE_314_REFERENCE:

	.byte 14
.LDIFF_SYM2153=.LTDIE_314 - .Ldebug_info_start
	.long .LDIFF_SYM2153
.LTDIE_8:

	.byte 5
	.string "Mono_Cecil_TypeReference"

	.byte 96,16
.LDIFF_SYM2154=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2154
	.byte 2,35,0,6
	.string "namespace"

.LDIFF_SYM2155=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2155
	.byte 2,35,48,6
	.string "value_type"

.LDIFF_SYM2156=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2156
	.byte 2,35,88,6
	.string "scope"

.LDIFF_SYM2157=.LTDIE_10_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2157
	.byte 2,35,56,6
	.string "module"

.LDIFF_SYM2158=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2158
	.byte 2,35,64,6
	.string "etype"

.LDIFF_SYM2159=.LTDIE_314 - .Ldebug_info_start
	.long .LDIFF_SYM2159
	.byte 2,35,89,6
	.string "fullname"

.LDIFF_SYM2160=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2160
	.byte 2,35,72,6
	.string "generic_parameters"

.LDIFF_SYM2161=.LTDIE_191_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2161
	.byte 2,35,80,0,7
	.string "Mono_Cecil_TypeReference"

.LDIFF_SYM2162=.LTDIE_8 - .Ldebug_info_start
	.long .LDIFF_SYM2162
.LTDIE_8_POINTER:

	.byte 13
.LDIFF_SYM2163=.LTDIE_8 - .Ldebug_info_start
	.long .LDIFF_SYM2163
.LTDIE_8_REFERENCE:

	.byte 14
.LDIFF_SYM2164=.LTDIE_8 - .Ldebug_info_start
	.long .LDIFF_SYM2164
.LTDIE_7:

	.byte 5
	.string "Mono_Cecil_MemberReference"

	.byte 48,16
.LDIFF_SYM2165=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2165
	.byte 2,35,0,6
	.string "name"

.LDIFF_SYM2166=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2166
	.byte 2,35,16,6
	.string "declaring_type"

.LDIFF_SYM2167=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2167
	.byte 2,35,24,6
	.string "token"

.LDIFF_SYM2168=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2168
	.byte 2,35,40,6
	.string "projection"

.LDIFF_SYM2169=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2169
	.byte 2,35,32,0,7
	.string "Mono_Cecil_MemberReference"

.LDIFF_SYM2170=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2170
.LTDIE_7_POINTER:

	.byte 13
.LDIFF_SYM2171=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2171
.LTDIE_7_REFERENCE:

	.byte 14
.LDIFF_SYM2172=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2172
.LTDIE_6:

	.byte 5
	.string "Mono_Cecil_FieldReference"

	.byte 56,16
.LDIFF_SYM2173=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2173
	.byte 2,35,0,6
	.string "field_type"

.LDIFF_SYM2174=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2174
	.byte 2,35,48,0,7
	.string "Mono_Cecil_FieldReference"

.LDIFF_SYM2175=.LTDIE_6 - .Ldebug_info_start
	.long .LDIFF_SYM2175
.LTDIE_6_POINTER:

	.byte 13
.LDIFF_SYM2176=.LTDIE_6 - .Ldebug_info_start
	.long .LDIFF_SYM2176
.LTDIE_6_REFERENCE:

	.byte 14
.LDIFF_SYM2177=.LTDIE_6 - .Ldebug_info_start
	.long .LDIFF_SYM2177
.LTDIE_5:

	.byte 5
	.string "Mono_Cecil_FieldDefinition"

	.byte 104,16
.LDIFF_SYM2178=.LTDIE_6 - .Ldebug_info_start
	.long .LDIFF_SYM2178
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM2179=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2179
	.byte 2,35,88,6
	.string "custom_attributes"

.LDIFF_SYM2180=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2180
	.byte 2,35,56,6
	.string "offset"

.LDIFF_SYM2181=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2181
	.byte 2,35,92,6
	.string "rva"

.LDIFF_SYM2182=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2182
	.byte 2,35,96,6
	.string "initial_value"

.LDIFF_SYM2183=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2183
	.byte 2,35,64,6
	.string "constant"

.LDIFF_SYM2184=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2184
	.byte 2,35,72,6
	.string "marshal_info"

.LDIFF_SYM2185=.LTDIE_188_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2185
	.byte 2,35,80,0,7
	.string "Mono_Cecil_FieldDefinition"

.LDIFF_SYM2186=.LTDIE_5 - .Ldebug_info_start
	.long .LDIFF_SYM2186
.LTDIE_5_POINTER:

	.byte 13
.LDIFF_SYM2187=.LTDIE_5 - .Ldebug_info_start
	.long .LDIFF_SYM2187
.LTDIE_5_REFERENCE:

	.byte 14
.LDIFF_SYM2188=.LTDIE_5 - .Ldebug_info_start
	.long .LDIFF_SYM2188
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteField"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteField_Mono_Cecil_FieldDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteField"
	.quad .Lm_1
	.quad .Lme_1

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2189=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2189
	.byte 2,119,0,3
	.string "field"

.LDIFF_SYM2190=.LTDIE_5_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2190
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2191=.Lfde1_end - .Lfde1_start
	.long .LDIFF_SYM2191
.Lfde1_start:

	.long 0
	.balign 8
	.quad .Lm_1

.LDIFF_SYM2192=.Lme_1 - .Lm_1
	.long .LDIFF_SYM2192
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde1_end:

.section ".debug_info"
.subsection 0
.LTDIE_316:

	.byte 5
	.string "Mono_Cecil_EventReference"

	.byte 56,16
.LDIFF_SYM2193=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2193
	.byte 2,35,0,6
	.string "event_type"

.LDIFF_SYM2194=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2194
	.byte 2,35,48,0,7
	.string "Mono_Cecil_EventReference"

.LDIFF_SYM2195=.LTDIE_316 - .Ldebug_info_start
	.long .LDIFF_SYM2195
.LTDIE_316_POINTER:

	.byte 13
.LDIFF_SYM2196=.LTDIE_316 - .Ldebug_info_start
	.long .LDIFF_SYM2196
.LTDIE_316_REFERENCE:

	.byte 14
.LDIFF_SYM2197=.LTDIE_316 - .Ldebug_info_start
	.long .LDIFF_SYM2197
.LTDIE_317:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2198=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2198
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2199=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2199
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2200=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2200
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2201=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2201
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2202=.LTDIE_317 - .Ldebug_info_start
	.long .LDIFF_SYM2202
.LTDIE_317_POINTER:

	.byte 13
.LDIFF_SYM2203=.LTDIE_317 - .Ldebug_info_start
	.long .LDIFF_SYM2203
.LTDIE_317_REFERENCE:

	.byte 14
.LDIFF_SYM2204=.LTDIE_317 - .Ldebug_info_start
	.long .LDIFF_SYM2204
.LTDIE_315:

	.byte 5
	.string "Mono_Cecil_EventDefinition"

	.byte 104,16
.LDIFF_SYM2205=.LTDIE_316 - .Ldebug_info_start
	.long .LDIFF_SYM2205
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM2206=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2206
	.byte 2,35,96,6
	.string "custom_attributes"

.LDIFF_SYM2207=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2207
	.byte 2,35,56,6
	.string "add_method"

.LDIFF_SYM2208=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2208
	.byte 2,35,64,6
	.string "invoke_method"

.LDIFF_SYM2209=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2209
	.byte 2,35,72,6
	.string "remove_method"

.LDIFF_SYM2210=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2210
	.byte 2,35,80,6
	.string "other_methods"

.LDIFF_SYM2211=.LTDIE_317_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2211
	.byte 2,35,88,0,7
	.string "Mono_Cecil_EventDefinition"

.LDIFF_SYM2212=.LTDIE_315 - .Ldebug_info_start
	.long .LDIFF_SYM2212
.LTDIE_315_POINTER:

	.byte 13
.LDIFF_SYM2213=.LTDIE_315 - .Ldebug_info_start
	.long .LDIFF_SYM2213
.LTDIE_315_REFERENCE:

	.byte 14
.LDIFF_SYM2214=.LTDIE_315 - .Ldebug_info_start
	.long .LDIFF_SYM2214
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteEvent"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteEvent_Mono_Cecil_EventDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteEvent"
	.quad .Lm_2
	.quad .Lme_2

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2215=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2215
	.byte 2,119,0,3
	.string "event"

.LDIFF_SYM2216=.LTDIE_315_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2216
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2217=.Lfde2_end - .Lfde2_start
	.long .LDIFF_SYM2217
.Lfde2_start:

	.long 0
	.balign 8
	.quad .Lm_2

.LDIFF_SYM2218=.Lme_2 - .Lm_2
	.long .LDIFF_SYM2218
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde2_end:

.section ".debug_info"
.subsection 0
.LTDIE_319:

	.byte 5
	.string "System_Int16"

	.byte 18,16
.LDIFF_SYM2219=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM2219
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM2220=.LDIE_I2 - .Ldebug_info_start
	.long .LDIFF_SYM2220
	.byte 2,35,16,0,7
	.string "System_Int16"

.LDIFF_SYM2221=.LTDIE_319 - .Ldebug_info_start
	.long .LDIFF_SYM2221
.LTDIE_319_POINTER:

	.byte 13
.LDIFF_SYM2222=.LTDIE_319 - .Ldebug_info_start
	.long .LDIFF_SYM2222
.LTDIE_319_REFERENCE:

	.byte 14
.LDIFF_SYM2223=.LTDIE_319 - .Ldebug_info_start
	.long .LDIFF_SYM2223
.LTDIE_321:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2224=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2224
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2225=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2225
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2226=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2226
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2227=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2227
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2228=.LTDIE_321 - .Ldebug_info_start
	.long .LDIFF_SYM2228
.LTDIE_321_POINTER:

	.byte 13
.LDIFF_SYM2229=.LTDIE_321 - .Ldebug_info_start
	.long .LDIFF_SYM2229
.LTDIE_321_REFERENCE:

	.byte 14
.LDIFF_SYM2230=.LTDIE_321 - .Ldebug_info_start
	.long .LDIFF_SYM2230
.LTDIE_320:

	.byte 5
	.string "Mono_Cecil_InterfaceImplementationCollection"

	.byte 40,16
.LDIFF_SYM2231=.LTDIE_321 - .Ldebug_info_start
	.long .LDIFF_SYM2231
	.byte 2,35,0,6
	.string "type"

.LDIFF_SYM2232=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2232
	.byte 2,35,32,0,7
	.string "Mono_Cecil_InterfaceImplementationCollection"

.LDIFF_SYM2233=.LTDIE_320 - .Ldebug_info_start
	.long .LDIFF_SYM2233
.LTDIE_320_POINTER:

	.byte 13
.LDIFF_SYM2234=.LTDIE_320 - .Ldebug_info_start
	.long .LDIFF_SYM2234
.LTDIE_320_REFERENCE:

	.byte 14
.LDIFF_SYM2235=.LTDIE_320 - .Ldebug_info_start
	.long .LDIFF_SYM2235
.LTDIE_322:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2236=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2236
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2237=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2237
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2238=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2238
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2239=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2239
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2240=.LTDIE_322 - .Ldebug_info_start
	.long .LDIFF_SYM2240
.LTDIE_322_POINTER:

	.byte 13
.LDIFF_SYM2241=.LTDIE_322 - .Ldebug_info_start
	.long .LDIFF_SYM2241
.LTDIE_322_REFERENCE:

	.byte 14
.LDIFF_SYM2242=.LTDIE_322 - .Ldebug_info_start
	.long .LDIFF_SYM2242
.LTDIE_323:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2243=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2243
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2244=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2244
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2245=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2245
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2246=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2246
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2247=.LTDIE_323 - .Ldebug_info_start
	.long .LDIFF_SYM2247
.LTDIE_323_POINTER:

	.byte 13
.LDIFF_SYM2248=.LTDIE_323 - .Ldebug_info_start
	.long .LDIFF_SYM2248
.LTDIE_323_REFERENCE:

	.byte 14
.LDIFF_SYM2249=.LTDIE_323 - .Ldebug_info_start
	.long .LDIFF_SYM2249
.LTDIE_324:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2250=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2250
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2251=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2251
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2252=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2252
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2253=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2253
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2254=.LTDIE_324 - .Ldebug_info_start
	.long .LDIFF_SYM2254
.LTDIE_324_POINTER:

	.byte 13
.LDIFF_SYM2255=.LTDIE_324 - .Ldebug_info_start
	.long .LDIFF_SYM2255
.LTDIE_324_REFERENCE:

	.byte 14
.LDIFF_SYM2256=.LTDIE_324 - .Ldebug_info_start
	.long .LDIFF_SYM2256
.LTDIE_318:

	.byte 5
	.string "Mono_Cecil_TypeDefinition"

	.byte 200,1,16
.LDIFF_SYM2257=.LTDIE_8 - .Ldebug_info_start
	.long .LDIFF_SYM2257
	.byte 2,35,0,6
	.string "attributes"

.LDIFF_SYM2258=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2258
	.byte 3,35,168,1,6
	.string "base_type"

.LDIFF_SYM2259=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2259
	.byte 2,35,96,6
	.string "fields_range"

.LDIFF_SYM2260=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2260
	.byte 3,35,172,1,6
	.string "methods_range"

.LDIFF_SYM2261=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2261
	.byte 3,35,180,1,6
	.string "packing_size"

.LDIFF_SYM2262=.LDIE_I2 - .Ldebug_info_start
	.long .LDIFF_SYM2262
	.byte 3,35,188,1,6
	.string "class_size"

.LDIFF_SYM2263=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2263
	.byte 3,35,192,1,6
	.string "interfaces"

.LDIFF_SYM2264=.LTDIE_320_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2264
	.byte 2,35,104,6
	.string "nested_types"

.LDIFF_SYM2265=.LTDIE_227_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2265
	.byte 2,35,112,6
	.string "methods"

.LDIFF_SYM2266=.LTDIE_317_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2266
	.byte 2,35,120,6
	.string "fields"

.LDIFF_SYM2267=.LTDIE_322_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2267
	.byte 3,35,128,1,6
	.string "events"

.LDIFF_SYM2268=.LTDIE_323_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2268
	.byte 3,35,136,1,6
	.string "properties"

.LDIFF_SYM2269=.LTDIE_324_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2269
	.byte 3,35,144,1,6
	.string "custom_attributes"

.LDIFF_SYM2270=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2270
	.byte 3,35,152,1,6
	.string "security_declarations"

.LDIFF_SYM2271=.LTDIE_193_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2271
	.byte 3,35,160,1,0,7
	.string "Mono_Cecil_TypeDefinition"

.LDIFF_SYM2272=.LTDIE_318 - .Ldebug_info_start
	.long .LDIFF_SYM2272
.LTDIE_318_POINTER:

	.byte 13
.LDIFF_SYM2273=.LTDIE_318 - .Ldebug_info_start
	.long .LDIFF_SYM2273
.LTDIE_318_REFERENCE:

	.byte 14
.LDIFF_SYM2274=.LTDIE_318 - .Ldebug_info_start
	.long .LDIFF_SYM2274
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteType"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteType_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteType"
	.quad .Lm_3
	.quad .Lme_3

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2275=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2275
	.byte 2,119,0,3
	.string "type"

.LDIFF_SYM2276=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2276
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2277=.Lfde3_end - .Lfde3_start
	.long .LDIFF_SYM2277
.Lfde3_start:

	.long 0
	.balign 8
	.quad .Lm_3

.LDIFF_SYM2278=.Lme_3 - .Lm_3
	.long .LDIFF_SYM2278
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde3_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteMethod"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteMethod_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteMethod"
	.quad .Lm_4
	.quad .Lme_4

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2279=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2279
	.byte 1,94,3
	.string "method"

.LDIFF_SYM2280=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2280
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2281=.Lfde4_end - .Lfde4_start
	.long .LDIFF_SYM2281
.Lfde4_start:

	.long 0
	.balign 8
	.quad .Lm_4

.LDIFF_SYM2282=.Lme_4 - .Lm_4
	.long .LDIFF_SYM2282
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde4_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:IsConversionOperator"
	.string "Mono_Cecil_Rocks_DocCommentId_IsConversionOperator_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:IsConversionOperator"
	.quad .Lm_5
	.quad .Lme_5

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2283=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2283
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2284=.Lfde5_end - .Lfde5_start
	.long .LDIFF_SYM2284
.Lfde5_start:

	.long 0
	.balign 8
	.quad .Lm_5

.LDIFF_SYM2285=.Lme_5 - .Lm_5
	.long .LDIFF_SYM2285
	.long 0
	.byte 68,14,16,68,143,2,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde5_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteReturnType"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteReturnType_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteReturnType"
	.quad .Lm_6
	.quad .Lme_6

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2286=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2286
	.byte 2,119,0,3
	.string "method"

.LDIFF_SYM2287=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2287
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2288=.Lfde6_end - .Lfde6_start
	.long .LDIFF_SYM2288
.Lfde6_start:

	.long 0
	.balign 8
	.quad .Lm_6

.LDIFF_SYM2289=.Lme_6 - .Lm_6
	.long .LDIFF_SYM2289
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde6_end:

.section ".debug_info"
.subsection 0
.LTDIE_326:

	.byte 5
	.string "Mono_Cecil_PropertyReference"

	.byte 56,16
.LDIFF_SYM2290=.LTDIE_7 - .Ldebug_info_start
	.long .LDIFF_SYM2290
	.byte 2,35,0,6
	.string "property_type"

.LDIFF_SYM2291=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2291
	.byte 2,35,48,0,7
	.string "Mono_Cecil_PropertyReference"

.LDIFF_SYM2292=.LTDIE_326 - .Ldebug_info_start
	.long .LDIFF_SYM2292
.LTDIE_326_POINTER:

	.byte 13
.LDIFF_SYM2293=.LTDIE_326 - .Ldebug_info_start
	.long .LDIFF_SYM2293
.LTDIE_326_REFERENCE:

	.byte 14
.LDIFF_SYM2294=.LTDIE_326 - .Ldebug_info_start
	.long .LDIFF_SYM2294
.LTDIE_325:

	.byte 5
	.string "Mono_Cecil_PropertyDefinition"

	.byte 104,16
.LDIFF_SYM2295=.LTDIE_326 - .Ldebug_info_start
	.long .LDIFF_SYM2295
	.byte 2,35,0,6
	.string "has_this"

.LDIFF_SYM2296=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2296
	.byte 2,35,96,6
	.string "attributes"

.LDIFF_SYM2297=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2297
	.byte 2,35,98,6
	.string "custom_attributes"

.LDIFF_SYM2298=.LTDIE_187_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2298
	.byte 2,35,56,6
	.string "get_method"

.LDIFF_SYM2299=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2299
	.byte 2,35,64,6
	.string "set_method"

.LDIFF_SYM2300=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2300
	.byte 2,35,72,6
	.string "other_methods"

.LDIFF_SYM2301=.LTDIE_317_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2301
	.byte 2,35,80,6
	.string "constant"

.LDIFF_SYM2302=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2302
	.byte 2,35,88,0,7
	.string "Mono_Cecil_PropertyDefinition"

.LDIFF_SYM2303=.LTDIE_325 - .Ldebug_info_start
	.long .LDIFF_SYM2303
.LTDIE_325_POINTER:

	.byte 13
.LDIFF_SYM2304=.LTDIE_325 - .Ldebug_info_start
	.long .LDIFF_SYM2304
.LTDIE_325_REFERENCE:

	.byte 14
.LDIFF_SYM2305=.LTDIE_325 - .Ldebug_info_start
	.long .LDIFF_SYM2305
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteProperty"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteProperty_Mono_Cecil_PropertyDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteProperty"
	.quad .Lm_7
	.quad .Lme_7

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2306=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2306
	.byte 2,119,8,3
	.string "property"

.LDIFF_SYM2307=.LTDIE_325_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2307
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2308=.Lfde7_end - .Lfde7_start
	.long .LDIFF_SYM2308
.Lfde7_start:

	.long 0
	.balign 8
	.quad .Lm_7

.LDIFF_SYM2309=.Lme_7 - .Lm_7
	.long .LDIFF_SYM2309
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde7_end:

.section ".debug_info"
.subsection 0
.LTDIE_327:

	.byte 17
	.string "System_Collections_Generic_IList`1"

	.byte 16,7
	.string "System_Collections_Generic_IList`1"

.LDIFF_SYM2310=.LTDIE_327 - .Ldebug_info_start
	.long .LDIFF_SYM2310
.LTDIE_327_POINTER:

	.byte 13
.LDIFF_SYM2311=.LTDIE_327 - .Ldebug_info_start
	.long .LDIFF_SYM2311
.LTDIE_327_REFERENCE:

	.byte 14
.LDIFF_SYM2312=.LTDIE_327 - .Ldebug_info_start
	.long .LDIFF_SYM2312
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteParameters"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteParameters_System_Collections_Generic_IList_1_Mono_Cecil_ParameterDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteParameters"
	.quad .Lm_8
	.quad .Lme_8

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2313=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2313
	.byte 1,94,3
	.string "parameters"

.LDIFF_SYM2314=.LTDIE_327_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2314
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2315=.Lfde8_end - .Lfde8_start
	.long .LDIFF_SYM2315
.Lfde8_start:

	.long 0
	.balign 8
	.quad .Lm_8

.LDIFF_SYM2316=.Lme_8 - .Lm_8
	.long .LDIFF_SYM2316
	.long 0
	.byte 68,14,32,68,142,4,10,68,8,14,68,12,7,8,65,11
	.balign 8
.Lfde8_end:

.section ".debug_info"
.subsection 0
.LTDIE_328:

	.byte 8
	.string "Mono_Cecil_MetadataType"

	.byte 1
.LDIFF_SYM2317=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM2317
	.byte 9
	.string "Void"

	.byte 1,9
	.string "Boolean"

	.byte 2,9
	.string "Char"

	.byte 3,9
	.string "SByte"

	.byte 4,9
	.string "Byte"

	.byte 5,9
	.string "Int16"

	.byte 6,9
	.string "UInt16"

	.byte 7,9
	.string "Int32"

	.byte 8,9
	.string "UInt32"

	.byte 9,9
	.string "Int64"

	.byte 10,9
	.string "UInt64"

	.byte 11,9
	.string "Single"

	.byte 12,9
	.string "Double"

	.byte 13,9
	.string "String"

	.byte 14,9
	.string "Pointer"

	.byte 15,9
	.string "ByReference"

	.byte 16,9
	.string "ValueType"

	.byte 17,9
	.string "Class"

	.byte 18,9
	.string "Var"

	.byte 19,9
	.string "Array"

	.byte 20,9
	.string "GenericInstance"

	.byte 21,9
	.string "TypedByReference"

	.byte 22,9
	.string "IntPtr"

	.byte 24,9
	.string "UIntPtr"

	.byte 25,9
	.string "FunctionPointer"

	.byte 27,9
	.string "Object"

	.byte 28,9
	.string "MVar"

	.byte 30,9
	.string "RequiredModifier"

	.byte 31,9
	.string "OptionalModifier"

	.byte 32,9
	.string "Sentinel"

	.byte 193,0,9
	.string "Pinned"

	.byte 197,0,0,7
	.string "Mono_Cecil_MetadataType"

.LDIFF_SYM2318=.LTDIE_328 - .Ldebug_info_start
	.long .LDIFF_SYM2318
.LTDIE_328_POINTER:

	.byte 13
.LDIFF_SYM2319=.LTDIE_328 - .Ldebug_info_start
	.long .LDIFF_SYM2319
.LTDIE_328_REFERENCE:

	.byte 14
.LDIFF_SYM2320=.LTDIE_328 - .Ldebug_info_start
	.long .LDIFF_SYM2320
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteTypeSignature"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteTypeSignature_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteTypeSignature"
	.quad .Lm_9
	.quad .Lme_9

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2321=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2321
	.byte 1,94,3
	.string "type"

.LDIFF_SYM2322=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2322
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2323=.LTDIE_328 - .Ldebug_info_start
	.long .LDIFF_SYM2323
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2324=.Lfde9_end - .Lfde9_start
	.long .LDIFF_SYM2324
.Lfde9_start:

	.long 0
	.balign 8
	.quad .Lm_9

.LDIFF_SYM2325=.Lme_9 - .Lm_9
	.long .LDIFF_SYM2325
	.long 0
	.byte 68,14,48,68,140,6,69,141,5,69,142,4,69,143,3,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde9_end:

.section ".debug_info"
.subsection 0
.LTDIE_330:

	.byte 5
	.string "Mono_Cecil_TypeSpecification"

	.byte 104,16
.LDIFF_SYM2326=.LTDIE_8 - .Ldebug_info_start
	.long .LDIFF_SYM2326
	.byte 2,35,0,6
	.string "element_type"

.LDIFF_SYM2327=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2327
	.byte 2,35,96,0,7
	.string "Mono_Cecil_TypeSpecification"

.LDIFF_SYM2328=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2328
.LTDIE_330_POINTER:

	.byte 13
.LDIFF_SYM2329=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2329
.LTDIE_330_REFERENCE:

	.byte 14
.LDIFF_SYM2330=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2330
.LTDIE_331:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2331=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2331
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2332=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2332
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2333=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2333
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2334=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2334
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2335=.LTDIE_331 - .Ldebug_info_start
	.long .LDIFF_SYM2335
.LTDIE_331_POINTER:

	.byte 13
.LDIFF_SYM2336=.LTDIE_331 - .Ldebug_info_start
	.long .LDIFF_SYM2336
.LTDIE_331_REFERENCE:

	.byte 14
.LDIFF_SYM2337=.LTDIE_331 - .Ldebug_info_start
	.long .LDIFF_SYM2337
.LTDIE_329:

	.byte 5
	.string "Mono_Cecil_GenericInstanceType"

	.byte 112,16
.LDIFF_SYM2338=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2338
	.byte 2,35,0,6
	.string "arguments"

.LDIFF_SYM2339=.LTDIE_331_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2339
	.byte 2,35,104,0,7
	.string "Mono_Cecil_GenericInstanceType"

.LDIFF_SYM2340=.LTDIE_329 - .Ldebug_info_start
	.long .LDIFF_SYM2340
.LTDIE_329_POINTER:

	.byte 13
.LDIFF_SYM2341=.LTDIE_329 - .Ldebug_info_start
	.long .LDIFF_SYM2341
.LTDIE_329_REFERENCE:

	.byte 14
.LDIFF_SYM2342=.LTDIE_329 - .Ldebug_info_start
	.long .LDIFF_SYM2342
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteGenericInstanceTypeSignature"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteGenericInstanceTypeSignature_Mono_Cecil_GenericInstanceType"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteGenericInstanceTypeSignature"
	.quad .Lm_a
	.quad .Lme_a

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2343=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2343
	.byte 1,94,3
	.string "type"

.LDIFF_SYM2344=.LTDIE_329_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2344
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2345=.Lfde10_end - .Lfde10_start
	.long .LDIFF_SYM2345
.Lfde10_start:

	.long 0
	.balign 8
	.quad .Lm_a

.LDIFF_SYM2346=.Lme_a - .Lm_a
	.long .LDIFF_SYM2346
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde10_end:

.section ".debug_info"
.subsection 0
.LTDIE_332:

	.byte 17
	.string "System_Collections_Generic_IList`1"

	.byte 16,7
	.string "System_Collections_Generic_IList`1"

.LDIFF_SYM2347=.LTDIE_332 - .Ldebug_info_start
	.long .LDIFF_SYM2347
.LTDIE_332_POINTER:

	.byte 13
.LDIFF_SYM2348=.LTDIE_332 - .Ldebug_info_start
	.long .LDIFF_SYM2348
.LTDIE_332_REFERENCE:

	.byte 14
.LDIFF_SYM2349=.LTDIE_332 - .Ldebug_info_start
	.long .LDIFF_SYM2349
.LTDIE_333:

	.byte 5
	.string "System_Action`1"

	.byte 128,1,16
.LDIFF_SYM2350=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM2350
	.byte 2,35,0,0,7
	.string "System_Action`1"

.LDIFF_SYM2351=.LTDIE_333 - .Ldebug_info_start
	.long .LDIFF_SYM2351
.LTDIE_333_POINTER:

	.byte 13
.LDIFF_SYM2352=.LTDIE_333 - .Ldebug_info_start
	.long .LDIFF_SYM2352
.LTDIE_333_REFERENCE:

	.byte 14
.LDIFF_SYM2353=.LTDIE_333 - .Ldebug_info_start
	.long .LDIFF_SYM2353
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteList<T_REF>"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteList_T_REF_System_Collections_Generic_IList_1_T_REF_System_Action_1_T_REF"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteList<T_REF>"
	.quad .Lm_b
	.quad .Lme_b

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2354=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2354
	.byte 1,93,3
	.string "list"

.LDIFF_SYM2355=.LTDIE_332_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2355
	.byte 1,94,3
	.string "action"

.LDIFF_SYM2356=.LTDIE_333_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2356
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2357=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2357
	.byte 1,92,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2358=.Lfde11_end - .Lfde11_start
	.long .LDIFF_SYM2358
.Lfde11_start:

	.long 0
	.balign 8
	.quad .Lm_b

.LDIFF_SYM2359=.Lme_b - .Lm_b
	.long .LDIFF_SYM2359
	.long 0
	.byte 68,14,48,68,140,6,69,141,5,69,142,4,69,143,3,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde11_end:

.section ".debug_info"
.subsection 0
.LTDIE_334:

	.byte 17
	.string "Mono_Cecil_IModifierType"

	.byte 16,7
	.string "Mono_Cecil_IModifierType"

.LDIFF_SYM2360=.LTDIE_334 - .Ldebug_info_start
	.long .LDIFF_SYM2360
.LTDIE_334_POINTER:

	.byte 13
.LDIFF_SYM2361=.LTDIE_334 - .Ldebug_info_start
	.long .LDIFF_SYM2361
.LTDIE_334_REFERENCE:

	.byte 14
.LDIFF_SYM2362=.LTDIE_334 - .Ldebug_info_start
	.long .LDIFF_SYM2362
.LTDIE_335:

	.byte 5
	.string "System_Char"

	.byte 18,16
.LDIFF_SYM2363=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM2363
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM2364=.LDIE_CHAR - .Ldebug_info_start
	.long .LDIFF_SYM2364
	.byte 2,35,16,0,7
	.string "System_Char"

.LDIFF_SYM2365=.LTDIE_335 - .Ldebug_info_start
	.long .LDIFF_SYM2365
.LTDIE_335_POINTER:

	.byte 13
.LDIFF_SYM2366=.LTDIE_335 - .Ldebug_info_start
	.long .LDIFF_SYM2366
.LTDIE_335_REFERENCE:

	.byte 14
.LDIFF_SYM2367=.LTDIE_335 - .Ldebug_info_start
	.long .LDIFF_SYM2367
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteModiferTypeSignature"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteModiferTypeSignature_Mono_Cecil_IModifierType_char"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteModiferTypeSignature"
	.quad .Lm_c
	.quad .Lme_c

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2368=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2368
	.byte 1,93,3
	.string "type"

.LDIFF_SYM2369=.LTDIE_334_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2369
	.byte 1,94,3
	.string "id"

.LDIFF_SYM2370=.LDIE_CHAR - .Ldebug_info_start
	.long .LDIFF_SYM2370
	.byte 2,119,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2371=.Lfde12_end - .Lfde12_start
	.long .LDIFF_SYM2371
.Lfde12_start:

	.long 0
	.balign 8
	.quad .Lm_c

.LDIFF_SYM2372=.Lme_c - .Lm_c
	.long .LDIFF_SYM2372
	.long 0
	.byte 68,14,32,68,141,4,69,142,3,10,68,8,13,69,8,14,68,12,7,8,65,11
	.balign 8
.Lfde12_end:

.section ".debug_info"
.subsection 0
.LTDIE_336:

	.byte 5
	.string "Mono_Cecil_FunctionPointerType"

	.byte 112,16
.LDIFF_SYM2373=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2373
	.byte 2,35,0,6
	.string "function"

.LDIFF_SYM2374=.LTDIE_180_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2374
	.byte 2,35,104,0,7
	.string "Mono_Cecil_FunctionPointerType"

.LDIFF_SYM2375=.LTDIE_336 - .Ldebug_info_start
	.long .LDIFF_SYM2375
.LTDIE_336_POINTER:

	.byte 13
.LDIFF_SYM2376=.LTDIE_336 - .Ldebug_info_start
	.long .LDIFF_SYM2376
.LTDIE_336_REFERENCE:

	.byte 14
.LDIFF_SYM2377=.LTDIE_336 - .Ldebug_info_start
	.long .LDIFF_SYM2377
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteFunctionPointerTypeSignature"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteFunctionPointerTypeSignature_Mono_Cecil_FunctionPointerType"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteFunctionPointerTypeSignature"
	.quad .Lm_d
	.quad .Lme_d

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2378=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2378
	.byte 1,94,3
	.string "type"

.LDIFF_SYM2379=.LTDIE_336_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2379
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2380=.Lfde13_end - .Lfde13_start
	.long .LDIFF_SYM2380
.Lfde13_start:

	.long 0
	.balign 8
	.quad .Lm_d

.LDIFF_SYM2381=.Lme_d - .Lm_d
	.long .LDIFF_SYM2381
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde13_end:

.section ".debug_info"
.subsection 0
.LTDIE_338:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2382=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2382
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2383=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2383
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2384=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2384
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2385=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2385
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2386=.LTDIE_338 - .Ldebug_info_start
	.long .LDIFF_SYM2386
.LTDIE_338_POINTER:

	.byte 13
.LDIFF_SYM2387=.LTDIE_338 - .Ldebug_info_start
	.long .LDIFF_SYM2387
.LTDIE_338_REFERENCE:

	.byte 14
.LDIFF_SYM2388=.LTDIE_338 - .Ldebug_info_start
	.long .LDIFF_SYM2388
.LTDIE_337:

	.byte 5
	.string "Mono_Cecil_ArrayType"

	.byte 112,16
.LDIFF_SYM2389=.LTDIE_330 - .Ldebug_info_start
	.long .LDIFF_SYM2389
	.byte 2,35,0,6
	.string "dimensions"

.LDIFF_SYM2390=.LTDIE_338_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2390
	.byte 2,35,104,0,7
	.string "Mono_Cecil_ArrayType"

.LDIFF_SYM2391=.LTDIE_337 - .Ldebug_info_start
	.long .LDIFF_SYM2391
.LTDIE_337_POINTER:

	.byte 13
.LDIFF_SYM2392=.LTDIE_337 - .Ldebug_info_start
	.long .LDIFF_SYM2392
.LTDIE_337_REFERENCE:

	.byte 14
.LDIFF_SYM2393=.LTDIE_337 - .Ldebug_info_start
	.long .LDIFF_SYM2393
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteArrayTypeSignature"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteArrayTypeSignature_Mono_Cecil_ArrayType"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteArrayTypeSignature"
	.quad .Lm_e
	.quad .Lme_e

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2394=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2394
	.byte 1,94,3
	.string "type"

.LDIFF_SYM2395=.LTDIE_337_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2395
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2396=.Lfde14_end - .Lfde14_start
	.long .LDIFF_SYM2396
.Lfde14_start:

	.long 0
	.balign 8
	.quad .Lm_e

.LDIFF_SYM2397=.Lme_e - .Lm_e
	.long .LDIFF_SYM2397
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde14_end:

.section ".debug_info"
.subsection 0
.LTDIE_339:

	.byte 17
	.string "Mono_Cecil_IMemberDefinition"

	.byte 16,7
	.string "Mono_Cecil_IMemberDefinition"

.LDIFF_SYM2398=.LTDIE_339 - .Ldebug_info_start
	.long .LDIFF_SYM2398
.LTDIE_339_POINTER:

	.byte 13
.LDIFF_SYM2399=.LTDIE_339 - .Ldebug_info_start
	.long .LDIFF_SYM2399
.LTDIE_339_REFERENCE:

	.byte 14
.LDIFF_SYM2400=.LTDIE_339 - .Ldebug_info_start
	.long .LDIFF_SYM2400
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteDefinition"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteDefinition_char_Mono_Cecil_IMemberDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteDefinition"
	.quad .Lm_f
	.quad .Lme_f

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2401=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2401
	.byte 1,93,3
	.string "id"

.LDIFF_SYM2402=.LDIE_CHAR - .Ldebug_info_start
	.long .LDIFF_SYM2402
	.byte 2,119,16,3
	.string "member"

.LDIFF_SYM2403=.LTDIE_339_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2403
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2404=.Lfde15_end - .Lfde15_start
	.long .LDIFF_SYM2404
.Lfde15_start:

	.long 0
	.balign 8
	.quad .Lm_f

.LDIFF_SYM2405=.Lme_f - .Lm_f
	.long .LDIFF_SYM2405
	.long 0
	.byte 68,14,32,68,141,4,69,143,3,10,68,8,13,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde15_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteTypeFullName"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteTypeFullName_Mono_Cecil_TypeReference_bool"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteTypeFullName"
	.quad .Lm_10
	.quad .Lme_10

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2406=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2406
	.byte 1,93,3
	.string "type"

.LDIFF_SYM2407=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2407
	.byte 1,94,3
	.string "stripGenericArity"

.LDIFF_SYM2408=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2408
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2409=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2409
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2410=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2410
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2411=.Lfde16_end - .Lfde16_start
	.long .LDIFF_SYM2411
.Lfde16_start:

	.long 0
	.balign 8
	.quad .Lm_10

.LDIFF_SYM2412=.Lme_10 - .Lm_10
	.long .LDIFF_SYM2412
	.long 0
	.byte 68,14,48,68,140,6,69,141,5,69,142,4,69,143,3,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde16_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:WriteItemName"
	.string "Mono_Cecil_Rocks_DocCommentId_WriteItemName_string"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:WriteItemName"
	.quad .Lm_11
	.quad .Lme_11

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2413=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2413
	.byte 2,119,0,3
	.string "name"

.LDIFF_SYM2414=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2414
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2415=.Lfde17_end - .Lfde17_start
	.long .LDIFF_SYM2415
.Lfde17_start:

	.long 0
	.balign 8
	.quad .Lm_11

.LDIFF_SYM2416=.Lme_11 - .Lm_11
	.long .LDIFF_SYM2416
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde17_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:ToString"
	.string "Mono_Cecil_Rocks_DocCommentId_ToString"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:ToString"
	.quad .Lm_12
	.quad .Lme_12

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2417=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2417
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2418=.Lfde18_end - .Lfde18_start
	.long .LDIFF_SYM2418
.Lfde18_start:

	.long 0
	.balign 8
	.quad .Lm_12

.LDIFF_SYM2419=.Lme_12 - .Lm_12
	.long .LDIFF_SYM2419
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde18_end:

.section ".debug_info"
.subsection 0
.LTDIE_340:

	.byte 8
	.string "Mono_Cecil_TokenType"

	.byte 4
.LDIFF_SYM2420=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2420
	.byte 9
	.string "Module"

	.byte 0,9
	.string "TypeRef"

	.byte 128,128,128,8,9
	.string "TypeDef"

	.byte 128,128,128,16,9
	.string "Field"

	.byte 128,128,128,32,9
	.string "Method"

	.byte 128,128,128,48,9
	.string "Param"

	.byte 128,128,128,192,0,9
	.string "InterfaceImpl"

	.byte 128,128,128,200,0,9
	.string "MemberRef"

	.byte 128,128,128,208,0,9
	.string "CustomAttribute"

	.byte 128,128,128,224,0,9
	.string "Permission"

	.byte 128,128,128,240,0,9
	.string "Signature"

	.byte 128,128,128,136,1,9
	.string "Event"

	.byte 128,128,128,160,1,9
	.string "Property"

	.byte 128,128,128,184,1,9
	.string "ModuleRef"

	.byte 128,128,128,208,1,9
	.string "TypeSpec"

	.byte 128,128,128,216,1,9
	.string "Assembly"

	.byte 128,128,128,128,2,9
	.string "AssemblyRef"

	.byte 128,128,128,152,2,9
	.string "File"

	.byte 128,128,128,176,2,9
	.string "ExportedType"

	.byte 128,128,128,184,2,9
	.string "ManifestResource"

	.byte 128,128,128,192,2,9
	.string "GenericParam"

	.byte 128,128,128,208,2,9
	.string "MethodSpec"

	.byte 128,128,128,216,2,9
	.string "GenericParamConstraint"

	.byte 128,128,128,224,2,9
	.string "Document"

	.byte 128,128,128,128,3,9
	.string "MethodDebugInformation"

	.byte 128,128,128,136,3,9
	.string "LocalScope"

	.byte 128,128,128,144,3,9
	.string "LocalVariable"

	.byte 128,128,128,152,3,9
	.string "LocalConstant"

	.byte 128,128,128,160,3,9
	.string "ImportScope"

	.byte 128,128,128,168,3,9
	.string "StateMachineMethod"

	.byte 128,128,128,176,3,9
	.string "CustomDebugInformation"

	.byte 128,128,128,184,3,9
	.string "String"

	.byte 128,128,128,128,7,0,7
	.string "Mono_Cecil_TokenType"

.LDIFF_SYM2421=.LTDIE_340 - .Ldebug_info_start
	.long .LDIFF_SYM2421
.LTDIE_340_POINTER:

	.byte 13
.LDIFF_SYM2422=.LTDIE_340 - .Ldebug_info_start
	.long .LDIFF_SYM2422
.LTDIE_340_REFERENCE:

	.byte 14
.LDIFF_SYM2423=.LTDIE_340 - .Ldebug_info_start
	.long .LDIFF_SYM2423
	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:GetDocCommentId"
	.string "Mono_Cecil_Rocks_DocCommentId_GetDocCommentId_Mono_Cecil_IMemberDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:GetDocCommentId"
	.quad .Lm_13
	.quad .Lme_13

	.byte 2,118,16,3
	.string "member"

.LDIFF_SYM2424=.LTDIE_339_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2424
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2425=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2425
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2426=.LTDIE_340 - .Ldebug_info_start
	.long .LDIFF_SYM2426
	.byte 1,93,11
	.string "V_2"

.LDIFF_SYM2427=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2427
	.byte 2,119,24,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2428=.Lfde19_end - .Lfde19_start
	.long .LDIFF_SYM2428
.Lfde19_start:

	.long 0
	.balign 8
	.quad .Lm_13

.LDIFF_SYM2429=.Lme_13 - .Lm_13
	.long .LDIFF_SYM2429
	.long 0
	.byte 68,14,48,68,141,6,69,142,5,69,143,4,10,68,8,13,69,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde19_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:<WriteParameters>b__9_0"
	.string "Mono_Cecil_Rocks_DocCommentId__WriteParametersb__9_0_Mono_Cecil_ParameterDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:<WriteParameters>b__9_0"
	.quad .Lm_14
	.quad .Lme_14

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2430=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2430
	.byte 2,119,8,3
	.string "p"

.LDIFF_SYM2431=.LTDIE_185_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2431
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2432=.Lfde20_end - .Lfde20_start
	.long .LDIFF_SYM2432
.Lfde20_start:

	.long 0
	.balign 8
	.quad .Lm_14

.LDIFF_SYM2433=.Lme_14 - .Lm_14
	.long .LDIFF_SYM2433
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde20_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.DocCommentId:<WriteArrayTypeSignature>b__15_0"
	.string "Mono_Cecil_Rocks_DocCommentId__WriteArrayTypeSignatureb__15_0_Mono_Cecil_ArrayDimension"

	.byte 0,0
	.string "Mono.Cecil.Rocks.DocCommentId:<WriteArrayTypeSignature>b__15_0"
	.quad .Lm_15
	.quad .Lme_15

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2434=.LTDIE_0_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2434
	.byte 1,95,3
	.string "dimension"

.LDIFF_SYM2435=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2435
	.byte 2,119,16,11
	.string "V_0"

.LDIFF_SYM2436=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2436
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2437=.Lfde21_end - .Lfde21_start
	.long .LDIFF_SYM2437
.Lfde21_start:

	.long 0
	.balign 8
	.quad .Lm_15

.LDIFF_SYM2438=.Lme_15 - .Lm_15
	.long .LDIFF_SYM2438
	.long 0
	.byte 68,14,48,68,143,6,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde21_end:

.section ".debug_info"
.subsection 0
.LTDIE_341:

	.byte 5
	.string "System_Func`2"

	.byte 128,1,16
.LDIFF_SYM2439=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM2439
	.byte 2,35,0,0,7
	.string "System_Func`2"

.LDIFF_SYM2440=.LTDIE_341 - .Ldebug_info_start
	.long .LDIFF_SYM2440
.LTDIE_341_POINTER:

	.byte 13
.LDIFF_SYM2441=.LTDIE_341 - .Ldebug_info_start
	.long .LDIFF_SYM2441
.LTDIE_341_REFERENCE:

	.byte 14
.LDIFF_SYM2442=.LTDIE_341 - .Ldebug_info_start
	.long .LDIFF_SYM2442
.LTDIE_343:

	.byte 5
	.string "System_Func`2"

	.byte 128,1,16
.LDIFF_SYM2443=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM2443
	.byte 2,35,0,0,7
	.string "System_Func`2"

.LDIFF_SYM2444=.LTDIE_343 - .Ldebug_info_start
	.long .LDIFF_SYM2444
.LTDIE_343_POINTER:

	.byte 13
.LDIFF_SYM2445=.LTDIE_343 - .Ldebug_info_start
	.long .LDIFF_SYM2445
.LTDIE_343_REFERENCE:

	.byte 14
.LDIFF_SYM2446=.LTDIE_343 - .Ldebug_info_start
	.long .LDIFF_SYM2446
.LTDIE_342:

	.byte 5
	.string "_<>c__DisplayClass0_0`2"

	.byte 24,16
.LDIFF_SYM2447=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2447
	.byte 2,35,0,6
	.string "g"

.LDIFF_SYM2448=.LTDIE_343_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2448
	.byte 2,35,16,0,7
	.string "_<>c__DisplayClass0_0`2"

.LDIFF_SYM2449=.LTDIE_342 - .Ldebug_info_start
	.long .LDIFF_SYM2449
.LTDIE_342_POINTER:

	.byte 13
.LDIFF_SYM2450=.LTDIE_342 - .Ldebug_info_start
	.long .LDIFF_SYM2450
.LTDIE_342_REFERENCE:

	.byte 14
.LDIFF_SYM2451=.LTDIE_342 - .Ldebug_info_start
	.long .LDIFF_SYM2451
	.byte 2
	.string "Mono.Cecil.Rocks.Functional:Y<A_REF,_R_REF>"
	.string "Mono_Cecil_Rocks_Functional_Y_A_REF_R_REF_System_Func_2_System_Func_2_A_REF_R_REF_System_Func_2_A_REF_R_REF"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional:Y<A_REF,_R_REF>"
	.quad .Lm_16
	.quad .Lme_16

	.byte 2,118,16,3
	.string "f"

.LDIFF_SYM2452=.LTDIE_341_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2452
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2453=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2453
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2454=.Lfde22_end - .Lfde22_start
	.long .LDIFF_SYM2454
.Lfde22_start:

	.long 0
	.balign 8
	.quad .Lm_16

.LDIFF_SYM2455=.Lme_16 - .Lm_16
	.long .LDIFF_SYM2455
	.long 0
	.byte 68,14,64,68,143,8,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde22_end:

.section ".debug_info"
.subsection 0
.LTDIE_344:

	.byte 17
	.string "System_Collections_Generic_IEnumerable`1"

	.byte 16,7
	.string "System_Collections_Generic_IEnumerable`1"

.LDIFF_SYM2456=.LTDIE_344 - .Ldebug_info_start
	.long .LDIFF_SYM2456
.LTDIE_344_POINTER:

	.byte 13
.LDIFF_SYM2457=.LTDIE_344 - .Ldebug_info_start
	.long .LDIFF_SYM2457
.LTDIE_344_REFERENCE:

	.byte 14
.LDIFF_SYM2458=.LTDIE_344 - .Ldebug_info_start
	.long .LDIFF_SYM2458
	.byte 2
	.string "Mono.Cecil.Rocks.Functional:Prepend<TSource_REF>"
	.string "Mono_Cecil_Rocks_Functional_Prepend_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional:Prepend<TSource_REF>"
	.quad .Lm_17
	.quad .Lme_17

	.byte 2,118,16,3
	.string "source"

.LDIFF_SYM2459=.LTDIE_344_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2459
	.byte 2,119,8,3
	.string "element"

.LDIFF_SYM2460=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2460
	.byte 2,119,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2461=.Lfde23_end - .Lfde23_start
	.long .LDIFF_SYM2461
.Lfde23_start:

	.long 0
	.balign 8
	.quad .Lm_17

.LDIFF_SYM2462=.Lme_17 - .Lm_17
	.long .LDIFF_SYM2462
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde23_end:

.section ".debug_info"
.subsection 0
.LTDIE_345:

	.byte 17
	.string "System_Collections_Generic_IEnumerable`1"

	.byte 16,7
	.string "System_Collections_Generic_IEnumerable`1"

.LDIFF_SYM2463=.LTDIE_345 - .Ldebug_info_start
	.long .LDIFF_SYM2463
.LTDIE_345_POINTER:

	.byte 13
.LDIFF_SYM2464=.LTDIE_345 - .Ldebug_info_start
	.long .LDIFF_SYM2464
.LTDIE_345_REFERENCE:

	.byte 14
.LDIFF_SYM2465=.LTDIE_345 - .Ldebug_info_start
	.long .LDIFF_SYM2465
	.byte 2
	.string "Mono.Cecil.Rocks.Functional:PrependIterator<TSource_REF>"
	.string "Mono_Cecil_Rocks_Functional_PrependIterator_TSource_REF_System_Collections_Generic_IEnumerable_1_TSource_REF_TSource_REF"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional:PrependIterator<TSource_REF>"
	.quad .Lm_18
	.quad .Lme_18

	.byte 2,118,16,3
	.string "source"

.LDIFF_SYM2466=.LTDIE_345_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2466
	.byte 2,119,8,3
	.string "element"

.LDIFF_SYM2467=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2467
	.byte 2,119,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2468=.Lfde24_end - .Lfde24_start
	.long .LDIFF_SYM2468
.Lfde24_start:

	.long 0
	.balign 8
	.quad .Lm_18

.LDIFF_SYM2469=.Lme_18 - .Lm_18
	.long .LDIFF_SYM2469
	.long 0
	.byte 68,14,48,10,68,12,7,8,65,11
	.balign 8
.Lfde24_end:

.section ".debug_info"
.subsection 0
.LTDIE_346:

	.byte 17
	.string "Mono_Cecil_Rocks_IILVisitor"

	.byte 16,7
	.string "Mono_Cecil_Rocks_IILVisitor"

.LDIFF_SYM2470=.LTDIE_346 - .Ldebug_info_start
	.long .LDIFF_SYM2470
.LTDIE_346_POINTER:

	.byte 13
.LDIFF_SYM2471=.LTDIE_346 - .Ldebug_info_start
	.long .LDIFF_SYM2471
.LTDIE_346_REFERENCE:

	.byte 14
.LDIFF_SYM2472=.LTDIE_346 - .Ldebug_info_start
	.long .LDIFF_SYM2472
.LTDIE_347:

	.byte 5
	.string "_<>c__DisplayClass1_0"

	.byte 24,16
.LDIFF_SYM2473=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2473
	.byte 2,35,0,6
	.string "visitor"

.LDIFF_SYM2474=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2474
	.byte 2,35,16,0,7
	.string "_<>c__DisplayClass1_0"

.LDIFF_SYM2475=.LTDIE_347 - .Ldebug_info_start
	.long .LDIFF_SYM2475
.LTDIE_347_POINTER:

	.byte 13
.LDIFF_SYM2476=.LTDIE_347 - .Ldebug_info_start
	.long .LDIFF_SYM2476
.LTDIE_347_REFERENCE:

	.byte 14
.LDIFF_SYM2477=.LTDIE_347 - .Ldebug_info_start
	.long .LDIFF_SYM2477
	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:Parse"
	.string "Mono_Cecil_Rocks_ILParser_Parse_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:Parse"
	.quad .Lm_29
	.quad .Lme_29

	.byte 2,118,16,3
	.string "method"

.LDIFF_SYM2478=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2478
	.byte 1,94,3
	.string "visitor"

.LDIFF_SYM2479=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2479
	.byte 2,119,16,11
	.string "V_0"

.LDIFF_SYM2480=.LTDIE_347_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2480
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2481=.Lfde25_end - .Lfde25_start
	.long .LDIFF_SYM2481
.Lfde25_start:

	.long 0
	.balign 8
	.quad .Lm_29

.LDIFF_SYM2482=.Lme_29 - .Lm_29
	.long .LDIFF_SYM2482
	.long 0
	.byte 68,14,48,68,141,6,69,142,5,10,68,8,13,69,8,14,68,12,7,8,65,11
	.balign 8
.Lfde25_end:

.section ".debug_info"
.subsection 0
.LTDIE_348:

	.byte 5
	.string "_ParseContext"

	.byte 56,16
.LDIFF_SYM2483=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2483
	.byte 2,35,0,6
	.string "<Code>k__BackingField"

.LDIFF_SYM2484=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2484
	.byte 2,35,16,6
	.string "<Position>k__BackingField"

.LDIFF_SYM2485=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2485
	.byte 2,35,48,6
	.string "<Metadata>k__BackingField"

.LDIFF_SYM2486=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2486
	.byte 2,35,24,6
	.string "<Variables>k__BackingField"

.LDIFF_SYM2487=.LTDIE_199_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2487
	.byte 2,35,32,6
	.string "<Visitor>k__BackingField"

.LDIFF_SYM2488=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2488
	.byte 2,35,40,0,7
	.string "_ParseContext"

.LDIFF_SYM2489=.LTDIE_348 - .Ldebug_info_start
	.long .LDIFF_SYM2489
.LTDIE_348_POINTER:

	.byte 13
.LDIFF_SYM2490=.LTDIE_348 - .Ldebug_info_start
	.long .LDIFF_SYM2490
.LTDIE_348_REFERENCE:

	.byte 14
.LDIFF_SYM2491=.LTDIE_348 - .Ldebug_info_start
	.long .LDIFF_SYM2491
.LTDIE_349:

	.byte 5
	.string "System_Byte"

	.byte 17,16
.LDIFF_SYM2492=.LTDIE_4 - .Ldebug_info_start
	.long .LDIFF_SYM2492
	.byte 2,35,0,6
	.string "m_value"

.LDIFF_SYM2493=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM2493
	.byte 2,35,16,0,7
	.string "System_Byte"

.LDIFF_SYM2494=.LTDIE_349 - .Ldebug_info_start
	.long .LDIFF_SYM2494
.LTDIE_349_POINTER:

	.byte 13
.LDIFF_SYM2495=.LTDIE_349 - .Ldebug_info_start
	.long .LDIFF_SYM2495
.LTDIE_349_REFERENCE:

	.byte 14
.LDIFF_SYM2496=.LTDIE_349 - .Ldebug_info_start
	.long .LDIFF_SYM2496
	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:ParseMethod"
	.string "Mono_Cecil_Rocks_ILParser_ParseMethod_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:ParseMethod"
	.quad .Lm_2a
	.quad .Lme_2a

	.byte 2,118,16,3
	.string "method"

.LDIFF_SYM2497=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2497
	.byte 1,94,3
	.string "visitor"

.LDIFF_SYM2498=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2498
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2499=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2499
	.byte 1,95,11
	.string "V_1"

.LDIFF_SYM2500=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2500
	.byte 1,94,11
	.string "V_2"

.LDIFF_SYM2501=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM2501
	.byte 1,93,11
	.string "V_3"

.LDIFF_SYM2502=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2502
	.byte 1,92,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2503=.Lfde26_end - .Lfde26_start
	.long .LDIFF_SYM2503
.Lfde26_start:

	.long 0
	.balign 8
	.quad .Lm_2a

.LDIFF_SYM2504=.Lme_2a - .Lm_2a
	.long .LDIFF_SYM2504
	.long 0
	.byte 68,14,48,68,140,6,69,141,5,69,142,4,69,143,3,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde26_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:CreateContext"
	.string "Mono_Cecil_Rocks_ILParser_CreateContext_Mono_Cecil_MethodDefinition_Mono_Cecil_Rocks_IILVisitor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:CreateContext"
	.quad .Lm_2b
	.quad .Lme_2b

	.byte 2,118,16,3
	.string "method"

.LDIFF_SYM2505=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2505
	.byte 1,94,3
	.string "visitor"

.LDIFF_SYM2506=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2506
	.byte 2,119,32,11
	.string "V_0"

.LDIFF_SYM2507=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2507
	.byte 1,93,11
	.string "V_1"

.LDIFF_SYM2508=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2508
	.byte 1,94,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2509=.Lfde27_end - .Lfde27_start
	.long .LDIFF_SYM2509
.Lfde27_start:

	.long 0
	.balign 8
	.quad .Lm_2b

.LDIFF_SYM2510=.Lme_2b - .Lm_2b
	.long .LDIFF_SYM2510
	.long 0
	.byte 68,14,64,68,131,8,69,141,7,69,142,6,10,68,8,3,69,8,13,69,8,14,68,12,7,8,65,11
	.balign 8
.Lfde27_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:ParseFatMethod"
	.string "Mono_Cecil_Rocks_ILParser_ParseFatMethod_Mono_Cecil_Rocks_ILParser_ParseContext"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:ParseFatMethod"
	.quad .Lm_2c
	.quad .Lme_2c

	.byte 2,118,16,3
	.string "context"

.LDIFF_SYM2511=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2511
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2512=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2512
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2513=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2513
	.byte 2,119,48,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2514=.Lfde28_end - .Lfde28_start
	.long .LDIFF_SYM2514
.Lfde28_start:

	.long 0
	.balign 8
	.quad .Lm_2c

.LDIFF_SYM2515=.Lme_2c - .Lm_2c
	.long .LDIFF_SYM2515
	.long 0
	.byte 68,14,80,68,142,10,69,143,9,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde28_end:

.section ".debug_info"
.subsection 0
.LTDIE_350:

	.byte 17
	.string "Mono_Cecil_IMetadataTokenProvider"

	.byte 16,7
	.string "Mono_Cecil_IMetadataTokenProvider"

.LDIFF_SYM2516=.LTDIE_350 - .Ldebug_info_start
	.long .LDIFF_SYM2516
.LTDIE_350_POINTER:

	.byte 13
.LDIFF_SYM2517=.LTDIE_350 - .Ldebug_info_start
	.long .LDIFF_SYM2517
.LTDIE_350_REFERENCE:

	.byte 14
.LDIFF_SYM2518=.LTDIE_350 - .Ldebug_info_start
	.long .LDIFF_SYM2518
.LTDIE_351:

	.byte 8
	.string "Mono_Cecil_Cil_OperandType"

	.byte 4
.LDIFF_SYM2519=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2519
	.byte 9
	.string "InlineBrTarget"

	.byte 0,9
	.string "InlineField"

	.byte 1,9
	.string "InlineI"

	.byte 2,9
	.string "InlineI8"

	.byte 3,9
	.string "InlineMethod"

	.byte 4,9
	.string "InlineNone"

	.byte 5,9
	.string "InlinePhi"

	.byte 6,9
	.string "InlineR"

	.byte 7,9
	.string "InlineSig"

	.byte 8,9
	.string "InlineString"

	.byte 9,9
	.string "InlineSwitch"

	.byte 10,9
	.string "InlineTok"

	.byte 11,9
	.string "InlineType"

	.byte 12,9
	.string "InlineVar"

	.byte 13,9
	.string "InlineArg"

	.byte 14,9
	.string "ShortInlineBrTarget"

	.byte 15,9
	.string "ShortInlineI"

	.byte 16,9
	.string "ShortInlineR"

	.byte 17,9
	.string "ShortInlineVar"

	.byte 18,9
	.string "ShortInlineArg"

	.byte 19,0,7
	.string "Mono_Cecil_Cil_OperandType"

.LDIFF_SYM2520=.LTDIE_351 - .Ldebug_info_start
	.long .LDIFF_SYM2520
.LTDIE_351_POINTER:

	.byte 13
.LDIFF_SYM2521=.LTDIE_351 - .Ldebug_info_start
	.long .LDIFF_SYM2521
.LTDIE_351_REFERENCE:

	.byte 14
.LDIFF_SYM2522=.LTDIE_351 - .Ldebug_info_start
	.long .LDIFF_SYM2522
	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:ParseCode"
	.string "Mono_Cecil_Rocks_ILParser_ParseCode_int_Mono_Cecil_Rocks_ILParser_ParseContext"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:ParseCode"
	.quad .Lm_2d
	.quad .Lme_2d

	.byte 2,118,16,3
	.string "code_size"

.LDIFF_SYM2523=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2523
	.byte 1,94,3
	.string "context"

.LDIFF_SYM2524=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2524
	.byte 3,119,184,2,11
	.string "V_0"

.LDIFF_SYM2525=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2525
	.byte 1,93,11
	.string "V_1"

.LDIFF_SYM2526=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2526
	.byte 1,92,11
	.string "V_2"

.LDIFF_SYM2527=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2527
	.byte 1,83,11
	.string "V_3"

.LDIFF_SYM2528=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2528
	.byte 1,86,11
	.string "V_4"

.LDIFF_SYM2529=.LDIE_U1 - .Ldebug_info_start
	.long .LDIFF_SYM2529
	.byte 1,94,11
	.string "V_5"

.LDIFF_SYM2530=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2530
	.byte 3,119,144,2,11
	.string "V_6"

.LDIFF_SYM2531=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2531
	.byte 1,95,11
	.string "V_7"

.LDIFF_SYM2532=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2532
	.byte 1,94,11
	.string "V_8"

.LDIFF_SYM2533=.LTDIE_350_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2533
	.byte 1,94,11
	.string "V_9"

.LDIFF_SYM2534=.LTDIE_351 - .Ldebug_info_start
	.long .LDIFF_SYM2534
	.byte 1,94,11
	.string "V_10"

.LDIFF_SYM2535=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2535
	.byte 3,119,176,2,11
	.string "V_11"

.LDIFF_SYM2536=.LTDIE_6_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2536
	.byte 3,119,168,2,11
	.string "V_12"

.LDIFF_SYM2537=.LTDIE_180_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2537
	.byte 1,94,11
	.string "V_13"

.LDIFF_SYM2538=.LTDIE_340 - .Ldebug_info_start
	.long .LDIFF_SYM2538
	.byte 3,119,160,2,11
	.string "V_14"

.LDIFF_SYM2539=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2539
	.byte 3,119,136,2,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2540=.Lfde29_end - .Lfde29_start
	.long .LDIFF_SYM2540
.Lfde29_start:

	.long 0
	.balign 8
	.quad .Lm_2d

.LDIFF_SYM2541=.Lme_2d - .Lm_2d
	.long .LDIFF_SYM2541
	.long 0
	.byte 71,14,208,2,68,131,42,69,134,41,69,140,40,69,141,39,69,142,38,69,143,37,10,68,8,3,69,8,6,69,8,12
	.byte 69,8,13,69,8,14,69,8,15,71,12,7,8,65,11
	.balign 8
.Lfde29_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser:GetVariable"
	.string "Mono_Cecil_Rocks_ILParser_GetVariable_Mono_Cecil_Rocks_ILParser_ParseContext_int"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser:GetVariable"
	.quad .Lm_2e
	.quad .Lme_2e

	.byte 2,118,16,3
	.string "context"

.LDIFF_SYM2542=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2542
	.byte 1,94,3
	.string "index"

.LDIFF_SYM2543=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2543
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2544=.Lfde30_end - .Lfde30_start
	.long .LDIFF_SYM2544
.Lfde30_start:

	.long 0
	.balign 8
	.quad .Lm_2e

.LDIFF_SYM2545=.Lme_2e - .Lm_2e
	.long .LDIFF_SYM2545
	.long 0
	.byte 68,14,32,68,142,4,10,68,8,14,68,12,7,8,65,11
	.balign 8
.Lfde30_end:

.section ".debug_info"
.subsection 0
.LTDIE_352:

	.byte 5
	.string "Mono_Cecil_Cil_Instruction"

	.byte 56,16
.LDIFF_SYM2546=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2546
	.byte 2,35,0,6
	.string "offset"

.LDIFF_SYM2547=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2547
	.byte 2,35,40,6
	.string "opcode"

.LDIFF_SYM2548=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2548
	.byte 2,35,44,6
	.string "operand"

.LDIFF_SYM2549=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2549
	.byte 2,35,16,6
	.string "previous"

.LDIFF_SYM2550=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2550
	.byte 2,35,24,6
	.string "next"

.LDIFF_SYM2551=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2551
	.byte 2,35,32,0,7
	.string "Mono_Cecil_Cil_Instruction"

.LDIFF_SYM2552=.LTDIE_352 - .Ldebug_info_start
	.long .LDIFF_SYM2552
.LTDIE_352_POINTER:

	.byte 13
.LDIFF_SYM2553=.LTDIE_352 - .Ldebug_info_start
	.long .LDIFF_SYM2553
.LTDIE_352_REFERENCE:

	.byte 14
.LDIFF_SYM2554=.LTDIE_352 - .Ldebug_info_start
	.long .LDIFF_SYM2554
.LTDIE_353:

	.byte 8
	.string "Mono_Cecil_Cil_Code"

	.byte 4
.LDIFF_SYM2555=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2555
	.byte 9
	.string "Nop"

	.byte 0,9
	.string "Break"

	.byte 1,9
	.string "Ldarg_0"

	.byte 2,9
	.string "Ldarg_1"

	.byte 3,9
	.string "Ldarg_2"

	.byte 4,9
	.string "Ldarg_3"

	.byte 5,9
	.string "Ldloc_0"

	.byte 6,9
	.string "Ldloc_1"

	.byte 7,9
	.string "Ldloc_2"

	.byte 8,9
	.string "Ldloc_3"

	.byte 9,9
	.string "Stloc_0"

	.byte 10,9
	.string "Stloc_1"

	.byte 11,9
	.string "Stloc_2"

	.byte 12,9
	.string "Stloc_3"

	.byte 13,9
	.string "Ldarg_S"

	.byte 14,9
	.string "Ldarga_S"

	.byte 15,9
	.string "Starg_S"

	.byte 16,9
	.string "Ldloc_S"

	.byte 17,9
	.string "Ldloca_S"

	.byte 18,9
	.string "Stloc_S"

	.byte 19,9
	.string "Ldnull"

	.byte 20,9
	.string "Ldc_I4_M1"

	.byte 21,9
	.string "Ldc_I4_0"

	.byte 22,9
	.string "Ldc_I4_1"

	.byte 23,9
	.string "Ldc_I4_2"

	.byte 24,9
	.string "Ldc_I4_3"

	.byte 25,9
	.string "Ldc_I4_4"

	.byte 26,9
	.string "Ldc_I4_5"

	.byte 27,9
	.string "Ldc_I4_6"

	.byte 28,9
	.string "Ldc_I4_7"

	.byte 29,9
	.string "Ldc_I4_8"

	.byte 30,9
	.string "Ldc_I4_S"

	.byte 31,9
	.string "Ldc_I4"

	.byte 32,9
	.string "Ldc_I8"

	.byte 33,9
	.string "Ldc_R4"

	.byte 34,9
	.string "Ldc_R8"

	.byte 35,9
	.string "Dup"

	.byte 36,9
	.string "Pop"

	.byte 37,9
	.string "Jmp"

	.byte 38,9
	.string "Call"

	.byte 39,9
	.string "Calli"

	.byte 40,9
	.string "Ret"

	.byte 41,9
	.string "Br_S"

	.byte 42,9
	.string "Brfalse_S"

	.byte 43,9
	.string "Brtrue_S"

	.byte 44,9
	.string "Beq_S"

	.byte 45,9
	.string "Bge_S"

	.byte 46,9
	.string "Bgt_S"

	.byte 47,9
	.string "Ble_S"

	.byte 48,9
	.string "Blt_S"

	.byte 49,9
	.string "Bne_Un_S"

	.byte 50,9
	.string "Bge_Un_S"

	.byte 51,9
	.string "Bgt_Un_S"

	.byte 52,9
	.string "Ble_Un_S"

	.byte 53,9
	.string "Blt_Un_S"

	.byte 54,9
	.string "Br"

	.byte 55,9
	.string "Brfalse"

	.byte 56,9
	.string "Brtrue"

	.byte 57,9
	.string "Beq"

	.byte 58,9
	.string "Bge"

	.byte 59,9
	.string "Bgt"

	.byte 60,9
	.string "Ble"

	.byte 61,9
	.string "Blt"

	.byte 62,9
	.string "Bne_Un"

	.byte 63,9
	.string "Bge_Un"

	.byte 192,0,9
	.string "Bgt_Un"

	.byte 193,0,9
	.string "Ble_Un"

	.byte 194,0,9
	.string "Blt_Un"

	.byte 195,0,9
	.string "Switch"

	.byte 196,0,9
	.string "Ldind_I1"

	.byte 197,0,9
	.string "Ldind_U1"

	.byte 198,0,9
	.string "Ldind_I2"

	.byte 199,0,9
	.string "Ldind_U2"

	.byte 200,0,9
	.string "Ldind_I4"

	.byte 201,0,9
	.string "Ldind_U4"

	.byte 202,0,9
	.string "Ldind_I8"

	.byte 203,0,9
	.string "Ldind_I"

	.byte 204,0,9
	.string "Ldind_R4"

	.byte 205,0,9
	.string "Ldind_R8"

	.byte 206,0,9
	.string "Ldind_Ref"

	.byte 207,0,9
	.string "Stind_Ref"

	.byte 208,0,9
	.string "Stind_I1"

	.byte 209,0,9
	.string "Stind_I2"

	.byte 210,0,9
	.string "Stind_I4"

	.byte 211,0,9
	.string "Stind_I8"

	.byte 212,0,9
	.string "Stind_R4"

	.byte 213,0,9
	.string "Stind_R8"

	.byte 214,0,9
	.string "Add"

	.byte 215,0,9
	.string "Sub"

	.byte 216,0,9
	.string "Mul"

	.byte 217,0,9
	.string "Div"

	.byte 218,0,9
	.string "Div_Un"

	.byte 219,0,9
	.string "Rem"

	.byte 220,0,9
	.string "Rem_Un"

	.byte 221,0,9
	.string "And"

	.byte 222,0,9
	.string "Or"

	.byte 223,0,9
	.string "Xor"

	.byte 224,0,9
	.string "Shl"

	.byte 225,0,9
	.string "Shr"

	.byte 226,0,9
	.string "Shr_Un"

	.byte 227,0,9
	.string "Neg"

	.byte 228,0,9
	.string "Not"

	.byte 229,0,9
	.string "Conv_I1"

	.byte 230,0,9
	.string "Conv_I2"

	.byte 231,0,9
	.string "Conv_I4"

	.byte 232,0,9
	.string "Conv_I8"

	.byte 233,0,9
	.string "Conv_R4"

	.byte 234,0,9
	.string "Conv_R8"

	.byte 235,0,9
	.string "Conv_U4"

	.byte 236,0,9
	.string "Conv_U8"

	.byte 237,0,9
	.string "Callvirt"

	.byte 238,0,9
	.string "Cpobj"

	.byte 239,0,9
	.string "Ldobj"

	.byte 240,0,9
	.string "Ldstr"

	.byte 241,0,9
	.string "Newobj"

	.byte 242,0,9
	.string "Castclass"

	.byte 243,0,9
	.string "Isinst"

	.byte 244,0,9
	.string "Conv_R_Un"

	.byte 245,0,9
	.string "Unbox"

	.byte 246,0,9
	.string "Throw"

	.byte 247,0,9
	.string "Ldfld"

	.byte 248,0,9
	.string "Ldflda"

	.byte 249,0,9
	.string "Stfld"

	.byte 250,0,9
	.string "Ldsfld"

	.byte 251,0,9
	.string "Ldsflda"

	.byte 252,0,9
	.string "Stsfld"

	.byte 253,0,9
	.string "Stobj"

	.byte 254,0,9
	.string "Conv_Ovf_I1_Un"

	.byte 255,0,9
	.string "Conv_Ovf_I2_Un"

	.byte 128,1,9
	.string "Conv_Ovf_I4_Un"

	.byte 129,1,9
	.string "Conv_Ovf_I8_Un"

	.byte 130,1,9
	.string "Conv_Ovf_U1_Un"

	.byte 131,1,9
	.string "Conv_Ovf_U2_Un"

	.byte 132,1,9
	.string "Conv_Ovf_U4_Un"

	.byte 133,1,9
	.string "Conv_Ovf_U8_Un"

	.byte 134,1,9
	.string "Conv_Ovf_I_Un"

	.byte 135,1,9
	.string "Conv_Ovf_U_Un"

	.byte 136,1,9
	.string "Box"

	.byte 137,1,9
	.string "Newarr"

	.byte 138,1,9
	.string "Ldlen"

	.byte 139,1,9
	.string "Ldelema"

	.byte 140,1,9
	.string "Ldelem_I1"

	.byte 141,1,9
	.string "Ldelem_U1"

	.byte 142,1,9
	.string "Ldelem_I2"

	.byte 143,1,9
	.string "Ldelem_U2"

	.byte 144,1,9
	.string "Ldelem_I4"

	.byte 145,1,9
	.string "Ldelem_U4"

	.byte 146,1,9
	.string "Ldelem_I8"

	.byte 147,1,9
	.string "Ldelem_I"

	.byte 148,1,9
	.string "Ldelem_R4"

	.byte 149,1,9
	.string "Ldelem_R8"

	.byte 150,1,9
	.string "Ldelem_Ref"

	.byte 151,1,9
	.string "Stelem_I"

	.byte 152,1,9
	.string "Stelem_I1"

	.byte 153,1,9
	.string "Stelem_I2"

	.byte 154,1,9
	.string "Stelem_I4"

	.byte 155,1,9
	.string "Stelem_I8"

	.byte 156,1,9
	.string "Stelem_R4"

	.byte 157,1,9
	.string "Stelem_R8"

	.byte 158,1,9
	.string "Stelem_Ref"

	.byte 159,1,9
	.string "Ldelem_Any"

	.byte 160,1,9
	.string "Stelem_Any"

	.byte 161,1,9
	.string "Unbox_Any"

	.byte 162,1,9
	.string "Conv_Ovf_I1"

	.byte 163,1,9
	.string "Conv_Ovf_U1"

	.byte 164,1,9
	.string "Conv_Ovf_I2"

	.byte 165,1,9
	.string "Conv_Ovf_U2"

	.byte 166,1,9
	.string "Conv_Ovf_I4"

	.byte 167,1,9
	.string "Conv_Ovf_U4"

	.byte 168,1,9
	.string "Conv_Ovf_I8"

	.byte 169,1,9
	.string "Conv_Ovf_U8"

	.byte 170,1,9
	.string "Refanyval"

	.byte 171,1,9
	.string "Ckfinite"

	.byte 172,1,9
	.string "Mkrefany"

	.byte 173,1,9
	.string "Ldtoken"

	.byte 174,1,9
	.string "Conv_U2"

	.byte 175,1,9
	.string "Conv_U1"

	.byte 176,1,9
	.string "Conv_I"

	.byte 177,1,9
	.string "Conv_Ovf_I"

	.byte 178,1,9
	.string "Conv_Ovf_U"

	.byte 179,1,9
	.string "Add_Ovf"

	.byte 180,1,9
	.string "Add_Ovf_Un"

	.byte 181,1,9
	.string "Mul_Ovf"

	.byte 182,1,9
	.string "Mul_Ovf_Un"

	.byte 183,1,9
	.string "Sub_Ovf"

	.byte 184,1,9
	.string "Sub_Ovf_Un"

	.byte 185,1,9
	.string "Endfinally"

	.byte 186,1,9
	.string "Leave"

	.byte 187,1,9
	.string "Leave_S"

	.byte 188,1,9
	.string "Stind_I"

	.byte 189,1,9
	.string "Conv_U"

	.byte 190,1,9
	.string "Arglist"

	.byte 191,1,9
	.string "Ceq"

	.byte 192,1,9
	.string "Cgt"

	.byte 193,1,9
	.string "Cgt_Un"

	.byte 194,1,9
	.string "Clt"

	.byte 195,1,9
	.string "Clt_Un"

	.byte 196,1,9
	.string "Ldftn"

	.byte 197,1,9
	.string "Ldvirtftn"

	.byte 198,1,9
	.string "Ldarg"

	.byte 199,1,9
	.string "Ldarga"

	.byte 200,1,9
	.string "Starg"

	.byte 201,1,9
	.string "Ldloc"

	.byte 202,1,9
	.string "Ldloca"

	.byte 203,1,9
	.string "Stloc"

	.byte 204,1,9
	.string "Localloc"

	.byte 205,1,9
	.string "Endfilter"

	.byte 206,1,9
	.string "Unaligned"

	.byte 207,1,9
	.string "Volatile"

	.byte 208,1,9
	.string "Tail"

	.byte 209,1,9
	.string "Initobj"

	.byte 210,1,9
	.string "Constrained"

	.byte 211,1,9
	.string "Cpblk"

	.byte 212,1,9
	.string "Initblk"

	.byte 213,1,9
	.string "No"

	.byte 214,1,9
	.string "Rethrow"

	.byte 215,1,9
	.string "Sizeof"

	.byte 216,1,9
	.string "Refanytype"

	.byte 217,1,9
	.string "Readonly"

	.byte 218,1,0,7
	.string "Mono_Cecil_Cil_Code"

.LDIFF_SYM2556=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2556
.LTDIE_353_POINTER:

	.byte 13
.LDIFF_SYM2557=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2557
.LTDIE_353_REFERENCE:

	.byte 14
.LDIFF_SYM2558=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2558
	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:SimplifyMacros"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_SimplifyMacros_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:SimplifyMacros"
	.quad .Lm_2f
	.quad .Lme_2f

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2559=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2559
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2560=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2560
	.byte 3,118,232,124,11
	.string "V_1"

.LDIFF_SYM2561=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2561
	.byte 1,94,11
	.string "V_2"

.LDIFF_SYM2562=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2562
	.byte 3,118,128,125,11
	.string "V_3"

.LDIFF_SYM2563=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2563
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2564=.Lfde31_end - .Lfde31_start
	.long .LDIFF_SYM2564
.Lfde31_start:

	.long 0
	.balign 8
	.quad .Lm_2f

.LDIFF_SYM2565=.Lme_2f - .Lm_2f
	.long .LDIFF_SYM2565
	.long 0
	.byte 65,14,16,134,2,67,13,6,75,140,6,68,141,5,68,142,4,68,143,3,10,68,8,12,68,8,13,68,8,14,68,8
	.byte 15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde31_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:ExpandMacro"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_ExpandMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode_object"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:ExpandMacro"
	.quad .Lm_30
	.quad .Lme_30

	.byte 2,118,16,3
	.string "instruction"

.LDIFF_SYM2566=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2566
	.byte 1,94,3
	.string "opcode"

.LDIFF_SYM2567=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2567
	.byte 2,119,8,3
	.string "operand"

.LDIFF_SYM2568=.LDIE_OBJECT - .Ldebug_info_start
	.long .LDIFF_SYM2568
	.byte 2,119,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2569=.Lfde32_end - .Lfde32_start
	.long .LDIFF_SYM2569
.Lfde32_start:

	.long 0
	.balign 8
	.quad .Lm_30

.LDIFF_SYM2570=.Lme_30 - .Lm_30
	.long .LDIFF_SYM2570
	.long 0
	.byte 68,14,32,68,142,4,10,68,8,14,68,12,7,8,65,11
	.balign 8
.Lfde32_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:MakeMacro"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_MakeMacro_Mono_Cecil_Cil_Instruction_Mono_Cecil_Cil_OpCode"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:MakeMacro"
	.quad .Lm_31
	.quad .Lme_31

	.byte 2,118,16,3
	.string "instruction"

.LDIFF_SYM2571=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2571
	.byte 1,95,3
	.string "opcode"

.LDIFF_SYM2572=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2572
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2573=.Lfde33_end - .Lfde33_start
	.long .LDIFF_SYM2573
.Lfde33_start:

	.long 0
	.balign 8
	.quad .Lm_31

.LDIFF_SYM2574=.Lme_31 - .Lm_31
	.long .LDIFF_SYM2574
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde33_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:Optimize"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_Optimize_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:Optimize"
	.quad .Lm_32
	.quad .Lme_32

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2575=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2575
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2576=.Lfde34_end - .Lfde34_start
	.long .LDIFF_SYM2576
.Lfde34_start:

	.long 0
	.balign 8
	.quad .Lm_32

.LDIFF_SYM2577=.Lme_32 - .Lm_32
	.long .LDIFF_SYM2577
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde34_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeLongs"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_OptimizeLongs_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeLongs"
	.quad .Lm_33
	.quad .Lme_33

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2578=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2578
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2579=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2579
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2580=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2580
	.byte 1,93,11
	.string "V_2"

.LDIFF_SYM2581=.LDIE_I8 - .Ldebug_info_start
	.long .LDIFF_SYM2581
	.byte 1,92,11
	.string "V_3"

.LDIFF_SYM2582=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2582
	.byte 2,119,48,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2583=.Lfde35_end - .Lfde35_start
	.long .LDIFF_SYM2583
.Lfde35_start:

	.long 0
	.balign 8
	.quad .Lm_33

.LDIFF_SYM2584=.Lme_33 - .Lm_33
	.long .LDIFF_SYM2584
	.long 0
	.byte 68,14,96,68,140,12,69,141,11,69,142,10,69,143,9,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde35_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeMacros"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_OptimizeMacros_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeMacros"
	.quad .Lm_34
	.quad .Lme_34

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2585=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2585
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2586=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2586
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2587=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2587
	.byte 3,118,216,125,11
	.string "V_2"

.LDIFF_SYM2588=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2588
	.byte 1,93,11
	.string "V_3"

.LDIFF_SYM2589=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2589
	.byte 1,92,11
	.string "V_4"

.LDIFF_SYM2590=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2590
	.byte 1,92,11
	.string "V_5"

.LDIFF_SYM2591=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2591
	.byte 1,92,11
	.string "V_6"

.LDIFF_SYM2592=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2592
	.byte 3,118,240,125,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2593=.Lfde36_end - .Lfde36_start
	.long .LDIFF_SYM2593
.Lfde36_start:

	.long 0
	.balign 8
	.quad .Lm_34

.LDIFF_SYM2594=.Lme_34 - .Lm_34
	.long .LDIFF_SYM2594
	.long 0
	.byte 65,14,16,134,2,67,13,6,75,131,7,68,140,6,68,141,5,68,142,4,68,143,3,10,68,8,3,68,8,12,68,8
	.byte 13,68,8,14,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde36_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeBranches"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranches_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeBranches"
	.quad .Lm_35
	.quad .Lme_35

	.byte 2,118,16,3
	.string "body"

.LDIFF_SYM2595=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2595
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2596=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2596
	.byte 2,118,80,11
	.string "V_1"

.LDIFF_SYM2597=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2597
	.byte 1,94,11
	.string "V_2"

.LDIFF_SYM2598=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2598
	.byte 2,118,104,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2599=.Lfde37_end - .Lfde37_start
	.long .LDIFF_SYM2599
.Lfde37_start:

	.long 0
	.balign 8
	.quad .Lm_35

.LDIFF_SYM2600=.Lme_35 - .Lm_35
	.long .LDIFF_SYM2600
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,142,4,68,143,3,10,68,8,14,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde37_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeBranch"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_OptimizeBranch_Mono_Cecil_Cil_Instruction"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:OptimizeBranch"
	.quad .Lm_36
	.quad .Lme_36

	.byte 2,118,16,3
	.string "instruction"

.LDIFF_SYM2601=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2601
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2602=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2602
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2603=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2603
	.byte 3,119,136,1,11
	.string "V_2"

.LDIFF_SYM2604=.LTDIE_353 - .Ldebug_info_start
	.long .LDIFF_SYM2604
	.byte 1,94,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2605=.Lfde38_end - .Lfde38_start
	.long .LDIFF_SYM2605
.Lfde38_start:

	.long 0
	.balign 8
	.quad .Lm_36

.LDIFF_SYM2606=.Lme_36 - .Lm_36
	.long .LDIFF_SYM2606
	.long 0
	.byte 71,14,160,1,68,141,20,69,142,19,69,143,18,10,68,8,13,69,8,14,69,8,15,71,12,7,8,65,11
	.balign 8
.Lfde38_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodBodyRocks:ComputeOffsets"
	.string "Mono_Cecil_Rocks_MethodBodyRocks_ComputeOffsets_Mono_Cecil_Cil_MethodBody"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodBodyRocks:ComputeOffsets"
	.quad .Lm_37
	.quad .Lme_37

	.byte 2,118,16,3
	.string "body"

.LDIFF_SYM2607=.LTDIE_196_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2607
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2608=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2608
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2609=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2609
	.byte 2,118,88,11
	.string "V_2"

.LDIFF_SYM2610=.LTDIE_352_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2610
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2611=.Lfde39_end - .Lfde39_start
	.long .LDIFF_SYM2611
.Lfde39_start:

	.long 0
	.balign 8
	.quad .Lm_37

.LDIFF_SYM2612=.Lme_37 - .Lm_37
	.long .LDIFF_SYM2612
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,142,4,68,143,3,10,68,8,14,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde39_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetBaseMethod"
	.string "Mono_Cecil_Rocks_MethodDefinitionRocks_GetBaseMethod_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetBaseMethod"
	.quad .Lm_38
	.quad .Lme_38

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2613=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2613
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2614=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2614
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2615=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2615
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2616=.Lfde40_end - .Lfde40_start
	.long .LDIFF_SYM2616
.Lfde40_start:

	.long 0
	.balign 8
	.quad .Lm_38

.LDIFF_SYM2617=.Lme_38 - .Lm_38
	.long .LDIFF_SYM2617
	.long 0
	.byte 68,14,32,68,141,4,69,142,3,69,143,2,10,68,8,13,69,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde40_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetOriginalBaseMethod"
	.string "Mono_Cecil_Rocks_MethodDefinitionRocks_GetOriginalBaseMethod_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetOriginalBaseMethod"
	.quad .Lm_39
	.quad .Lme_39

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2618=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2618
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2619=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2619
	.byte 1,94,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2620=.Lfde41_end - .Lfde41_start
	.long .LDIFF_SYM2620
.Lfde41_start:

	.long 0
	.balign 8
	.quad .Lm_39

.LDIFF_SYM2621=.Lme_39 - .Lm_39
	.long .LDIFF_SYM2621
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde41_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:ResolveBaseType"
	.string "Mono_Cecil_Rocks_MethodDefinitionRocks_ResolveBaseType_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:ResolveBaseType"
	.quad .Lm_3a
	.quad .Lme_3a

	.byte 2,118,16,3
	.string "type"

.LDIFF_SYM2622=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2622
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2623=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2623
	.byte 1,94,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2624=.Lfde42_end - .Lfde42_start
	.long .LDIFF_SYM2624
.Lfde42_start:

	.long 0
	.balign 8
	.quad .Lm_3a

.LDIFF_SYM2625=.Lme_3a - .Lm_3a
	.long .LDIFF_SYM2625
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde42_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetMatchingMethod"
	.string "Mono_Cecil_Rocks_MethodDefinitionRocks_GetMatchingMethod_Mono_Cecil_TypeDefinition_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.MethodDefinitionRocks:GetMatchingMethod"
	.quad .Lm_3b
	.quad .Lme_3b

	.byte 2,118,16,3
	.string "type"

.LDIFF_SYM2626=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2626
	.byte 2,119,0,3
	.string "method"

.LDIFF_SYM2627=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2627
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2628=.Lfde43_end - .Lfde43_start
	.long .LDIFF_SYM2628
.Lfde43_start:

	.long 0
	.balign 8
	.quad .Lm_3b

.LDIFF_SYM2629=.Lme_3b - .Lm_3b
	.long .LDIFF_SYM2629
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde43_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks:GetAllTypes"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks_GetAllTypes_Mono_Cecil_ModuleDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks:GetAllTypes"
	.quad .Lm_3c
	.quad .Lme_3c

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2630=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2630
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2631=.Lfde44_end - .Lfde44_start
	.long .LDIFF_SYM2631
.Lfde44_start:

	.long 0
	.balign 8
	.quad .Lm_3c

.LDIFF_SYM2632=.Lme_3c - .Lm_3c
	.long .LDIFF_SYM2632
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde44_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ParameterReferenceRocks:GetSequence"
	.string "Mono_Cecil_Rocks_ParameterReferenceRocks_GetSequence_Mono_Cecil_ParameterReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ParameterReferenceRocks:GetSequence"
	.quad .Lm_3d
	.quad .Lme_3d

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2633=.LTDIE_186_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2633
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2634=.Lfde45_end - .Lfde45_start
	.long .LDIFF_SYM2634
.Lfde45_start:

	.long 0
	.balign 8
	.quad .Lm_3d

.LDIFF_SYM2635=.Lme_3d - .Lm_3d
	.long .LDIFF_SYM2635
	.long 0
	.byte 68,14,16,68,143,2,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde45_end:

.section ".debug_info"
.subsection 0
.LTDIE_355:

	.byte 8
	.string "Mono_Cecil_SecurityAction"

	.byte 2
.LDIFF_SYM2636=.LDIE_U2 - .Ldebug_info_start
	.long .LDIFF_SYM2636
	.byte 9
	.string "Request"

	.byte 1,9
	.string "Demand"

	.byte 2,9
	.string "Assert"

	.byte 3,9
	.string "Deny"

	.byte 4,9
	.string "PermitOnly"

	.byte 5,9
	.string "LinkDemand"

	.byte 6,9
	.string "InheritDemand"

	.byte 7,9
	.string "RequestMinimum"

	.byte 8,9
	.string "RequestOptional"

	.byte 9,9
	.string "RequestRefuse"

	.byte 10,9
	.string "PreJitGrant"

	.byte 11,9
	.string "PreJitDeny"

	.byte 12,9
	.string "NonCasDemand"

	.byte 13,9
	.string "NonCasLinkDemand"

	.byte 14,9
	.string "NonCasInheritance"

	.byte 15,0,7
	.string "Mono_Cecil_SecurityAction"

.LDIFF_SYM2637=.LTDIE_355 - .Ldebug_info_start
	.long .LDIFF_SYM2637
.LTDIE_355_POINTER:

	.byte 13
.LDIFF_SYM2638=.LTDIE_355 - .Ldebug_info_start
	.long .LDIFF_SYM2638
.LTDIE_355_REFERENCE:

	.byte 14
.LDIFF_SYM2639=.LTDIE_355 - .Ldebug_info_start
	.long .LDIFF_SYM2639
.LTDIE_356:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2640=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2640
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2641=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2641
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2642=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2642
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2643=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2643
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2644=.LTDIE_356 - .Ldebug_info_start
	.long .LDIFF_SYM2644
.LTDIE_356_POINTER:

	.byte 13
.LDIFF_SYM2645=.LTDIE_356 - .Ldebug_info_start
	.long .LDIFF_SYM2645
.LTDIE_356_REFERENCE:

	.byte 14
.LDIFF_SYM2646=.LTDIE_356 - .Ldebug_info_start
	.long .LDIFF_SYM2646
.LTDIE_354:

	.byte 5
	.string "Mono_Cecil_SecurityDeclaration"

	.byte 48,16
.LDIFF_SYM2647=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2647
	.byte 2,35,0,6
	.string "signature"

.LDIFF_SYM2648=.LDIE_U4 - .Ldebug_info_start
	.long .LDIFF_SYM2648
	.byte 2,35,40,6
	.string "blob"

.LDIFF_SYM2649=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2649
	.byte 2,35,16,6
	.string "module"

.LDIFF_SYM2650=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2650
	.byte 2,35,24,6
	.string "resolved"

.LDIFF_SYM2651=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2651
	.byte 2,35,44,6
	.string "action"

.LDIFF_SYM2652=.LTDIE_355 - .Ldebug_info_start
	.long .LDIFF_SYM2652
	.byte 2,35,46,6
	.string "security_attributes"

.LDIFF_SYM2653=.LTDIE_356_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2653
	.byte 2,35,32,0,7
	.string "Mono_Cecil_SecurityDeclaration"

.LDIFF_SYM2654=.LTDIE_354 - .Ldebug_info_start
	.long .LDIFF_SYM2654
.LTDIE_354_POINTER:

	.byte 13
.LDIFF_SYM2655=.LTDIE_354 - .Ldebug_info_start
	.long .LDIFF_SYM2655
.LTDIE_354_REFERENCE:

	.byte 14
.LDIFF_SYM2656=.LTDIE_354 - .Ldebug_info_start
	.long .LDIFF_SYM2656
.LTDIE_358:

	.byte 8
	.string "System_Security_Permissions_PermissionState"

	.byte 4
.LDIFF_SYM2657=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2657
	.byte 9
	.string "None"

	.byte 0,9
	.string "Unrestricted"

	.byte 1,0,7
	.string "System_Security_Permissions_PermissionState"

.LDIFF_SYM2658=.LTDIE_358 - .Ldebug_info_start
	.long .LDIFF_SYM2658
.LTDIE_358_POINTER:

	.byte 13
.LDIFF_SYM2659=.LTDIE_358 - .Ldebug_info_start
	.long .LDIFF_SYM2659
.LTDIE_358_REFERENCE:

	.byte 14
.LDIFF_SYM2660=.LTDIE_358 - .Ldebug_info_start
	.long .LDIFF_SYM2660
.LTDIE_362:

	.byte 8
	.string "System_Security_Policy_PolicyStatementAttribute"

	.byte 4
.LDIFF_SYM2661=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2661
	.byte 9
	.string "All"

	.byte 3,9
	.string "Exclusive"

	.byte 1,9
	.string "LevelFinal"

	.byte 2,9
	.string "Nothing"

	.byte 0,0,7
	.string "System_Security_Policy_PolicyStatementAttribute"

.LDIFF_SYM2662=.LTDIE_362 - .Ldebug_info_start
	.long .LDIFF_SYM2662
.LTDIE_362_POINTER:

	.byte 13
.LDIFF_SYM2663=.LTDIE_362 - .Ldebug_info_start
	.long .LDIFF_SYM2663
.LTDIE_362_REFERENCE:

	.byte 14
.LDIFF_SYM2664=.LTDIE_362 - .Ldebug_info_start
	.long .LDIFF_SYM2664
.LTDIE_361:

	.byte 5
	.string "System_Security_Policy_PolicyStatement"

	.byte 32,16
.LDIFF_SYM2665=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2665
	.byte 2,35,0,6
	.string "perms"

.LDIFF_SYM2666=.LTDIE_357_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2666
	.byte 2,35,16,6
	.string "attrs"

.LDIFF_SYM2667=.LTDIE_362 - .Ldebug_info_start
	.long .LDIFF_SYM2667
	.byte 2,35,24,0,7
	.string "System_Security_Policy_PolicyStatement"

.LDIFF_SYM2668=.LTDIE_361 - .Ldebug_info_start
	.long .LDIFF_SYM2668
.LTDIE_361_POINTER:

	.byte 13
.LDIFF_SYM2669=.LTDIE_361 - .Ldebug_info_start
	.long .LDIFF_SYM2669
.LTDIE_361_REFERENCE:

	.byte 14
.LDIFF_SYM2670=.LTDIE_361 - .Ldebug_info_start
	.long .LDIFF_SYM2670
.LTDIE_363:

	.byte 17
	.string "System_Security_Policy_IMembershipCondition"

	.byte 16,7
	.string "System_Security_Policy_IMembershipCondition"

.LDIFF_SYM2671=.LTDIE_363 - .Ldebug_info_start
	.long .LDIFF_SYM2671
.LTDIE_363_POINTER:

	.byte 13
.LDIFF_SYM2672=.LTDIE_363 - .Ldebug_info_start
	.long .LDIFF_SYM2672
.LTDIE_363_REFERENCE:

	.byte 14
.LDIFF_SYM2673=.LTDIE_363 - .Ldebug_info_start
	.long .LDIFF_SYM2673
.LTDIE_360:

	.byte 5
	.string "System_Security_Policy_CodeGroup"

	.byte 56,16
.LDIFF_SYM2674=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2674
	.byte 2,35,0,6
	.string "m_policy"

.LDIFF_SYM2675=.LTDIE_361_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2675
	.byte 2,35,16,6
	.string "m_membershipCondition"

.LDIFF_SYM2676=.LTDIE_363_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2676
	.byte 2,35,24,6
	.string "m_description"

.LDIFF_SYM2677=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2677
	.byte 2,35,32,6
	.string "m_name"

.LDIFF_SYM2678=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2678
	.byte 2,35,40,6
	.string "m_children"

.LDIFF_SYM2679=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2679
	.byte 2,35,48,0,7
	.string "System_Security_Policy_CodeGroup"

.LDIFF_SYM2680=.LTDIE_360 - .Ldebug_info_start
	.long .LDIFF_SYM2680
.LTDIE_360_POINTER:

	.byte 13
.LDIFF_SYM2681=.LTDIE_360 - .Ldebug_info_start
	.long .LDIFF_SYM2681
.LTDIE_360_REFERENCE:

	.byte 14
.LDIFF_SYM2682=.LTDIE_360 - .Ldebug_info_start
	.long .LDIFF_SYM2682
.LTDIE_364:

	.byte 8
	.string "System_Security_PolicyLevelType"

	.byte 4
.LDIFF_SYM2683=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2683
	.byte 9
	.string "AppDomain"

	.byte 3,9
	.string "Enterprise"

	.byte 2,9
	.string "Machine"

	.byte 1,9
	.string "User"

	.byte 0,0,7
	.string "System_Security_PolicyLevelType"

.LDIFF_SYM2684=.LTDIE_364 - .Ldebug_info_start
	.long .LDIFF_SYM2684
.LTDIE_364_POINTER:

	.byte 13
.LDIFF_SYM2685=.LTDIE_364 - .Ldebug_info_start
	.long .LDIFF_SYM2685
.LTDIE_364_REFERENCE:

	.byte 14
.LDIFF_SYM2686=.LTDIE_364 - .Ldebug_info_start
	.long .LDIFF_SYM2686
.LTDIE_365:

	.byte 5
	.string "System_Security_SecurityElement"

	.byte 48,16
.LDIFF_SYM2687=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2687
	.byte 2,35,0,6
	.string "text"

.LDIFF_SYM2688=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2688
	.byte 2,35,16,6
	.string "tag"

.LDIFF_SYM2689=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2689
	.byte 2,35,24,6
	.string "attributes"

.LDIFF_SYM2690=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2690
	.byte 2,35,32,6
	.string "children"

.LDIFF_SYM2691=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2691
	.byte 2,35,40,0,7
	.string "System_Security_SecurityElement"

.LDIFF_SYM2692=.LTDIE_365 - .Ldebug_info_start
	.long .LDIFF_SYM2692
.LTDIE_365_POINTER:

	.byte 13
.LDIFF_SYM2693=.LTDIE_365 - .Ldebug_info_start
	.long .LDIFF_SYM2693
.LTDIE_365_REFERENCE:

	.byte 14
.LDIFF_SYM2694=.LTDIE_365 - .Ldebug_info_start
	.long .LDIFF_SYM2694
.LTDIE_359:

	.byte 5
	.string "System_Security_Policy_PolicyLevel"

	.byte 80,16
.LDIFF_SYM2695=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2695
	.byte 2,35,0,6
	.string "label"

.LDIFF_SYM2696=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2696
	.byte 2,35,16,6
	.string "root_code_group"

.LDIFF_SYM2697=.LTDIE_360_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2697
	.byte 2,35,24,6
	.string "full_trust_assemblies"

.LDIFF_SYM2698=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2698
	.byte 2,35,32,6
	.string "named_permission_sets"

.LDIFF_SYM2699=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2699
	.byte 2,35,40,6
	.string "_location"

.LDIFF_SYM2700=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2700
	.byte 2,35,48,6
	.string "_type"

.LDIFF_SYM2701=.LTDIE_364 - .Ldebug_info_start
	.long .LDIFF_SYM2701
	.byte 2,35,72,6
	.string "fullNames"

.LDIFF_SYM2702=.LTDIE_129_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2702
	.byte 2,35,56,6
	.string "xml"

.LDIFF_SYM2703=.LTDIE_365_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2703
	.byte 2,35,64,0,7
	.string "System_Security_Policy_PolicyLevel"

.LDIFF_SYM2704=.LTDIE_359 - .Ldebug_info_start
	.long .LDIFF_SYM2704
.LTDIE_359_POINTER:

	.byte 13
.LDIFF_SYM2705=.LTDIE_359 - .Ldebug_info_start
	.long .LDIFF_SYM2705
.LTDIE_359_REFERENCE:

	.byte 14
.LDIFF_SYM2706=.LTDIE_359 - .Ldebug_info_start
	.long .LDIFF_SYM2706
.LTDIE_357:

	.byte 5
	.string "System_Security_PermissionSet"

	.byte 48,16
.LDIFF_SYM2707=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2707
	.byte 2,35,0,6
	.string "state"

.LDIFF_SYM2708=.LTDIE_358 - .Ldebug_info_start
	.long .LDIFF_SYM2708
	.byte 2,35,40,6
	.string "list"

.LDIFF_SYM2709=.LTDIE_99_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2709
	.byte 2,35,16,6
	.string "_policyLevel"

.LDIFF_SYM2710=.LTDIE_359_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2710
	.byte 2,35,24,6
	.string "_declsec"

.LDIFF_SYM2711=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2711
	.byte 2,35,44,6
	.string "_readOnly"

.LDIFF_SYM2712=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2712
	.byte 2,35,45,6
	.string "_ignored"

.LDIFF_SYM2713=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2713
	.byte 2,35,32,0,7
	.string "System_Security_PermissionSet"

.LDIFF_SYM2714=.LTDIE_357 - .Ldebug_info_start
	.long .LDIFF_SYM2714
.LTDIE_357_POINTER:

	.byte 13
.LDIFF_SYM2715=.LTDIE_357 - .Ldebug_info_start
	.long .LDIFF_SYM2715
.LTDIE_357_REFERENCE:

	.byte 14
.LDIFF_SYM2716=.LTDIE_357 - .Ldebug_info_start
	.long .LDIFF_SYM2716
	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:ToPermissionSet"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_ToPermissionSet_Mono_Cecil_SecurityDeclaration"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:ToPermissionSet"
	.quad .Lm_3e
	.quad .Lme_3e

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2717=.LTDIE_354_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2717
	.byte 2,119,8,11
	.string "V_0"

.LDIFF_SYM2718=.LTDIE_357_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2718
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2719=.Lfde46_end - .Lfde46_start
	.long .LDIFF_SYM2719
.Lfde46_start:

	.long 0
	.balign 8
	.quad .Lm_3e

.LDIFF_SYM2720=.Lme_3e - .Lm_3e
	.long .LDIFF_SYM2720
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde46_end:

.section ".debug_info"
.subsection 0
.LTDIE_367:

	.byte 5
	.string "Mono_Collections_Generic_Collection`1"

	.byte 32,16
.LDIFF_SYM2721=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2721
	.byte 2,35,0,6
	.string "items"

.LDIFF_SYM2722=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2722
	.byte 2,35,16,6
	.string "size"

.LDIFF_SYM2723=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2723
	.byte 2,35,24,6
	.string "version"

.LDIFF_SYM2724=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2724
	.byte 2,35,28,0,7
	.string "Mono_Collections_Generic_Collection`1"

.LDIFF_SYM2725=.LTDIE_367 - .Ldebug_info_start
	.long .LDIFF_SYM2725
.LTDIE_367_POINTER:

	.byte 13
.LDIFF_SYM2726=.LTDIE_367 - .Ldebug_info_start
	.long .LDIFF_SYM2726
.LTDIE_367_REFERENCE:

	.byte 14
.LDIFF_SYM2727=.LTDIE_367 - .Ldebug_info_start
	.long .LDIFF_SYM2727
.LTDIE_366:

	.byte 5
	.string "Mono_Cecil_SecurityAttribute"

	.byte 40,16
.LDIFF_SYM2728=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2728
	.byte 2,35,0,6
	.string "attribute_type"

.LDIFF_SYM2729=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2729
	.byte 2,35,16,6
	.string "fields"

.LDIFF_SYM2730=.LTDIE_367_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2730
	.byte 2,35,24,6
	.string "properties"

.LDIFF_SYM2731=.LTDIE_367_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2731
	.byte 2,35,32,0,7
	.string "Mono_Cecil_SecurityAttribute"

.LDIFF_SYM2732=.LTDIE_366 - .Ldebug_info_start
	.long .LDIFF_SYM2732
.LTDIE_366_POINTER:

	.byte 13
.LDIFF_SYM2733=.LTDIE_366 - .Ldebug_info_start
	.long .LDIFF_SYM2733
.LTDIE_366_REFERENCE:

	.byte 14
.LDIFF_SYM2734=.LTDIE_366 - .Ldebug_info_start
	.long .LDIFF_SYM2734
.LTDIE_371:

	.byte 5
	.string "System_Attribute"

	.byte 16,16
.LDIFF_SYM2735=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2735
	.byte 2,35,0,0,7
	.string "System_Attribute"

.LDIFF_SYM2736=.LTDIE_371 - .Ldebug_info_start
	.long .LDIFF_SYM2736
.LTDIE_371_POINTER:

	.byte 13
.LDIFF_SYM2737=.LTDIE_371 - .Ldebug_info_start
	.long .LDIFF_SYM2737
.LTDIE_371_REFERENCE:

	.byte 14
.LDIFF_SYM2738=.LTDIE_371 - .Ldebug_info_start
	.long .LDIFF_SYM2738
.LTDIE_372:

	.byte 8
	.string "System_Security_Permissions_SecurityAction"

	.byte 4
.LDIFF_SYM2739=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2739
	.byte 9
	.string "Demand"

	.byte 2,9
	.string "Assert"

	.byte 3,9
	.string "Deny"

	.byte 4,9
	.string "PermitOnly"

	.byte 5,9
	.string "LinkDemand"

	.byte 6,9
	.string "InheritanceDemand"

	.byte 7,9
	.string "RequestMinimum"

	.byte 8,9
	.string "RequestOptional"

	.byte 9,9
	.string "RequestRefuse"

	.byte 10,0,7
	.string "System_Security_Permissions_SecurityAction"

.LDIFF_SYM2740=.LTDIE_372 - .Ldebug_info_start
	.long .LDIFF_SYM2740
.LTDIE_372_POINTER:

	.byte 13
.LDIFF_SYM2741=.LTDIE_372 - .Ldebug_info_start
	.long .LDIFF_SYM2741
.LTDIE_372_REFERENCE:

	.byte 14
.LDIFF_SYM2742=.LTDIE_372 - .Ldebug_info_start
	.long .LDIFF_SYM2742
.LTDIE_370:

	.byte 5
	.string "System_Security_Permissions_SecurityAttribute"

	.byte 24,16
.LDIFF_SYM2743=.LTDIE_371 - .Ldebug_info_start
	.long .LDIFF_SYM2743
	.byte 2,35,0,6
	.string "m_Action"

.LDIFF_SYM2744=.LTDIE_372 - .Ldebug_info_start
	.long .LDIFF_SYM2744
	.byte 2,35,16,6
	.string "m_Unrestricted"

.LDIFF_SYM2745=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2745
	.byte 2,35,20,0,7
	.string "System_Security_Permissions_SecurityAttribute"

.LDIFF_SYM2746=.LTDIE_370 - .Ldebug_info_start
	.long .LDIFF_SYM2746
.LTDIE_370_POINTER:

	.byte 13
.LDIFF_SYM2747=.LTDIE_370 - .Ldebug_info_start
	.long .LDIFF_SYM2747
.LTDIE_370_REFERENCE:

	.byte 14
.LDIFF_SYM2748=.LTDIE_370 - .Ldebug_info_start
	.long .LDIFF_SYM2748
.LTDIE_369:

	.byte 5
	.string "System_Security_Permissions_CodeAccessSecurityAttribute"

	.byte 24,16
.LDIFF_SYM2749=.LTDIE_370 - .Ldebug_info_start
	.long .LDIFF_SYM2749
	.byte 2,35,0,0,7
	.string "System_Security_Permissions_CodeAccessSecurityAttribute"

.LDIFF_SYM2750=.LTDIE_369 - .Ldebug_info_start
	.long .LDIFF_SYM2750
.LTDIE_369_POINTER:

	.byte 13
.LDIFF_SYM2751=.LTDIE_369 - .Ldebug_info_start
	.long .LDIFF_SYM2751
.LTDIE_369_REFERENCE:

	.byte 14
.LDIFF_SYM2752=.LTDIE_369 - .Ldebug_info_start
	.long .LDIFF_SYM2752
.LTDIE_368:

	.byte 5
	.string "System_Security_Permissions_PermissionSetAttribute"

	.byte 64,16
.LDIFF_SYM2753=.LTDIE_369 - .Ldebug_info_start
	.long .LDIFF_SYM2753
	.byte 2,35,0,6
	.string "file"

.LDIFF_SYM2754=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2754
	.byte 2,35,24,6
	.string "name"

.LDIFF_SYM2755=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2755
	.byte 2,35,32,6
	.string "isUnicodeEncoded"

.LDIFF_SYM2756=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2756
	.byte 2,35,56,6
	.string "xml"

.LDIFF_SYM2757=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2757
	.byte 2,35,40,6
	.string "hex"

.LDIFF_SYM2758=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2758
	.byte 2,35,48,0,7
	.string "System_Security_Permissions_PermissionSetAttribute"

.LDIFF_SYM2759=.LTDIE_368 - .Ldebug_info_start
	.long .LDIFF_SYM2759
.LTDIE_368_POINTER:

	.byte 13
.LDIFF_SYM2760=.LTDIE_368 - .Ldebug_info_start
	.long .LDIFF_SYM2760
.LTDIE_368_REFERENCE:

	.byte 14
.LDIFF_SYM2761=.LTDIE_368 - .Ldebug_info_start
	.long .LDIFF_SYM2761
	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:TryProcessPermissionSetAttribute"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_TryProcessPermissionSetAttribute_Mono_Cecil_SecurityDeclaration_System_Security_PermissionSet_"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:TryProcessPermissionSetAttribute"
	.quad .Lm_3f
	.quad .Lme_3f

	.byte 2,118,16,3
	.string "declaration"

.LDIFF_SYM2762=.LTDIE_354_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2762
	.byte 1,94,3
	.string "set"

.LDIFF_SYM2763=.LDIE_I - .Ldebug_info_start
	.long .LDIFF_SYM2763
	.byte 3,119,192,0,11
	.string "V_0"

.LDIFF_SYM2764=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2764
	.byte 1,93,11
	.string "V_1"

.LDIFF_SYM2765=.LTDIE_368_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2765
	.byte 1,94,11
	.string "V_2"

.LDIFF_SYM2766=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2766
	.byte 2,119,40,11
	.string "V_3"

.LDIFF_SYM2767=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2767
	.byte 1,92,11
	.string "V_4"

.LDIFF_SYM2768=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2768
	.byte 2,119,24,11
	.string "V_5"

.LDIFF_SYM2769=.LDIE_STRING - .Ldebug_info_start
	.long .LDIFF_SYM2769
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2770=.Lfde47_end - .Lfde47_start
	.long .LDIFF_SYM2770
.Lfde47_start:

	.long 0
	.balign 8
	.quad .Lm_3f

.LDIFF_SYM2771=.Lme_3f - .Lm_3f
	.long .LDIFF_SYM2771
	.long 0
	.byte 68,14,96,68,140,12,69,141,11,69,142,10,10,68,8,12,69,8,13,69,8,14,68,12,7,8,65,11
	.balign 8
.Lfde47_end:

.section ".debug_info"
.subsection 0
.LTDIE_373:

	.byte 17
	.string "System_Security_IPermission"

	.byte 16,7
	.string "System_Security_IPermission"

.LDIFF_SYM2772=.LTDIE_373 - .Ldebug_info_start
	.long .LDIFF_SYM2772
.LTDIE_373_POINTER:

	.byte 13
.LDIFF_SYM2773=.LTDIE_373 - .Ldebug_info_start
	.long .LDIFF_SYM2773
.LTDIE_373_REFERENCE:

	.byte 14
.LDIFF_SYM2774=.LTDIE_373 - .Ldebug_info_start
	.long .LDIFF_SYM2774
	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreatePermissionSet"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermissionSet_Mono_Cecil_SecurityDeclaration"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreatePermissionSet"
	.quad .Lm_40
	.quad .Lme_40

	.byte 2,118,16,3
	.string "declaration"

.LDIFF_SYM2775=.LTDIE_354_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2775
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2776=.LTDIE_357_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2776
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2777=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2777
	.byte 2,118,80,11
	.string "V_2"

.LDIFF_SYM2778=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2778
	.byte 1,93,11
	.string "V_3"

.LDIFF_SYM2779=.LTDIE_373_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2779
	.byte 1,93,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2780=.Lfde48_end - .Lfde48_start
	.long .LDIFF_SYM2780
.Lfde48_start:

	.long 0
	.balign 8
	.quad .Lm_40

.LDIFF_SYM2781=.Lme_40 - .Lm_40
	.long .LDIFF_SYM2781
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,141,5,68,142,4,68,143,3,10,68,8,13,68,8,14,68,8,15,65,8,6,12,7
	.byte 8,65,11
	.balign 8
.Lfde48_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreatePermission"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CreatePermission_Mono_Cecil_SecurityDeclaration_Mono_Cecil_SecurityAttribute"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreatePermission"
	.quad .Lm_41
	.quad .Lme_41

	.byte 2,118,16,3
	.string "declaration"

.LDIFF_SYM2782=.LTDIE_354_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2782
	.byte 2,119,16,3
	.string "attribute"

.LDIFF_SYM2783=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2783
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2784=.Lfde49_end - .Lfde49_start
	.long .LDIFF_SYM2784
.Lfde49_start:

	.long 0
	.balign 8
	.quad .Lm_41

.LDIFF_SYM2785=.Lme_41 - .Lm_41
	.long .LDIFF_SYM2785
	.long 0
	.byte 68,14,32,68,141,4,69,143,3,10,68,8,13,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde49_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttribute"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttribute_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttribute"
	.quad .Lm_42
	.quad .Lme_42

	.byte 2,118,16,3
	.string "security_attribute"

.LDIFF_SYM2786=.LTDIE_370_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2786
	.byte 2,119,16,3
	.string "attribute"

.LDIFF_SYM2787=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2787
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2788=.Lfde50_end - .Lfde50_start
	.long .LDIFF_SYM2788
.Lfde50_start:

	.long 0
	.balign 8
	.quad .Lm_42

.LDIFF_SYM2789=.Lme_42 - .Lm_42
	.long .LDIFF_SYM2789
	.long 0
	.byte 68,14,32,68,141,4,69,143,3,10,68,8,13,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde50_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttributeFields"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeFields_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttributeFields"
	.quad .Lm_43
	.quad .Lme_43

	.byte 2,118,16,3
	.string "security_attribute"

.LDIFF_SYM2790=.LTDIE_370_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2790
	.byte 1,94,3
	.string "attribute"

.LDIFF_SYM2791=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2791
	.byte 3,118,248,126,11
	.string "V_0"

.LDIFF_SYM2792=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2792
	.byte 1,93,11
	.string "V_1"

.LDIFF_SYM2793=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2793
	.byte 3,118,160,127,11
	.string "V_2"

.LDIFF_SYM2794=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2794
	.byte 2,118,72,11
	.string "V_3"

.LDIFF_SYM2795=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2795
	.byte 2,118,96,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2796=.Lfde51_end - .Lfde51_start
	.long .LDIFF_SYM2796
.Lfde51_start:

	.long 0
	.balign 8
	.quad .Lm_43

.LDIFF_SYM2797=.Lme_43 - .Lm_43
	.long .LDIFF_SYM2797
	.long 0
	.byte 65,14,16,134,2,67,13,6,75,141,4,68,142,3,10,68,8,13,68,8,14,65,8,6,12,7,8,65,11
	.balign 8
.Lfde51_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttributeProperties"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CompleteSecurityAttributeProperties_System_Security_Permissions_SecurityAttribute_Mono_Cecil_SecurityAttribute"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CompleteSecurityAttributeProperties"
	.quad .Lm_44
	.quad .Lme_44

	.byte 2,118,16,3
	.string "security_attribute"

.LDIFF_SYM2798=.LTDIE_370_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2798
	.byte 1,94,3
	.string "attribute"

.LDIFF_SYM2799=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2799
	.byte 3,118,248,126,11
	.string "V_0"

.LDIFF_SYM2800=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2800
	.byte 1,93,11
	.string "V_1"

.LDIFF_SYM2801=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2801
	.byte 3,118,160,127,11
	.string "V_2"

.LDIFF_SYM2802=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2802
	.byte 2,118,72,11
	.string "V_3"

.LDIFF_SYM2803=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2803
	.byte 2,118,96,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2804=.Lfde52_end - .Lfde52_start
	.long .LDIFF_SYM2804
.Lfde52_start:

	.long 0
	.balign 8
	.quad .Lm_44

.LDIFF_SYM2805=.Lme_44 - .Lm_44
	.long .LDIFF_SYM2805
	.long 0
	.byte 65,14,16,134,2,67,13,6,75,141,4,68,142,3,10,68,8,13,68,8,14,65,8,6,12,7,8,65,11
	.balign 8
.Lfde52_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreateSecurityAttribute"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_CreateSecurityAttribute_System_Type_Mono_Cecil_SecurityDeclaration"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:CreateSecurityAttribute"
	.quad .Lm_45
	.quad .Lme_45

	.byte 2,118,16,3
	.string "attribute_type"

.LDIFF_SYM2806=.LTDIE_41_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2806
	.byte 2,118,64,3
	.string "declaration"

.LDIFF_SYM2807=.LTDIE_354_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2807
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2808=.LTDIE_370_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2808
	.byte 2,118,112,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2809=.Lfde53_end - .Lfde53_start
	.long .LDIFF_SYM2809
.Lfde53_start:

	.long 0
	.balign 8
	.quad .Lm_45

.LDIFF_SYM2810=.Lme_45 - .Lm_45
	.long .LDIFF_SYM2810
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,143,3,10,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde53_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:ToSecurityDeclaration"
	.string "Mono_Cecil_Rocks_SecurityDeclarationRocks_ToSecurityDeclaration_System_Security_PermissionSet_Mono_Cecil_SecurityAction_Mono_Cecil_ModuleDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.SecurityDeclarationRocks:ToSecurityDeclaration"
	.quad .Lm_46
	.quad .Lme_46

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2811=.LTDIE_357_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2811
	.byte 1,93,3
	.string "action"

.LDIFF_SYM2812=.LTDIE_355 - .Ldebug_info_start
	.long .LDIFF_SYM2812
	.byte 3,118,144,127,3
	.string "module"

.LDIFF_SYM2813=.LTDIE_11_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2813
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2814=.LTDIE_366_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2814
	.byte 1,94,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2815=.Lfde54_end - .Lfde54_start
	.long .LDIFF_SYM2815
.Lfde54_start:

	.long 0
	.balign 8
	.quad .Lm_46

.LDIFF_SYM2816=.Lme_46 - .Lm_46
	.long .LDIFF_SYM2816
	.long 0
	.byte 65,14,16,134,2,67,13,6,75,141,5,68,142,4,68,143,3,10,68,8,13,68,8,14,68,8,15,65,8,6,12,7
	.byte 8,65,11
	.balign 8
.Lfde54_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetConstructors"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks_GetConstructors_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetConstructors"
	.quad .Lm_47
	.quad .Lme_47

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2817=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2817
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2818=.Lfde55_end - .Lfde55_start
	.long .LDIFF_SYM2818
.Lfde55_start:

	.long 0
	.balign 8
	.quad .Lm_47

.LDIFF_SYM2819=.Lme_47 - .Lm_47
	.long .LDIFF_SYM2819
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde55_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetStaticConstructor"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks_GetStaticConstructor_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetStaticConstructor"
	.quad .Lm_48
	.quad .Lme_48

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2820=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2820
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2821=.Lfde56_end - .Lfde56_start
	.long .LDIFF_SYM2821
.Lfde56_start:

	.long 0
	.balign 8
	.quad .Lm_48

.LDIFF_SYM2822=.Lme_48 - .Lm_48
	.long .LDIFF_SYM2822
	.long 0
	.byte 68,14,48,68,142,6,69,143,5,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde56_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetMethods"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks_GetMethods_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetMethods"
	.quad .Lm_49
	.quad .Lme_49

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2823=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2823
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2824=.Lfde57_end - .Lfde57_start
	.long .LDIFF_SYM2824
.Lfde57_start:

	.long 0
	.balign 8
	.quad .Lm_49

.LDIFF_SYM2825=.Lme_49 - .Lm_49
	.long .LDIFF_SYM2825
	.long 0
	.byte 68,14,32,68,142,4,69,143,3,10,68,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde57_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetEnumUnderlyingType"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks_GetEnumUnderlyingType_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks:GetEnumUnderlyingType"
	.quad .Lm_4a
	.quad .Lme_4a

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2826=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2826
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2827=.Lfde58_end - .Lfde58_start
	.long .LDIFF_SYM2827
.Lfde58_start:

	.long 0
	.balign 8
	.quad .Lm_4a

.LDIFF_SYM2828=.Lme_4a - .Lm_4a
	.long .LDIFF_SYM2828
	.long 0
	.byte 68,14,16,68,143,2,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde58_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeArrayType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeArrayType"
	.quad .Lm_4b
	.quad .Lme_4b

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2829=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2829
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2830=.Lfde59_end - .Lfde59_start
	.long .LDIFF_SYM2830
.Lfde59_start:

	.long 0
	.balign 8
	.quad .Lm_4b

.LDIFF_SYM2831=.Lme_4b - .Lm_4b
	.long .LDIFF_SYM2831
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde59_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeArrayType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeArrayType_Mono_Cecil_TypeReference_int"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeArrayType"
	.quad .Lm_4c
	.quad .Lme_4c

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2832=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2832
	.byte 1,94,3
	.string "rank"

.LDIFF_SYM2833=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2833
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2834=.LTDIE_337_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2834
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2835=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2835
	.byte 1,93,11
	.string "V_2"

.LDIFF_SYM2836=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2836
	.byte 2,119,40,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2837=.Lfde60_end - .Lfde60_start
	.long .LDIFF_SYM2837
.Lfde60_start:

	.long 0
	.balign 8
	.quad .Lm_4c

.LDIFF_SYM2838=.Lme_4c - .Lm_4c
	.long .LDIFF_SYM2838
	.long 0
	.byte 68,14,80,68,141,10,69,142,9,69,143,8,10,68,8,13,69,8,14,69,8,15,68,12,7,8,65,11
	.balign 8
.Lfde60_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakePointerType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakePointerType_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakePointerType"
	.quad .Lm_4d
	.quad .Lme_4d

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2839=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2839
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2840=.Lfde61_end - .Lfde61_start
	.long .LDIFF_SYM2840
.Lfde61_start:

	.long 0
	.balign 8
	.quad .Lm_4d

.LDIFF_SYM2841=.Lme_4d - .Lm_4d
	.long .LDIFF_SYM2841
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde61_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeByReferenceType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeByReferenceType_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeByReferenceType"
	.quad .Lm_4e
	.quad .Lme_4e

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2842=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2842
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2843=.Lfde62_end - .Lfde62_start
	.long .LDIFF_SYM2843
.Lfde62_start:

	.long 0
	.balign 8
	.quad .Lm_4e

.LDIFF_SYM2844=.Lme_4e - .Lm_4e
	.long .LDIFF_SYM2844
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde62_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeOptionalModifierType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeOptionalModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeOptionalModifierType"
	.quad .Lm_4f
	.quad .Lme_4f

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2845=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2845
	.byte 2,119,0,3
	.string "modifierType"

.LDIFF_SYM2846=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2846
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2847=.Lfde63_end - .Lfde63_start
	.long .LDIFF_SYM2847
.Lfde63_start:

	.long 0
	.balign 8
	.quad .Lm_4f

.LDIFF_SYM2848=.Lme_4f - .Lm_4f
	.long .LDIFF_SYM2848
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde63_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeRequiredModifierType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeRequiredModifierType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeRequiredModifierType"
	.quad .Lm_50
	.quad .Lme_50

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2849=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2849
	.byte 2,119,0,3
	.string "modifierType"

.LDIFF_SYM2850=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2850
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2851=.Lfde64_end - .Lfde64_start
	.long .LDIFF_SYM2851
.Lfde64_start:

	.long 0
	.balign 8
	.quad .Lm_50

.LDIFF_SYM2852=.Lme_50 - .Lm_50
	.long .LDIFF_SYM2852
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde64_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeGenericInstanceType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeGenericInstanceType_Mono_Cecil_TypeReference_Mono_Cecil_TypeReference__"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeGenericInstanceType"
	.quad .Lm_51
	.quad .Lme_51

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2853=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2853
	.byte 1,94,3
	.string "arguments"

.LDIFF_SYM2854=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2854
	.byte 1,95,11
	.string "V_0"

.LDIFF_SYM2855=.LTDIE_329_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2855
	.byte 1,94,11
	.string "V_1"

.LDIFF_SYM2856=.LDIE_SZARRAY - .Ldebug_info_start
	.long .LDIFF_SYM2856
	.byte 1,93,11
	.string "V_2"

.LDIFF_SYM2857=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2857
	.byte 1,95,11
	.string "V_3"

.LDIFF_SYM2858=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2858
	.byte 1,92,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2859=.Lfde65_end - .Lfde65_start
	.long .LDIFF_SYM2859
.Lfde65_start:

	.long 0
	.balign 8
	.quad .Lm_51

.LDIFF_SYM2860=.Lme_51 - .Lm_51
	.long .LDIFF_SYM2860
	.long 0
	.byte 68,14,64,68,140,8,69,141,7,69,142,6,69,143,5,10,68,8,12,69,8,13,69,8,14,69,8,15,68,12,7,8
	.byte 65,11
	.balign 8
.Lfde65_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakePinnedType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakePinnedType_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakePinnedType"
	.quad .Lm_52
	.quad .Lme_52

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2861=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2861
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2862=.Lfde66_end - .Lfde66_start
	.long .LDIFF_SYM2862
.Lfde66_start:

	.long 0
	.balign 8
	.quad .Lm_52

.LDIFF_SYM2863=.Lme_52 - .Lm_52
	.long .LDIFF_SYM2863
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde66_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeSentinelType"
	.string "Mono_Cecil_Rocks_TypeReferenceRocks_MakeSentinelType_Mono_Cecil_TypeReference"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeReferenceRocks:MakeSentinelType"
	.quad .Lm_53
	.quad .Lme_53

	.byte 2,118,16,3
	.string "self"

.LDIFF_SYM2864=.LTDIE_8_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2864
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2865=.Lfde67_end - .Lfde67_start
	.long .LDIFF_SYM2865
.Lfde67_start:

	.long 0
	.balign 8
	.quad .Lm_53

.LDIFF_SYM2866=.Lme_53 - .Lm_53
	.long .LDIFF_SYM2866
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde67_end:

.section ".debug_info"
.subsection 0
.LTDIE_375:

	.byte 5
	.string "System_Func`2"

	.byte 128,1,16
.LDIFF_SYM2867=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM2867
	.byte 2,35,0,0,7
	.string "System_Func`2"

.LDIFF_SYM2868=.LTDIE_375 - .Ldebug_info_start
	.long .LDIFF_SYM2868
.LTDIE_375_POINTER:

	.byte 13
.LDIFF_SYM2869=.LTDIE_375 - .Ldebug_info_start
	.long .LDIFF_SYM2869
.LTDIE_375_REFERENCE:

	.byte 14
.LDIFF_SYM2870=.LTDIE_375 - .Ldebug_info_start
	.long .LDIFF_SYM2870
.LTDIE_374:

	.byte 5
	.string "_<>c__DisplayClass0_0`2"

	.byte 24,16
.LDIFF_SYM2871=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2871
	.byte 2,35,0,6
	.string "g"

.LDIFF_SYM2872=.LTDIE_375_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2872
	.byte 2,35,16,0,7
	.string "_<>c__DisplayClass0_0`2"

.LDIFF_SYM2873=.LTDIE_374 - .Ldebug_info_start
	.long .LDIFF_SYM2873
.LTDIE_374_POINTER:

	.byte 13
.LDIFF_SYM2874=.LTDIE_374 - .Ldebug_info_start
	.long .LDIFF_SYM2874
.LTDIE_374_REFERENCE:

	.byte 14
.LDIFF_SYM2875=.LTDIE_374 - .Ldebug_info_start
	.long .LDIFF_SYM2875
	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<>c__DisplayClass0_0`2<A_REF,_R_REF>:.ctor"
	.string "Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<>c__DisplayClass0_0`2<A_REF,_R_REF>:.ctor"
	.quad .Lm_54
	.quad .Lme_54

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2876=.LTDIE_374_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2876
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2877=.Lfde68_end - .Lfde68_start
	.long .LDIFF_SYM2877
.Lfde68_start:

	.long 0
	.balign 8
	.quad .Lm_54

.LDIFF_SYM2878=.Lme_54 - .Lm_54
	.long .LDIFF_SYM2878
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde68_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<>c__DisplayClass0_0`2<A_REF,_R_REF>:<Y>b__0"
	.string "Mono_Cecil_Rocks_Functional__c__DisplayClass0_0_2_A_REF_R_REF__Yb__0_A_REF"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<>c__DisplayClass0_0`2<A_REF,_R_REF>:<Y>b__0"
	.quad .Lm_55
	.quad .Lme_55

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2879=.LTDIE_374_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2879
	.byte 2,119,0,3
	.string "a"

.LDIFF_SYM2880=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2880
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2881=.Lfde69_end - .Lfde69_start
	.long .LDIFF_SYM2881
.Lfde69_start:

	.long 0
	.balign 8
	.quad .Lm_55

.LDIFF_SYM2882=.Lme_55 - .Lm_55
	.long .LDIFF_SYM2882
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde69_end:

.section ".debug_info"
.subsection 0
.LTDIE_377:

	.byte 17
	.string "System_Collections_Generic_IEnumerable`1"

	.byte 16,7
	.string "System_Collections_Generic_IEnumerable`1"

.LDIFF_SYM2883=.LTDIE_377 - .Ldebug_info_start
	.long .LDIFF_SYM2883
.LTDIE_377_POINTER:

	.byte 13
.LDIFF_SYM2884=.LTDIE_377 - .Ldebug_info_start
	.long .LDIFF_SYM2884
.LTDIE_377_REFERENCE:

	.byte 14
.LDIFF_SYM2885=.LTDIE_377 - .Ldebug_info_start
	.long .LDIFF_SYM2885
.LTDIE_378:

	.byte 17
	.string "System_Collections_Generic_IEnumerator`1"

	.byte 16,7
	.string "System_Collections_Generic_IEnumerator`1"

.LDIFF_SYM2886=.LTDIE_378 - .Ldebug_info_start
	.long .LDIFF_SYM2886
.LTDIE_378_POINTER:

	.byte 13
.LDIFF_SYM2887=.LTDIE_378 - .Ldebug_info_start
	.long .LDIFF_SYM2887
.LTDIE_378_REFERENCE:

	.byte 14
.LDIFF_SYM2888=.LTDIE_378 - .Ldebug_info_start
	.long .LDIFF_SYM2888
.LTDIE_376:

	.byte 5
	.string "_<PrependIterator>d__2`1"

	.byte 72,16
.LDIFF_SYM2889=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2889
	.byte 2,35,0,6
	.string "<>1__state"

.LDIFF_SYM2890=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2890
	.byte 2,35,64,6
	.string "<>2__current"

.LDIFF_SYM2891=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2891
	.byte 2,35,16,6
	.string "<>l__initialThreadId"

.LDIFF_SYM2892=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2892
	.byte 2,35,68,6
	.string "element"

.LDIFF_SYM2893=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2893
	.byte 2,35,24,6
	.string "<>3__element"

.LDIFF_SYM2894=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2894
	.byte 2,35,32,6
	.string "source"

.LDIFF_SYM2895=.LTDIE_377_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2895
	.byte 2,35,40,6
	.string "<>3__source"

.LDIFF_SYM2896=.LTDIE_377_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2896
	.byte 2,35,48,6
	.string "<>7__wrap1"

.LDIFF_SYM2897=.LTDIE_378_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2897
	.byte 2,35,56,0,7
	.string "_<PrependIterator>d__2`1"

.LDIFF_SYM2898=.LTDIE_376 - .Ldebug_info_start
	.long .LDIFF_SYM2898
.LTDIE_376_POINTER:

	.byte 13
.LDIFF_SYM2899=.LTDIE_376 - .Ldebug_info_start
	.long .LDIFF_SYM2899
.LTDIE_376_REFERENCE:

	.byte 14
.LDIFF_SYM2900=.LTDIE_376 - .Ldebug_info_start
	.long .LDIFF_SYM2900
	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:.ctor"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__ctor_int"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:.ctor"
	.quad .Lm_56
	.quad .Lme_56

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2901=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2901
	.byte 2,119,0,3
	.string "<>1__state"

.LDIFF_SYM2902=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2902
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2903=.Lfde70_end - .Lfde70_start
	.long .LDIFF_SYM2903
.Lfde70_start:

	.long 0
	.balign 8
	.quad .Lm_56

.LDIFF_SYM2904=.Lme_56 - .Lm_56
	.long .LDIFF_SYM2904
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde70_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.IDisposable.Dispose"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_IDisposable_Dispose"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.IDisposable.Dispose"
	.quad .Lm_57
	.quad .Lme_57

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2905=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2905
	.byte 2,118,88,11
	.string "V_0"

.LDIFF_SYM2906=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2906
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2907=.Lfde71_end - .Lfde71_start
	.long .LDIFF_SYM2907
.Lfde71_start:

	.long 0
	.balign 8
	.quad .Lm_57

.LDIFF_SYM2908=.Lme_57 - .Lm_57
	.long .LDIFF_SYM2908
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,143,3,10,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde71_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:MoveNext"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_MoveNext"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:MoveNext"
	.quad .Lm_58
	.quad .Lme_58

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2909=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2909
	.byte 2,118,88,11
	.string "V_0"

.LDIFF_SYM2910=.LDIE_BOOLEAN - .Ldebug_info_start
	.long .LDIFF_SYM2910
	.byte 1,95,11
	.string "V_1"

.LDIFF_SYM2911=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2911
	.byte 1,95,11
	.string "V_2"

.LDIFF_SYM2912=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2912
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2913=.Lfde72_end - .Lfde72_start
	.long .LDIFF_SYM2913
.Lfde72_start:

	.long 0
	.balign 8
	.quad .Lm_58

.LDIFF_SYM2914=.Lme_58 - .Lm_58
	.long .LDIFF_SYM2914
	.long 0
	.byte 65,14,16,134,2,67,13,6,72,142,4,68,143,3,10,68,8,14,68,8,15,65,8,6,12,7,8,65,11
	.balign 8
.Lfde72_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:<>m__Finally1"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF__m__Finally1"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:<>m__Finally1"
	.quad .Lm_59
	.quad .Lme_59

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2915=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2915
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2916=.Lfde73_end - .Lfde73_start
	.long .LDIFF_SYM2916
.Lfde73_start:

	.long 0
	.balign 8
	.quad .Lm_59

.LDIFF_SYM2917=.Lme_59 - .Lm_59
	.long .LDIFF_SYM2917
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde73_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.Generic.IEnumerator<TSource>.get_Current"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerator_TSource_get_Current"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.Generic.IEnumerator<TSource>.get_Current"
	.quad .Lm_5a
	.quad .Lme_5a

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2918=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2918
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2919=.Lfde74_end - .Lfde74_start
	.long .LDIFF_SYM2919
.Lfde74_start:

	.long 0
	.balign 8
	.quad .Lm_5a

.LDIFF_SYM2920=.Lme_5a - .Lm_5a
	.long .LDIFF_SYM2920
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde74_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerator.Reset"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_Reset"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerator.Reset"
	.quad .Lm_5b
	.quad .Lme_5b

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2921=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2921
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2922=.Lfde75_end - .Lfde75_start
	.long .LDIFF_SYM2922
.Lfde75_start:

	.long 0
	.balign 8
	.quad .Lm_5b

.LDIFF_SYM2923=.Lme_5b - .Lm_5b
	.long .LDIFF_SYM2923
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde75_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerator.get_Current"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerator_get_Current"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerator.get_Current"
	.quad .Lm_5c
	.quad .Lme_5c

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2924=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2924
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2925=.Lfde76_end - .Lfde76_start
	.long .LDIFF_SYM2925
.Lfde76_start:

	.long 0
	.balign 8
	.quad .Lm_5c

.LDIFF_SYM2926=.Lme_5c - .Lm_5c
	.long .LDIFF_SYM2926
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde76_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.Generic.IEnumerable<TSource>.GetEnumerator"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_Generic_IEnumerable_TSource_GetEnumerator"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.Generic.IEnumerable<TSource>.GetEnumerator"
	.quad .Lm_5d
	.quad .Lme_5d

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2927=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2927
	.byte 2,119,8,11
	.string "V_0"

.LDIFF_SYM2928=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2928
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2929=.Lfde77_end - .Lfde77_start
	.long .LDIFF_SYM2929
.Lfde77_start:

	.long 0
	.balign 8
	.quad .Lm_5d

.LDIFF_SYM2930=.Lme_5d - .Lm_5d
	.long .LDIFF_SYM2930
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde77_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerable.GetEnumerator"
	.string "Mono_Cecil_Rocks_Functional__PrependIteratord__2_1_TSource_REF_System_Collections_IEnumerable_GetEnumerator"

	.byte 0,0
	.string "Mono.Cecil.Rocks.Functional/<PrependIterator>d__2`1<TSource_REF>:System.Collections.IEnumerable.GetEnumerator"
	.quad .Lm_5e
	.quad .Lme_5e

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2931=.LTDIE_376_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2931
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2932=.Lfde78_end - .Lfde78_start
	.long .LDIFF_SYM2932
.Lfde78_start:

	.long 0
	.balign 8
	.quad .Lm_5e

.LDIFF_SYM2933=.Lme_5e - .Lm_5e
	.long .LDIFF_SYM2933
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde78_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Code"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_get_Code"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Code"
	.quad .Lm_5f
	.quad .Lme_5f

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2934=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2934
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2935=.Lfde79_end - .Lfde79_start
	.long .LDIFF_SYM2935
.Lfde79_start:

	.long 0
	.balign 8
	.quad .Lm_5f

.LDIFF_SYM2936=.Lme_5f - .Lm_5f
	.long .LDIFF_SYM2936
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde79_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Code"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_set_Code_Mono_Cecil_Cil_CodeReader"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Code"
	.quad .Lm_60
	.quad .Lme_60

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2937=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2937
	.byte 2,119,0,3
	.string "value"

.LDIFF_SYM2938=.LTDIE_90_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2938
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2939=.Lfde80_end - .Lfde80_start
	.long .LDIFF_SYM2939
.Lfde80_start:

	.long 0
	.balign 8
	.quad .Lm_60

.LDIFF_SYM2940=.Lme_60 - .Lm_60
	.long .LDIFF_SYM2940
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde80_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Position"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_get_Position"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Position"
	.quad .Lm_61
	.quad .Lme_61

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2941=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2941
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2942=.Lfde81_end - .Lfde81_start
	.long .LDIFF_SYM2942
.Lfde81_start:

	.long 0
	.balign 8
	.quad .Lm_61

.LDIFF_SYM2943=.Lme_61 - .Lm_61
	.long .LDIFF_SYM2943
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde81_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Position"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_set_Position_int"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Position"
	.quad .Lm_62
	.quad .Lme_62

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2944=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2944
	.byte 2,119,0,3
	.string "value"

.LDIFF_SYM2945=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2945
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2946=.Lfde82_end - .Lfde82_start
	.long .LDIFF_SYM2946
.Lfde82_start:

	.long 0
	.balign 8
	.quad .Lm_62

.LDIFF_SYM2947=.Lme_62 - .Lm_62
	.long .LDIFF_SYM2947
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde82_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Metadata"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_get_Metadata"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Metadata"
	.quad .Lm_63
	.quad .Lme_63

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2948=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2948
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2949=.Lfde83_end - .Lfde83_start
	.long .LDIFF_SYM2949
.Lfde83_start:

	.long 0
	.balign 8
	.quad .Lm_63

.LDIFF_SYM2950=.Lme_63 - .Lm_63
	.long .LDIFF_SYM2950
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde83_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Metadata"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_set_Metadata_Mono_Cecil_MetadataReader"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Metadata"
	.quad .Lm_64
	.quad .Lme_64

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2951=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2951
	.byte 2,119,0,3
	.string "value"

.LDIFF_SYM2952=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2952
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2953=.Lfde84_end - .Lfde84_start
	.long .LDIFF_SYM2953
.Lfde84_start:

	.long 0
	.balign 8
	.quad .Lm_64

.LDIFF_SYM2954=.Lme_64 - .Lm_64
	.long .LDIFF_SYM2954
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde84_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Variables"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_get_Variables"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Variables"
	.quad .Lm_65
	.quad .Lme_65

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2955=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2955
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2956=.Lfde85_end - .Lfde85_start
	.long .LDIFF_SYM2956
.Lfde85_start:

	.long 0
	.balign 8
	.quad .Lm_65

.LDIFF_SYM2957=.Lme_65 - .Lm_65
	.long .LDIFF_SYM2957
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde85_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Variables"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_set_Variables_Mono_Collections_Generic_Collection_1_Mono_Cecil_Cil_VariableDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Variables"
	.quad .Lm_66
	.quad .Lme_66

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2958=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2958
	.byte 2,119,0,3
	.string "value"

.LDIFF_SYM2959=.LTDIE_199_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2959
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2960=.Lfde86_end - .Lfde86_start
	.long .LDIFF_SYM2960
.Lfde86_start:

	.long 0
	.balign 8
	.quad .Lm_66

.LDIFF_SYM2961=.Lme_66 - .Lm_66
	.long .LDIFF_SYM2961
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde86_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Visitor"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_get_Visitor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:get_Visitor"
	.quad .Lm_67
	.quad .Lme_67

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2962=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2962
	.byte 2,119,0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2963=.Lfde87_end - .Lfde87_start
	.long .LDIFF_SYM2963
.Lfde87_start:

	.long 0
	.balign 8
	.quad .Lm_67

.LDIFF_SYM2964=.Lme_67 - .Lm_67
	.long .LDIFF_SYM2964
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde87_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Visitor"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext_set_Visitor_Mono_Cecil_Rocks_IILVisitor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:set_Visitor"
	.quad .Lm_68
	.quad .Lme_68

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2965=.LTDIE_348_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2965
	.byte 2,119,0,3
	.string "value"

.LDIFF_SYM2966=.LTDIE_346_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2966
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2967=.Lfde88_end - .Lfde88_start
	.long .LDIFF_SYM2967
.Lfde88_start:

	.long 0
	.balign 8
	.quad .Lm_68

.LDIFF_SYM2968=.Lme_68 - .Lm_68
	.long .LDIFF_SYM2968
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde88_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:.ctor"
	.string "Mono_Cecil_Rocks_ILParser_ParseContext__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/ParseContext:.ctor"
	.quad .Lm_69
	.quad .Lme_69

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2969=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2969
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2970=.Lfde89_end - .Lfde89_start
	.long .LDIFF_SYM2970
.Lfde89_start:

	.long 0
	.balign 8
	.quad .Lm_69

.LDIFF_SYM2971=.Lme_69 - .Lm_69
	.long .LDIFF_SYM2971
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde89_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/<>c__DisplayClass1_0:.ctor"
	.string "Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/<>c__DisplayClass1_0:.ctor"
	.quad .Lm_6a
	.quad .Lme_6a

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2972=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2972
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2973=.Lfde90_end - .Lfde90_start
	.long .LDIFF_SYM2973
.Lfde90_start:

	.long 0
	.balign 8
	.quad .Lm_6a

.LDIFF_SYM2974=.Lme_6a - .Lm_6a
	.long .LDIFF_SYM2974
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde90_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/<>c__DisplayClass1_0:<Parse>b__0"
	.string "Mono_Cecil_Rocks_ILParser__c__DisplayClass1_0__Parseb__0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/<>c__DisplayClass1_0:<Parse>b__0"
	.quad .Lm_6b
	.quad .Lme_6b

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2975=.LTDIE_347_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2975
	.byte 2,119,0,3
	.string "m"

.LDIFF_SYM2976=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2976
	.byte 2,119,8,3
	.string "_"

.LDIFF_SYM2977=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2977
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2978=.Lfde91_end - .Lfde91_start
	.long .LDIFF_SYM2978
.Lfde91_start:

	.long 0
	.balign 8
	.quad .Lm_6b

.LDIFF_SYM2979=.Lme_6b - .Lm_6b
	.long .LDIFF_SYM2979
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde91_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/<>c:.cctor"
	.string "Mono_Cecil_Rocks_ILParser__c__cctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/<>c:.cctor"
	.quad .Lm_6c
	.quad .Lme_6c

	.byte 2,118,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2980=.Lfde92_end - .Lfde92_start
	.long .LDIFF_SYM2980
.Lfde92_start:

	.long 0
	.balign 8
	.quad .Lm_6c

.LDIFF_SYM2981=.Lme_6c - .Lm_6c
	.long .LDIFF_SYM2981
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde92_end:

.section ".debug_info"
.subsection 0
.LTDIE_379:

	.byte 5
	.string "_<>c"

	.byte 16,16
.LDIFF_SYM2982=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2982
	.byte 2,35,0,0,7
	.string "_<>c"

.LDIFF_SYM2983=.LTDIE_379 - .Ldebug_info_start
	.long .LDIFF_SYM2983
.LTDIE_379_POINTER:

	.byte 13
.LDIFF_SYM2984=.LTDIE_379 - .Ldebug_info_start
	.long .LDIFF_SYM2984
.LTDIE_379_REFERENCE:

	.byte 14
.LDIFF_SYM2985=.LTDIE_379 - .Ldebug_info_start
	.long .LDIFF_SYM2985
	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/<>c:.ctor"
	.string "Mono_Cecil_Rocks_ILParser__c__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/<>c:.ctor"
	.quad .Lm_6d
	.quad .Lme_6d

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2986=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2986
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2987=.Lfde93_end - .Lfde93_start
	.long .LDIFF_SYM2987
.Lfde93_start:

	.long 0
	.balign 8
	.quad .Lm_6d

.LDIFF_SYM2988=.Lme_6d - .Lm_6d
	.long .LDIFF_SYM2988
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde93_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ILParser/<>c:<CreateContext>b__3_0"
	.string "Mono_Cecil_Rocks_ILParser__c__CreateContextb__3_0_Mono_Cecil_MethodDefinition_Mono_Cecil_MetadataReader"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ILParser/<>c:<CreateContext>b__3_0"
	.quad .Lm_6e
	.quad .Lme_6e

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM2989=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2989
	.byte 0,3
	.string "_"

.LDIFF_SYM2990=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM2990
	.byte 0,3
	.string "reader"

.LDIFF_SYM2991=.LTDIE_88_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2991
	.byte 2,119,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM2992=.Lfde94_end - .Lfde94_start
	.long .LDIFF_SYM2992
.Lfde94_start:

	.long 0
	.balign 8
	.quad .Lm_6e

.LDIFF_SYM2993=.Lme_6e - .Lm_6e
	.long .LDIFF_SYM2993
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde94_end:

.section ".debug_info"
.subsection 0
.LTDIE_381:

	.byte 5
	.string "System_Func`2"

	.byte 128,1,16
.LDIFF_SYM2994=.LTDIE_35 - .Ldebug_info_start
	.long .LDIFF_SYM2994
	.byte 2,35,0,0,7
	.string "System_Func`2"

.LDIFF_SYM2995=.LTDIE_381 - .Ldebug_info_start
	.long .LDIFF_SYM2995
.LTDIE_381_POINTER:

	.byte 13
.LDIFF_SYM2996=.LTDIE_381 - .Ldebug_info_start
	.long .LDIFF_SYM2996
.LTDIE_381_REFERENCE:

	.byte 14
.LDIFF_SYM2997=.LTDIE_381 - .Ldebug_info_start
	.long .LDIFF_SYM2997
.LTDIE_380:

	.byte 5
	.string "_<>c__DisplayClass0_0"

	.byte 24,16
.LDIFF_SYM2998=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM2998
	.byte 2,35,0,6
	.string "f"

.LDIFF_SYM2999=.LTDIE_381_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM2999
	.byte 2,35,16,0,7
	.string "_<>c__DisplayClass0_0"

.LDIFF_SYM3000=.LTDIE_380 - .Ldebug_info_start
	.long .LDIFF_SYM3000
.LTDIE_380_POINTER:

	.byte 13
.LDIFF_SYM3001=.LTDIE_380 - .Ldebug_info_start
	.long .LDIFF_SYM3001
.LTDIE_380_REFERENCE:

	.byte 14
.LDIFF_SYM3002=.LTDIE_380 - .Ldebug_info_start
	.long .LDIFF_SYM3002
	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c__DisplayClass0_0:.ctor"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c__DisplayClass0_0:.ctor"
	.quad .Lm_6f
	.quad .Lme_6f

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3003=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3003
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3004=.Lfde95_end - .Lfde95_start
	.long .LDIFF_SYM3004
.Lfde95_start:

	.long 0
	.balign 8
	.quad .Lm_6f

.LDIFF_SYM3005=.Lme_6f - .Lm_6f
	.long .LDIFF_SYM3005
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde95_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c__DisplayClass0_0:<GetAllTypes>b__1"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks__c__DisplayClass0_0__GetAllTypesb__1_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c__DisplayClass0_0:<GetAllTypes>b__1"
	.quad .Lm_70
	.quad .Lme_70

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3006=.LTDIE_380_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3006
	.byte 2,119,8,3
	.string "type"

.LDIFF_SYM3007=.LTDIE_318_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3007
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3008=.Lfde96_end - .Lfde96_start
	.long .LDIFF_SYM3008
.Lfde96_start:

	.long 0
	.balign 8
	.quad .Lm_70

.LDIFF_SYM3009=.Lme_70 - .Lm_70
	.long .LDIFF_SYM3009
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde96_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:.cctor"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks__c__cctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:.cctor"
	.quad .Lm_71
	.quad .Lme_71

	.byte 2,118,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3010=.Lfde97_end - .Lfde97_start
	.long .LDIFF_SYM3010
.Lfde97_start:

	.long 0
	.balign 8
	.quad .Lm_71

.LDIFF_SYM3011=.Lme_71 - .Lm_71
	.long .LDIFF_SYM3011
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde97_end:

.section ".debug_info"
.subsection 0
.LTDIE_382:

	.byte 5
	.string "_<>c"

	.byte 16,16
.LDIFF_SYM3012=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM3012
	.byte 2,35,0,0,7
	.string "_<>c"

.LDIFF_SYM3013=.LTDIE_382 - .Ldebug_info_start
	.long .LDIFF_SYM3013
.LTDIE_382_POINTER:

	.byte 13
.LDIFF_SYM3014=.LTDIE_382 - .Ldebug_info_start
	.long .LDIFF_SYM3014
.LTDIE_382_REFERENCE:

	.byte 14
.LDIFF_SYM3015=.LTDIE_382 - .Ldebug_info_start
	.long .LDIFF_SYM3015
	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:.ctor"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks__c__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:.ctor"
	.quad .Lm_72
	.quad .Lme_72

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3016=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3016
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3017=.Lfde98_end - .Lfde98_start
	.long .LDIFF_SYM3017
.Lfde98_start:

	.long 0
	.balign 8
	.quad .Lm_72

.LDIFF_SYM3018=.Lme_72 - .Lm_72
	.long .LDIFF_SYM3018
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde98_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:<GetAllTypes>b__0_0"
	.string "Mono_Cecil_Rocks_ModuleDefinitionRocks__c__GetAllTypesb__0_0_System_Func_2_Mono_Cecil_TypeDefinition_System_Collections_Generic_IEnumerable_1_Mono_Cecil_TypeDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.ModuleDefinitionRocks/<>c:<GetAllTypes>b__0_0"
	.quad .Lm_73
	.quad .Lme_73

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3019=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3019
	.byte 0,3
	.string "f"

.LDIFF_SYM3020=.LTDIE_381_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3020
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3021=.Lfde99_end - .Lfde99_start
	.long .LDIFF_SYM3021
.Lfde99_start:

	.long 0
	.balign 8
	.quad .Lm_73

.LDIFF_SYM3022=.Lme_73 - .Lm_73
	.long .LDIFF_SYM3022
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde99_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:.cctor"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks__c__cctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:.cctor"
	.quad .Lm_74
	.quad .Lme_74

	.byte 2,118,16,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3023=.Lfde100_end - .Lfde100_start
	.long .LDIFF_SYM3023
.Lfde100_start:

	.long 0
	.balign 8
	.quad .Lm_74

.LDIFF_SYM3024=.Lme_74 - .Lm_74
	.long .LDIFF_SYM3024
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde100_end:

.section ".debug_info"
.subsection 0
.LTDIE_383:

	.byte 5
	.string "_<>c"

	.byte 16,16
.LDIFF_SYM3025=.LTDIE_1 - .Ldebug_info_start
	.long .LDIFF_SYM3025
	.byte 2,35,0,0,7
	.string "_<>c"

.LDIFF_SYM3026=.LTDIE_383 - .Ldebug_info_start
	.long .LDIFF_SYM3026
.LTDIE_383_POINTER:

	.byte 13
.LDIFF_SYM3027=.LTDIE_383 - .Ldebug_info_start
	.long .LDIFF_SYM3027
.LTDIE_383_REFERENCE:

	.byte 14
.LDIFF_SYM3028=.LTDIE_383 - .Ldebug_info_start
	.long .LDIFF_SYM3028
	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:.ctor"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks__c__ctor"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:.ctor"
	.quad .Lm_75
	.quad .Lme_75

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3029=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3029
	.byte 0,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3030=.Lfde101_end - .Lfde101_start
	.long .LDIFF_SYM3030
.Lfde101_start:

	.long 0
	.balign 8
	.quad .Lm_75

.LDIFF_SYM3031=.Lme_75 - .Lm_75
	.long .LDIFF_SYM3031
	.long 0
	.byte 68,14,16,10,68,12,7,8,65,11
	.balign 8
.Lfde101_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetConstructors>b__0_0"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetConstructorsb__0_0_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetConstructors>b__0_0"
	.quad .Lm_76
	.quad .Lme_76

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3032=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3032
	.byte 0,3
	.string "method"

.LDIFF_SYM3033=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3033
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3034=.Lfde102_end - .Lfde102_start
	.long .LDIFF_SYM3034
.Lfde102_start:

	.long 0
	.balign 8
	.quad .Lm_76

.LDIFF_SYM3035=.Lme_76 - .Lm_76
	.long .LDIFF_SYM3035
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde102_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetStaticConstructor>b__1_0"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetStaticConstructorb__1_0_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetStaticConstructor>b__1_0"
	.quad .Lm_77
	.quad .Lme_77

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3036=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3036
	.byte 0,3
	.string "ctor"

.LDIFF_SYM3037=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3037
	.byte 1,95,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3038=.Lfde103_end - .Lfde103_start
	.long .LDIFF_SYM3038
.Lfde103_start:

	.long 0
	.balign 8
	.quad .Lm_77

.LDIFF_SYM3039=.Lme_77 - .Lm_77
	.long .LDIFF_SYM3039
	.long 0
	.byte 68,14,32,68,143,4,10,68,8,15,68,12,7,8,65,11
	.balign 8
.Lfde103_end:

.section ".debug_info"
.subsection 0

	.byte 2
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetMethods>b__2_0"
	.string "Mono_Cecil_Rocks_TypeDefinitionRocks__c__GetMethodsb__2_0_Mono_Cecil_MethodDefinition"

	.byte 0,0
	.string "Mono.Cecil.Rocks.TypeDefinitionRocks/<>c:<GetMethods>b__2_0"
	.quad .Lm_78
	.quad .Lme_78

	.byte 2,118,16,3
	.string "this"

.LDIFF_SYM3040=.LDIE_I4 - .Ldebug_info_start
	.long .LDIFF_SYM3040
	.byte 0,3
	.string "method"

.LDIFF_SYM3041=.LTDIE_179_REFERENCE - .Ldebug_info_start
	.long .LDIFF_SYM3041
	.byte 2,119,8,0

.section ".debug_frame"
.subsection 0

.LDIFF_SYM3042=.Lfde104_end - .Lfde104_start
	.long .LDIFF_SYM3042
.Lfde104_start:

	.long 0
	.balign 8
	.quad .Lm_78

.LDIFF_SYM3043=.Lme_78 - .Lm_78
	.long .LDIFF_SYM3043
	.long 0
	.byte 68,14,32,10,68,12,7,8,65,11
	.balign 8
.Lfde104_end:

.section ".debug_info"
.subsection 0

	.byte 0
.Ldebug_info_end:
.section ".debug_line"
.subsection 0
.Ldebug_line_section_start:
.Ldebug_line_start:

	.long .Ldebug_line_end - . -4
	.hword 2
	.long .Ldebug_line_header_end - . -4
	.byte 1,1,251,14,13,0,1,1,1,1,0,0,0,1,0,0,1
.section ".debug_line"
.subsection 0

	.byte 0
	.string "<unknown>"

	.byte 0,0,0,0
.Ldebug_line_header_end:

	.byte 0,1,1
.Ldebug_line_end:
.text 1
	.balign 8
mem_end:

.section	.note.GNU-stack,"",@progbits
