package com.kyhsgeekcode.disassembler;

public class Symbol {
    boolean is64;
    long st_name;
    long st_value;
    long st_size;
    short st_info;
    short st_other;
    short st_shndx;
    String name = "";
    String demangled = "";
    Bind bind;
    Type type;

    public void analyze() {
        bind = Bind.values()[st_info >> 4];
        type = Type.values()[st_info & 0xf];
        demangled = ELFUtil.Demangle(name);
        if ("".equals(demangled) || demangled == null)
            demangled = name;
        return;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append(" at ").append(Long.toHexString(st_value))
                .append(" with size ").append(st_size).append(" binding=")
                .append(bind).append("&type=").append(type)
                .append(" at section #").append(st_shndx);

        return sb.toString();
    }
	/*           #define STB_LOCAL  0
	 #define STB_GLOBAL 1
	 #define STB_WEAK   2

	 #define STT_NOTYPE  0
	 #define STT_OBJECT  1
	 #define STT_FUNC    2
	 #define STT_SECTION 3
	 #define STT_FILE    4
	 #define STT_COMMON  5
	 #define STT_TLS     6       
	 Oh. I Think I get it. `#define ELF_ST_BIND(x)    ((x) >> 4)` `#define ELF_ST_TYPE(x)    (((unsigned int) x) & 0xf)` that means that if `st_info == 34` then it means `STB_WEAK` **and** `STT_FUNC` because `34 >> 4 == 2` and `34 & 0xff == 2`. Is that right?


     https://stackoverflow.com/q/48181509/8614565*/

    enum Bind {
        STB_LOCAL,
        STB_GLOBAL,
        STB_WEAK
    }

    enum Type {
        STT_NOTYPE,
        STT_OBJECT,
        STT_FUNC,
        STT_SECTION,
        STT_FILE,
        STT_COMMON
    }

}
