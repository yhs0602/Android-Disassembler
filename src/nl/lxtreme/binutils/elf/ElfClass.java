/*
 * BinUtils - access various binary formats from Java
 *
 * (C) Copyright 2016 - JaWi - j.w.janssen@lxtreme.nl
 *
 * Licensed under Apache License v2. 
 */
package nl.lxtreme.binutils.elf;

/**
 * Denotes the class of an ELF object, whether it is using 32- or 64-bits offsets.
 */
public enum ElfClass {
    CLASS_32, CLASS_64;
}