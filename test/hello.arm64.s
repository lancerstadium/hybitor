Section :__text
0x100003f68: sub sp, sp, #0x20
0x100003f6c: stp x29, x30, [sp, #0x10]
0x100003f70: add x29, sp, #0x10
0x100003f74: mov w8, #0
0x100003f78: str w8, [sp, #8]
0x100003f7c: stur wzr, [x29, #-4]
0x100003f80: adrp x0, #0x100003000
0x100003f84: add x0, x0, #0xfa8
0x100003f88: bl #0x100003f9c
0x100003f8c: ldr w0, [sp, #8]
0x100003f90: ldp x29, x30, [sp, #0x10]
0x100003f94: add sp, sp, #0x20
0x100003f98: ret 
Section :__stubs
0x100003f9c: adrp x16, #0x100004000
0x100003fa0: ldr x16, [x16]
0x100003fa4: br x16
Section :__cstring
0x100003fa8: ldnp d8, d25, [x11, #-0x140]
Section :__unwind_info
0x100003fb8: udf #1
0x100003fbc: udf #0x1c
0x100003fc0: udf #0
0x100003fc4: udf #0x1c
0x100003fc8: udf #0
0x100003fcc: udf #0x1c
0x100003fd0: udf #2
0x100003fd4: udf #0x3f68
0x100003fd8: udf #0x34
0x100003fdc: udf #0x34
0x100003fe0: udf #0x3f9d
0x100003fe4: udf #0
0x100003fe8: udf #0x34
0x100003fec: udf #3
Section :__got
0x100004000: udf #0