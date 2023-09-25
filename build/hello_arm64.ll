; ModuleID = 'MyModule'
source_filename = "MyModule"

@0 = private unnamed_addr constant [18 x i8] c"sub sp, sp, #0x20\00", align 1
@1 = private unnamed_addr constant [26 x i8] c"stp x29, x30, [sp, #0x10]\00", align 1
@2 = private unnamed_addr constant [19 x i8] c"add x29, sp, #0x10\00", align 1
@3 = private unnamed_addr constant [11 x i8] c"mov w8, #0\00", align 1
@4 = private unnamed_addr constant [17 x i8] c"str w8, [sp, #8]\00", align 1
@5 = private unnamed_addr constant [21 x i8] c"stur wzr, [x29, #-4]\00", align 1
@6 = private unnamed_addr constant [22 x i8] c"adrp x0, #0x100003000\00", align 1
@7 = private unnamed_addr constant [19 x i8] c"add x0, x0, #0xfa8\00", align 1
@8 = private unnamed_addr constant [16 x i8] c"bl #0x100003f9c\00", align 1
@9 = private unnamed_addr constant [17 x i8] c"ldr w0, [sp, #8]\00", align 1
@10 = private unnamed_addr constant [26 x i8] c"ldp x29, x30, [sp, #0x10]\00", align 1
@11 = private unnamed_addr constant [18 x i8] c"add sp, sp, #0x20\00", align 1
@12 = private unnamed_addr constant [5 x i8] c"ret \00", align 1
@13 = private unnamed_addr constant [23 x i8] c"adrp x16, #0x100004000\00", align 1
@14 = private unnamed_addr constant [15 x i8] c"ldr x16, [x16]\00", align 1
@15 = private unnamed_addr constant [7 x i8] c"br x16\00", align 1
@16 = private unnamed_addr constant [29 x i8] c"ldnp d8, d25, [x11, #-0x140]\00", align 1
@17 = private unnamed_addr constant [7 x i8] c"udf #1\00", align 1
@18 = private unnamed_addr constant [10 x i8] c"udf #0x1c\00", align 1
@19 = private unnamed_addr constant [7 x i8] c"udf #0\00", align 1
@20 = private unnamed_addr constant [10 x i8] c"udf #0x1c\00", align 1
@21 = private unnamed_addr constant [7 x i8] c"udf #0\00", align 1
@22 = private unnamed_addr constant [10 x i8] c"udf #0x1c\00", align 1
@23 = private unnamed_addr constant [7 x i8] c"udf #2\00", align 1
@24 = private unnamed_addr constant [12 x i8] c"udf #0x3f68\00", align 1
@25 = private unnamed_addr constant [10 x i8] c"udf #0x34\00", align 1
@26 = private unnamed_addr constant [10 x i8] c"udf #0x34\00", align 1
@27 = private unnamed_addr constant [12 x i8] c"udf #0x3f9d\00", align 1
@28 = private unnamed_addr constant [7 x i8] c"udf #0\00", align 1
@29 = private unnamed_addr constant [10 x i8] c"udf #0x34\00", align 1
@30 = private unnamed_addr constant [7 x i8] c"udf #3\00", align 1
@31 = private unnamed_addr constant [7 x i8] c"udf #0\00", align 1

define void @myFunction() {
entry:
  call void @llvm.dbg.declare(ptr @0)
  call void @llvm.dbg.declare(ptr @1)
  call void @llvm.dbg.declare(ptr @2)
  call void @llvm.dbg.declare(ptr @3)
  call void @llvm.dbg.declare(ptr @4)
  call void @llvm.dbg.declare(ptr @5)
  call void @llvm.dbg.declare(ptr @6)
  call void @llvm.dbg.declare(ptr @7)
  call void @llvm.dbg.declare(ptr @8)
  call void @llvm.dbg.declare(ptr @9)
  call void @llvm.dbg.declare(ptr @10)
  call void @llvm.dbg.declare(ptr @11)
  call void @llvm.dbg.declare(ptr @12)
  call void @llvm.dbg.declare(ptr @13)
  call void @llvm.dbg.declare(ptr @14)
  call void @llvm.dbg.declare(ptr @15)
  call void @llvm.dbg.declare(ptr @16)
  call void @llvm.dbg.declare(ptr @17)
  call void @llvm.dbg.declare(ptr @18)
  call void @llvm.dbg.declare(ptr @19)
  call void @llvm.dbg.declare(ptr @20)
  call void @llvm.dbg.declare(ptr @21)
  call void @llvm.dbg.declare(ptr @22)
  call void @llvm.dbg.declare(ptr @23)
  call void @llvm.dbg.declare(ptr @24)
  call void @llvm.dbg.declare(ptr @25)
  call void @llvm.dbg.declare(ptr @26)
  call void @llvm.dbg.declare(ptr @27)
  call void @llvm.dbg.declare(ptr @28)
  call void @llvm.dbg.declare(ptr @29)
  call void @llvm.dbg.declare(ptr @30)
  call void @llvm.dbg.declare(ptr @31)
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #0

attributes #0 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
