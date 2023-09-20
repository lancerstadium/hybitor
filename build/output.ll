; ModuleID = 'MyModule'
source_filename = "MyModule"

@0 = private unnamed_addr constant [33 x i8] c"inc dword ptr [rbx + 0x7bfdd100]\00", align 1
@1 = private unnamed_addr constant [38 x i8] c"add dword ptr [rcx - 0x6effbc03], ebp\00", align 1
@2 = private unnamed_addr constant [22 x i8] c"or byte ptr [rax], al\00", align 1
@3 = private unnamed_addr constant [31 x i8] c"adc byte ptr [rdx - 0x18], 0xb\00", align 1
@4 = private unnamed_addr constant [36 x i8] c"add byte ptr [rcx - 0x47e03c41], bh\00", align 1
@5 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@6 = private unnamed_addr constant [36 x i8] c"add byte ptr [rax - 0x6ec16000], dl\00", align 1
@7 = private unnamed_addr constant [20 x i8] c"add eax, 0xe0940000\00", align 1
@8 = private unnamed_addr constant [31 x i8] c"or eax, dword ptr [rax - 0x47]\00", align 1
@9 = private unnamed_addr constant [5 x i8] c"std \00", align 1
@10 = private unnamed_addr constant [16 x i8] c"jnp 0x100003fd4\00", align 1
@11 = private unnamed_addr constant [21 x i8] c"test eax, 0x910083ff\00", align 1
@12 = private unnamed_addr constant [25 x i8] c"rol byte ptr [rbx], 0x5f\00", align 1
@13 = private unnamed_addr constant [23 x i8] c"adc byte ptr [rax], al\00", align 1
@14 = private unnamed_addr constant [35 x i8] c"add byte ptr [rax - 0x6bffdf0], dh\00", align 1
@15 = private unnamed_addr constant [23 x i8] c"add byte ptr [rdx], al\00", align 1
@16 = private unnamed_addr constant [16 x i8] c"push 0x6f6c6c65\00", align 1
@17 = private unnamed_addr constant [13 x i8] c"sub al, 0x20\00", align 1
@18 = private unnamed_addr constant [15 x i8] c"ja 0x100004020\00", align 1
@19 = private unnamed_addr constant [15 x i8] c"jb 0x10000401f\00", align 1
@20 = private unnamed_addr constant [28 x i8] c"and dword ptr fs:[rdx], ecx\00", align 1
@21 = private unnamed_addr constant [25 x i8] c"add dword ptr [rax], eax\00", align 1
@22 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@23 = private unnamed_addr constant [10 x i8] c"sbb al, 0\00", align 1
@24 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@25 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@26 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@27 = private unnamed_addr constant [10 x i8] c"sbb al, 0\00", align 1
@28 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@29 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@30 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@31 = private unnamed_addr constant [10 x i8] c"sbb al, 0\00", align 1
@32 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@33 = private unnamed_addr constant [23 x i8] c"add al, byte ptr [rax]\00", align 1
@34 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@35 = private unnamed_addr constant [16 x i8] c"push 0x3400003f\00", align 1
@36 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@37 = private unnamed_addr constant [29 x i8] c"add byte ptr [rax + rax], dh\00", align 1
@38 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@39 = private unnamed_addr constant [7 x i8] c"popfq \00", align 1
@40 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@41 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1
@42 = private unnamed_addr constant [23 x i8] c"add byte ptr [rax], al\00", align 1

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
  call void @llvm.dbg.declare(ptr @32)
  call void @llvm.dbg.declare(ptr @33)
  call void @llvm.dbg.declare(ptr @34)
  call void @llvm.dbg.declare(ptr @35)
  call void @llvm.dbg.declare(ptr @36)
  call void @llvm.dbg.declare(ptr @37)
  call void @llvm.dbg.declare(ptr @38)
  call void @llvm.dbg.declare(ptr @39)
  call void @llvm.dbg.declare(ptr @40)
  call void @llvm.dbg.declare(ptr @41)
  call void @llvm.dbg.declare(ptr @42)
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #0

attributes #0 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
