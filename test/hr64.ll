; ModuleID = 'MyModule'
source_filename = "MyModule"

@0 = private unnamed_addr constant [32 x i8] c"fmsub.d ft6, ft6, ft4, ft7, rmm\00", align 1
@1 = private unnamed_addr constant [32 x i8] c"fmsub.d ft6, ft6, ft4, ft7, rmm\00", align 1
@2 = private unnamed_addr constant [32 x i8] c"fmsub.d ft6, ft6, ft4, ft7, rmm\00", align 1

define void @myFunction() {
entry:
  call void @llvm.dbg.declare(ptr @0)
  call void @llvm.dbg.declare(ptr @1)
  call void @llvm.dbg.declare(ptr @2)
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #0

attributes #0 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
