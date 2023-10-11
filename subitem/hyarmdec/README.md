<!--
 * @Author: lancerstadium lancerstadium@163.com
 * @Date: 2023-10-11 14:32:26
 * @LastEditors: lancerstadium lancerstadium@163.com
 * @LastEditTime: 2023-10-11 15:24:57
 * @FilePath: /hybitor_effect/subitem/hyarmdec/README.md
 * @Description: hyarmdec: Arm 解码器介绍
-->

# hyarmdec

- Hybitor's Arm Archtecture Decoder.
- 使用方式：
  - 静态库链接：C/C++
  - 可执行工具：arm64dec-test


## 构建 build

```
meson set build
meson compile -C build
```

## 测试 test

1. 生成静态库文件路径：`./build/libhyarmdec.a`
2. 生成测试执行文件路径：`./build/arm64dec-test`

```
./build/arm64-test 0xd10083ff
```

## 使用示例 example


- 编写`example.cpp`文件：
  
```cpp
#include <cstdint>
#include <iostream>

#include "hyarmdec.h"

int main() {
	uint32_t in = 0xd10083ff;   // sub sp, sp, #32
	hyarmdec::Inst out;
	int n = arm64_decode(&in, 1, &out);
	print_inst(out);
	return 0;
}
```

- 编译，设置库位置：

```
clang++ example.cpp -o example -Lbuild -lhyarmdec
```

- 运行`./example`：

```
output:

sub_imm        X100, X100, X0, imm=32, offset=+32, fimm=0.000000, imm2=(32,0), flags=0b 000 000 00
```
