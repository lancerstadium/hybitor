# 编译器和编译选项
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude -lcapstone

# 文件夹目录
 
DEBUG_DIR = build/debug

# 源文件和目标文件
SRC = src/main.cpp
HEADERS = include/cliparser/*.hpp
OBJ = build/debug/main.o

# 目标可执行文件
TARGET = build/debug/hybitor

# 构建规则
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ)

$(OBJ): $(SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o $(OBJ)

# 清理构建文件
clean:
	rm -f $(OBJ) $(TARGET)
