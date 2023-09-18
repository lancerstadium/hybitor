/// \file binaryfile.h
/// \brief 二进制文件操作的定义文件

#include <string>

#include "elfio/elfio.hpp"


#define LOAD_BINARY_FAILED 1   // 读取二进制文件失败
#define LOAD_BINARY_SUCCESS 0   // 读取二进制文件成功


using std::cout;
using std::string;
using std::endl;
using std::cerr;
using namespace ELFIO;

/// @brief 二进制文件对象
class binaryfile {

public:
    string bf_name;     // 二进制文件名
    elfio *bf_reader;    // 二进制阅读器对象

    binaryfile(string filename) : bf_name(filename), bf_reader(nullptr) {};
    ~binaryfile() {};


    /// @brief 加载二进制文件
    /// @return 是否加载成功
    int load_binary_file()
    {
        // 打开 ELF 文件
        if (this->bf_reader->load(bf_name) == false) {
            cerr << "Unable to load ELF file" << endl;
            return LOAD_BINARY_FAILED;
        }

        return LOAD_BINARY_SUCCESS;
    }

    /// @brief 打印二进制文件 sections 信息
    void print_sections_info()
    {
        Elf_Half sec_num = this->bf_reader->sections.size();
        cout << "Number of sections: " << sec_num << endl; 
        for ( int i = 0; i < sec_num; ++i ) { 
            const section* psec = this->bf_reader->sections[i];       
            std::cout << "  [" << i << "] " 
                    << psec->get_name()                   
                    << "\t" 
                    << psec->get_size()                   
                    << std::endl; 
            // 访问 section 的数据
            const char* p = this->bf_reader->sections[i]->get_data();  
        } 
    }

    /// @brief 打印二进制文件 segments 信息
    void print_segments_info()
    {
        Elf_Half seg_num = this->bf_reader->segments.size();          
        std::cout << "Number of segments: " << seg_num << std::endl; for ( int i = 0; i < seg_num; ++i ) { 
            const segment* pseg = this->bf_reader->segments[i];       
            std::cout << "  [" << i << "] 0x" << std::hex 
                    << pseg->get_flags()                  
                    << "\t0x" 
                    << pseg->get_virtual_address()        
                    << "\t0x" 
                    << pseg->get_file_size()              
                    << "\t0x" 
                    << pseg->get_memory_size()            
                    << std::endl; 
            // 访问 segments 的数据
            const char* p = this->bf_reader->segments[i]->get_data(); 
        } 
    }


};