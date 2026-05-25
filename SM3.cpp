#include <iostream>     //   更新计划： 目前想着使用类继承重构代码，但是目前发现原来的类封装时将读取文件，端序转换和进行哈希值计算合到一个函数里面，目前打算是将读取文件，端序转换函数里面有关SHA-256的语句删除，同时在sha256和sm3上重新写两个一样的函数，调用父类的同一个函数。或者说有什么别的更好的方法。然后搞完了这些，还要接着写关于安全方面的代码，避免时序攻击和内存攻击
#include <fstream>      //为了在新分支上commit代码，稍微修改，占位记录
#include <string>      
#include <vector>       
#include <cstdint>      
#include <iomanip>      
#include <cstring>
class Hash_run{
    private:
	//该函数实现转换端序的作用，已经快被ai气死了。没有将小端序转化为大端序的时候，我发现相同的输入会有不同的输出，>
	void bytes_to_words_32(const uint8_t block[64], uint32_t words[16]) {
            for (int i = 0; i < 16; i++) {
                words[i] = ((uint32_t)block[i * 4] << 24) |
                    ((uint32_t)block[i * 4 + 1] << 16) |
                    ((uint32_t)block[i * 4 + 2] << 8) |
                    ((uint32_t)block[i * 4 + 3]);
            }
        }
	inline uint32_t rotr(uint32_t x, int n) {      //该函数实现右循环移位，下列函数为了实现SHA-256算法中的各种位运>
            return (x >> n) | (x << (32 - n));
        }
	void the_last(uint64_t total_bits, uint32_t H[8], uint32_t W[64], const uint32_t K[64]) {//该函数实现当文件刚[>
            uint8_t J[64] = { 0x80 };
            for (int i = 0; i < 8; i++) {
                J[56 + i] = (total_bits >> (56 - 8 * i)) & 0xFF;
            }
//            uint32_t words[16];
//            bytes_to_words_32(J, words);//下面有三个语句被我标记//。一开始代码不是这样的，原来代码是将原来的数组强制转>
//            expand_words(words, W);
//            compress(H, W, K);这里原来是专门设计给SHA－256算法的添加最后一个数据块的代码，现在为了写成类的形式，增强通用性，这里的代码被注释，仅仅作为留档
        }
	void process_file(const std::string& filepath, uint32_t H[8], uint32_t W[64], const uint32_t K[64]) {//该函数实现对文件计算哈希值，同时通过流式读取降低内存占用
            std::ifstream file(filepath, std::ios::binary);
            if (!file) {
                throw std::runtime_error("无法打开文件: " + filepath);
                return;
            }
            char buffer[4096];
            uint32_t words[16];
            uint64_t total_bits = 0;
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                size_t bytes_read = file.gcount();
                total_bits += bytes_read * 8;
                if (bytes_read == 4096) {
                    for (int k = 0; k < 4096; k += 64) {
                        bytes_to_words_32(reinterpret_cast<const uint8_t*>(buffer + k), words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                  }//只有这里往上的代码，才会一直参与while循环，当不满足bytes_read==4096时，将会执行下面代码，执行完之后会跳出循环
                else if (bytes_read % 64 == 0 && bytes_read != 4096) {
                    for (int k = 0; k < bytes_read; k += 64) {
                        bytes_to_words_32(reinterpret_cast<const uint8_t*>(buffer + k), words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                    the_last(total_bits, H, W, K);
                }
                else {
                    std::vector<uint8_t> Last;
                    Last.insert(Last.end(), buffer, buffer + bytes_read);
                    Last.push_back(0x80);
                    while ((Last.size() * 8) % 512 != 448) {
                        Last.push_back(0x00);
                    }
                    for (int i = 7; i >= 0; --i) {
                        Last.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
                    }
                    for (size_t i = 0; i < Last.size(); i += 64) {
                        bytes_to_words_32(Last.data() + i, words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                }
            }
            if (total_bits % 4096 == 0) {//文件恰好为4kb的整数倍的情况时，进行的选择
                the_last(total_bits, H, W, K);                                                                                                                                                                                                            }
        }
};  
class SHA_256{
    private:
        uint32_t W[64];
        uint32_t words[16];
        static const uint32_t K[64];
        uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
            return (x & y) ^ (~x & z);
        }
        inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        inline uint32_t Sigma0(uint32_t x) {
            return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
        }
        inline uint32_t Sigma1(uint32_t x) {
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
        }
        inline uint32_t sigma0(uint32_t x) {
        }
        inline uint32_t sigma1(uint32_t x) {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        }
        void expand_words(const uint32_t words[16], uint32_t W[64]) {
            for (int i = 0; i < 16; ++i)
            {
                W[i] = words[i];
            }
            for (int i = 16; i < 64; ++i)
            {
                W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
            }
        }
        void compress(uint32_t H[8], uint32_t W[64], const uint32_t K[64]) {//压缩函数
            uint32_t a = H[0];
            uint32_t b = H[1];
            uint32_t c = H[2];
            uint32_t d = H[3];
            uint32_t e = H[4];
            uint32_t f = H[5];
            uint32_t g = H[6];
            uint32_t h = H[7];
            for (int t = 0; t < 64; t++) {
                // T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
                uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
                // T2 = Σ0(a) + Maj(a,b,c)
                uint32_t T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }
        void process_file(const std::string& filepath, uint32_t H[8], uint32_t W[64], const uint32_t K[64]) {//该函数实现对文件计算哈希值，同时通过流式读取降低内存占用
            std::ifstream file(filepath, std::ios::binary);
            if (!file) {
                throw std::runtime_error("无法打开文件: " + filepath);
                return;
            }
            char buffer[4096];
            uint32_t words[16];
            uint64_t total_bits = 0;
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                size_t bytes_read = file.gcount();
                total_bits += bytes_read * 8;
                if (bytes_read == 4096) {
                    for (int k = 0; k < 4096; k += 64) {
                        bytes_to_words_32(reinterpret_cast<const uint8_t*>(buffer + k), words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                  }//只有这里往上的代码，才会一直参与while循环，当不满足bytes_read==4096时，将会执行下面代码，执行完之后会跳出循环
                else if (bytes_read % 64 == 0 && bytes_read != 4096) {
                    for (int k = 0; k < bytes_read; k += 64) {
                        bytes_to_words_32(reinterpret_cast<const uint8_t*>(buffer + k), words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                    the_last(total_bits, H, W, K);
                }
                else {
                    std::vector<uint8_t> Last;
                    Last.insert(Last.end(), buffer, buffer + bytes_read);
                    Last.push_back(0x80);
                    while ((Last.size() * 8) % 512 != 448) {
                        Last.push_back(0x00);
                    }
                    for (int i = 7; i >= 0; --i) {
                        Last.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
                    }
                    for (size_t i = 0; i < Last.size(); i += 64) {
                        bytes_to_words_32(Last.data() + i, words);//
                        expand_words(words, W);
                        compress(H, W, K);
                    }
                }
            }
            if (total_bits % 4096 == 0) {//文件恰好为4kb的整数倍的情况时，进行的选择
                the_last(total_bits, H, W, K);
            }
        }
    public:
        void str_run(std::string input){//该函数实现求字符串的哈希值
            uint64_t input_size = input.size();
            uint64_t total_bits = input_size * 8;
            input += static_cast<char>(0x80);
            while ((input.size() * 8) % 512 != 448) {
                input += static_cast<char>(0x00);
            }
            for (int i = 7; i >= 0; --i) {
                input += static_cast<char>((total_bits >> (i * 8)) & 0xFF);//实现长度的端序转换，再接到后面
            }
            if (input.size() * 8 > 512) {     //如果经过处理之后的数据大于512比特，那么需要进行分块
                for (size_t i = 0; i < input.size(); i += 64) {
                    bytes_to_words_32(reinterpret_cast<const uint8_t*>(&input[i]), words);
                    expand_words(words, W);
                    compress(H, W, K);
                }
            }
            else {
                bytes_to_words_32(reinterpret_cast<const uint8_t*>(&input[0]), words);
                expand_words(words, W);
                compress(H, W, K);
            }
        }
        int file_run(std::string filepath){//该函数实现求文件的哈希值，需要输入文件地址
            try {
		process_file(filepath, H, W, K);
		return 0;
            }
            catch (const std::exception& e) {
                std::cerr << "错误：" << e.what() << std::endl;
		return 1;
            }
        }
        void print_hash() {//输出哈希值
            std::cout << "SHA-256: ";
            for (int i = 0; i < 8; i++) {
                std::cout << std::hex << std::setw(8) << std::setfill('0') << H[i];
            }
            std::cout << std::endl;
        }
};
const uint32_t SHA_256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
int main() {
    int result=0;
    int n = 0;
    std::cout << "输入1进行文件哈希计算，输入0进行字符串哈希计算：" << std::endl << "如果要计算文件哈希值则输入文件地址，如果要计算字符串哈希值则直接输入字符串" << std::endl << "请输入：";
    std::cin >> n;
    std::cin.ignore(); // 忽略换行符    
    std::string input;
    std::string filepath;
    SHA_256 sha256;
    if (n == 1)
    {
        std::cout << "请输入文件路径: ";
        std::getline(std::cin, filepath);
        result=sha256.file_run(filepath);
    }
    else if (n == 0) {
        std::cout << "请输入字符串: ";
        std::getline(std::cin, input);
        sha256.str_run(input);
    }
    else {
        std::cout << "输入错误，请重新运行程序！" << std::endl;
    }
    if(result!=0)
        return result;
    sha256.print_hash();
    return 0;
}
