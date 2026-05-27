#include <iostream>     //   更新计划： 目前想着使用类继承重构代码，但是目前发现原来的类封装时将读取文件，端序转换和进行哈希值计算合到一个函数里面，目前打算是将读取文件，端序转换函数里面有关SHA-256的语句删除，同时在sha256和sm3上重新写两个一样的函数，调用父类的同一个函数。或者说有什么别的更好的方法。然后搞完了这些，还要接着写关于安全方面的代码，避免时序攻击和内存攻击
#include <fstream>      //我发现虚函数是个好东西
#include <string>      
#include <vector>       
#include <cstdint>      
#include <iomanip>      
#include <cstring>
class Hash_run{
    protected:
        uint32_t H[8];
    private:
        uint32_t W[64];
        //virtual const uint32_t* get_K() const = 0;//因为K是static数组，所以使用虚函数返回它的地址
        //const uint32_t* K = get_K();这个不可以在构造函数或者初始化使用，只能在普通函数里面调用，否则会出现严重错误。
        virtual void process_block(const uint8_t block[64])=0;//为了使用虚函数，但是sha256和sm3的许多代码，函数不同，所以设置一个这样的虚函数将整个计算过程封起来，这样就可以复用文件读取，输出等代码了
        void the_last(uint64_t total_bits) {//该函数实现当文件刚好为512比特的整数倍时，手动创建最后一个数据块参与哈希值运算
            uint8_t J[64] = { 0x80 };
            for (int i = 0; i < 8; i++) {
                J[56 + i] = (total_bits >> (56 - 8 * i)) & 0xFF;
            }
            process_block(J);
        }
        void process_file(const std::string& filepath) {//该函数实现对文件计算哈希值，同时通过流式读取降低内存占用
            //const uint32_t* K = get_K();
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
                        process_block(reinterpret_cast<uint8_t*>(buffer+k));
                    }
                }//只有这里往上的代码，才会一直参与while循环，当不满足bytes_read==4096时，将会执行下面代码，执行完之后会跳出循环
                else if (bytes_read % 64 == 0 && bytes_read != 4096) {
                    for (int k = 0; k < bytes_read; k += 64) {
                        process_block(reinterpret_cast<uint8_t*>(buffer+k));
                    }
                    the_last(total_bits);
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
                        process_block(Last.data()+i);
                    }
                }
            }
            if (total_bits % 4096 == 0) {//文件恰好为4kb的整数倍的情况时，进行的选择
                the_last(total_bits);
            }
        }
    public:
    void str_run(std::string input){//该函数实现求字符串的哈希值
        uint64_t total_bits = input.size() * 8;
        input += static_cast<char>(0x80);
        while ((input.size() * 8) % 512 != 448) {
            input += static_cast<char>(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            input += static_cast<char>((total_bits >> (i * 8)) & 0xFF);//实现长度的端序转换，再接到后面
        }
        if (input.size() * 8 > 512) {     //如果经过处理之后的数据大于512比特，那么需要进行分块
            for (size_t i = 0; i < input.size(); i += 64) {
                process_block(reinterpret_cast<uint8_t*>(input.data()+i));
            }
        }
        else {
            process_block(reinterpret_cast<uint8_t*>(input.data()));
        }
    }
    int file_run(std::string filepath){//该函数实现求文件的哈希值，需要输入文件地址
        try {
	        process_file(filepath);
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
    virtual ~Hash_run() = default;
};  
class SHA_256:public Hash_run{
    private:
        uint32_t W[64];
        uint32_t words[16];
        static const uint32_t K[64];
        //const uint32_t* get_K()  {//const override
        //    return K;  // 返回自己的 static const 数组
        //}
        inline uint32_t rotr(uint32_t x, int n) {      //该函数实现右循环移位，下列函数为了实现SHA-256算法中的各种位运算而定义的辅助函数
            return (x >> n) | (x << (32 - n));
        }
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
            return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        }
        inline uint32_t sigma1(uint32_t x) {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        } 
        void expand_words (const uint32_t words[16], uint32_t W[64]) {
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
        //该函数实现转换端序的作用，已经快被ai气死了。没有将小端序转化为大端序的时候，我发现相同的输入会有不同的输出，十分地奇怪，也琢磨不明白。
        void bytes_to_words_32(const uint8_t block[64], uint32_t words[16]) {
            for (int i = 0; i < 16; i++) {
                words[i] = ((uint32_t)block[i * 4] << 24) |
                    ((uint32_t)block[i * 4 + 1] << 16) |
                    ((uint32_t)block[i * 4 + 2] << 8) |
                    ((uint32_t)block[i * 4 + 3]);
            }
        }
        void process_block(const uint8_t block[64]) override{
            bytes_to_words_32(block, words);
            expand_words(words, W);
            compress(H, W, K);
        }
    public:
        SHA_256(){
            H[0]=0x6a09e667;
            H[1]=0xbb67ae85;
            H[2]=0x3c6ef372;
            H[3]=0xa54ff53a;
            H[4]=0x510e527f;
            H[5]=0x9b05688c;
            H[6]=0x1f83d9ab;
            H[7]=0x5be0cd19;
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
class SM3:public Hash_run{
    private:
        inline uint32_t rotl(uint32_t x, int n) {      //该函数实现左循环移位，下列函数为了实现SM3算法中的各种位运算而定义的辅助函数
            return (x << n) | (x >> (32 - n));
        }
        void bytes_to_words_32(const uint8_t block[64], uint32_t words[16]) {//该函数实现端序转换的同时将输入的512比特分为16个块
            for (int i = 0; i < 16; i++) {
                words[i] = ((uint32_t)block[i * 4] << 24) |
                    ((uint32_t)block[i * 4 + 1] << 16) |
                    ((uint32_t)block[i * 4 + 2] << 8) |
                    ((uint32_t)block[i * 4 + 3]);
            }
        }
        uint32_t P_0(uint32_t x){
            return x^rotl(x,9)^rotl(x,17);
        }
        uint32_t P_1(uint32_t x){
            return x^rotl(x,15)^rotl(x,23);
        }
        void expand_W(uint32_t W[]){
            for(int i=16;i<68;++i)
            {
                W[i]=P_1(W[i-16]^W[i-9]^rotl(W[i-3],15))^rotl(W[i-13],7)^W[i-6];
            }
        }
        void expand_W_prime(uint32_t W_prime[],uint32_t W[]){
            for(int i=0;i<64;++i)
            {
                W_prime[i]=W[i]^W[i+4];
            }
        }
        uint32_t FF_i(int i,uint32_t x,uint32_t y,uint32_t z){
            if(i<=15)
                return x^y^z;
            if(i>15)
                return (x&y)^(x&z)^(y&z);
        }
        uint32_t GG_i(int i,uint32_t x,uint32_t y,uint32_t z){
            if(i<=15)
                return x^y^z;
            if(i>15)
                return (x&y)^(~x&z);
        }
        void compress(uint32_t H[],uint32_t W[],uint32_t W_prime[]){
            for(int i=0;i<64;++i)
            {
                uint32_t T_val = (i < 16) ? 0x79CC4519 : 0x7A879D8A;
                uint32_t SS1=rotl((rotl(H[0],12)+H[4]+rotl(T_val,i)),7);
                uint32_t SS2=SS1^rotl(H[0],12);
                uint32_t TT1=(FF_i(i,H[0],H[1],H[2])+H[3]+SS2+W_prime[i])%0x100000000;
                uint32_t TT2=(GG_i(i,H[4],H[5],H[6])+H[7]+SS1+W[i])%0x100000000;
                H[3]=H[2];
                H[2]=rotl(H[1],9);
                H[1]=H[0];
                H[0]=TT1;
                H[7]=H[6];
                H[6]=rotl(H[5],19);
                H[5]=H[4];
                H[4]=P_0(TT2);
            }
        }
        void process_block(const uint8_t block[64]) override{
            uint32_t W[68];
            uint32_t W_prime[64];
            bytes_to_words_32(block, W);
            expand_W(W);
            expand_W_prime(W_prime,W);
            compress(H,W,W_prime);
        }
    public:
        SM3(){
            H[0]=0x7380166f;
            H[1]=0x4914b2b9;
            H[2]=0x172442d7;
            H[3]=0xda8a0600;
            H[4]=0xa96f30bc;
            H[5]=0x163138aa;
            H[6]=0xe38dee4d;
            H[7]=0xb0fb0e4e;
        }
};
int main() {
    int result=0;
    int n = 0;
    std::cout << "输入1进行文件哈希计算，输入0进行字符串哈希计算：" << std::endl << "如果要计算文件哈希值则输入文件地址，如果要计算字符串哈希值则直接输入字符串" << std::endl << "请输入：";
    std::cin >> n;
    std::cin.ignore(); // 忽略换行符    
    std::string input;
    std::string filepath;
    SM3 sha256;
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