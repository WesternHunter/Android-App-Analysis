# 可信执行环境(TEE)函数调用分析工具

### Java code
    修改config.ini中相关参数，按顺序运行即可进行分析
    1. 1反编译.py： 反编译apk文件
    2. 2检测Java层.py: 检测smali文件中的TEE函数
    3. 3统计Java层结果.py: 将2中结果进行统计
    4. all-keywords.csv: TEE相关函数关键词列表
    5. config.ini: 配置文件
### Native code
    修改config.ini中相关参数，通过ida和idc脚本分析.so和.a文件，再进行函数比对
    1. conifg.ini: 配置文件
    2. ida-a.py: 在反编译完成后的文件中找到.a文件，用[ida(反编译工具)]进行反编译，并用idc脚本提取出该.a文件用到哪些函数，写到函数列表当中
    3. ida-so.py: 在反编译完成后的文件中找到.so文件，用[ida(反编译工具)]进行反编译，并用idc脚本提取出该.so文件用到哪些函数，写到函数列表当中
        [注意：自行修改需要保留的名字  修改第2个和第3个文件中部分参数，93-96行，100-120行（临时文件位置）]
    4. TEE-APIs-List.txt: 特殊的TEE函数列表
    5. TEEtag_direct.py: 用ida-so.py得到的函数列表和[TEE-APIs-List.txt]进行比对，看哪些函数列表当中有这个列表当中的函数
    6. TEEtag_special.py: 调用特殊TEE，用ida-so.py得到的函数列表和[Trusty-API-List.txt]进行比对，看哪些函数列表当中有这个列表当中的函数 
    7. Trusty-API-List: Trusty专有的TEE函数列表
### DATA 原始数据链接
    1.恶意软件.rar        
    2.普通软件.rar
### Key_list 关键词数据
    
### tool
    1.ida64 
    2.apktool