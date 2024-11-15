# 反编译.so文件是执行ida64 -B D:/apk/test1-111-111\5DE3E0——————D00\lib\arm64-v8a\libmono-btls-shared.so
# ida64 -S -Amyidc1.idc D:/apk/test1-111-111\5DE3E0——————D00\lib\arm64-v8a\libmono-btls-shared.so
import configparser
import os
import shutil
import subprocess
import time


# 遍历第一层文件名（只包含文件夹名）
def find_file_first(root1):
    data = []
    for (path, subdirs, files) in os.walk(root1):
        for name in subdirs:
            file_name = os.path.join(path, name)
            print(file_name)
            data.append(file_name)
        break
    print(len(data))
    return data


# 遍历所有文件名 放到file_list中
def walk_through_dir(root):
    file_list = []
    for (path, subdirs, files) in os.walk(root):
        for name in files:
            file_name = os.path.join(path, name)
            file_list.append(file_name)
    return file_list


# 识别出所有后缀为 .so的文件
def find_so_files(myfiles):
    so_files = []
    for f in myfiles:
        file_type = os.path.splitext(f)[-1]
        if file_type == ".so":
            so_files.append(f)
            print(f)
    return so_files


# 执行 ida64 -B
def execute_so_files(so_ida):
    big_file = []
    for file in so_ida:
        print(file)
        os.chdir("D:/ida/IDA_Pro_v7.0_Portable")
        cmd_str = 'ida64 -B {}'.format(file)
        print(cmd_str)
        subprocess.Popen(cmd_str)

        time.sleep(2)
        filei64 = file.replace('.so', '.i64')
        print(filei64)
        fileasm = file.replace('.so', '.asm')
        print(fileasm)
        i = 0
        while not os.path.exists(filei64):
            print("正在下载！")
            i = i + 1
            # if i == 70:
            if i == 40:
                with open(filei64, 'w+') as f:
                    big_file.append(file)
                with open(fileasm, 'w+') as f:
                    print("空文件生成！！！！！！")
            time.sleep(5)
        print("filei64下载完成！！！！！！")
        while not os.path.exists(fileasm):
            print("正在下载！")
            time.sleep(5)
        print("fileasm下载完成！！！！！！")
    return big_file


# 执行 ida64 -A -Smyidc.idc
def execute_so_files_idc(so_ida):
    zero_file = []
    for file in so_ida:
        filei64 = file.replace('.so', '.i64')
        if os.path.getsize(filei64) == 0:
            zero_file.append(file)
            continue
        print(file)
        os.chdir("D:/ida/IDA_Pro_v7.0_Portable")
        cmd_str = 'ida64 -A -Smyidc1.idc {}'.format(file)
        print(cmd_str)
        # file当前是.so文件 D:/apk/test1-111-111\5DE3E0——————D00\lib\arm64-v8a\libmono-btls-shared.so
        print(file)
        # 45的意思是将E:\apkfile\finish123456788\ANDROID_WEAR\apk个字符删除 得到5DE3E0——————D00\lib\arm64-v8a\libmono-btls-shared.a
        f = file[45:]
        f = f.replace('/', '_')
        f = f.replace('\\', '_')
        f = f[:-3]
        print(f)   # 为了得到没有/和\的文件名：111-111_5DE3E0——————D00_lib_arm64-v8a_libmono-btls-shared
        subprocess.Popen(cmd_str)

        time.sleep(3)

        while not os.path.exists("D:/apk/result/test12.txt"):
            print("正在生成！")
            time.sleep(1)

        cmd_str1 = 'ren test12.txt {}.txt'.format(f)
        print(cmd_str1)
        os.chdir("D:/apk/result")
        print(os.getcwd())
        while True:
            try:
                os.rename(r"D:\apk\result\test12.txt", "D:/apk/result/" + f + ".txt")
                break
            except PermissionError as r:
                print("结果文件还在写入中，请稍等")
                time.sleep(5)
            except FileExistsError as t:
                os.remove("D:/apk/result/test12.txt")
                break
    return zero_file


# 对每个文件夹的so文件进行反编译
def file_so_ida(apk_craw_file):
    j = 1
    lib_files = []
    big_files = []
    zero_files = []
    for root1 in apk_craw_file:
        print(root1)   # D:/apk/test1-111-111\5DD18D4D0AFB7C8428F0AB1BD90EF68AE8AE67F8BC3F00F22758FBA79D805520
        all_files = walk_through_dir(root1)
        # print(len(all_files))
        so_f = find_so_files(all_files)  # D:/apk/test1-111-111\5DE3E095A96BFF5760D2CD9DD48F1FC31E193850AE84EEB17C7E53300B678D00\lib\arm64-v8a\libmono-native.so
        print(len(so_f))
        if len(so_f) != 0:
            lib_files.append(root1)
        file_big = execute_so_files(so_f)
        big_files.append(file_big)
        file_zero = execute_so_files_idc(so_f)
        zero_files.append(file_zero)
        print("第" + str(j) + "个执行完毕")
        j = j + 1
    print("下面是生成空文件的文件")
    print(big_files)
    print("下面是还没有执行脚本的文件，请重新执行idc脚本！！")
    print(zero_files)
    return lib_files


def handle_dir(apk_craw_dir):
    # 首先遍历
    for dir1 in apk_craw_dir:
        dir_lib = dir1 + "/lib"
        print(dir_lib)
        if os.path.exists(dir_lib):
            print("存在")
            dir_arm64_v8a = dir_lib + "/arm64-v8a"
            dir_armeabi_v7a = dir_lib + "/armeabi-v7a"
            dir_armeabi = dir_lib + "/armeabi"
            dir_x86 = dir_lib + "/x86"
            dir_x86_64 = dir_lib + "/x86_64"
            dir_mips = dir_lib + "/mips"
            dir_mips64 = dir_lib + "/mips64"
            if os.path.exists(dir_arm64_v8a):
                if os.path.exists(dir_armeabi_v7a):
                    shutil.rmtree(dir_armeabi_v7a)
                if os.path.exists(dir_armeabi):
                    shutil.rmtree(dir_armeabi)
                if os.path.exists(dir_x86):
                    shutil.rmtree(dir_x86)
                if os.path.exists(dir_x86_64):
                    shutil.rmtree(dir_x86_64)
                if os.path.exists(dir_mips):
                    shutil.rmtree(dir_mips)
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)

            if os.path.exists(dir_armeabi_v7a):
                if os.path.exists(dir_armeabi):
                    shutil.rmtree(dir_armeabi)
                if os.path.exists(dir_x86):
                    shutil.rmtree(dir_x86)
                if os.path.exists(dir_x86_64):
                    shutil.rmtree(dir_x86_64)
                if os.path.exists(dir_mips):
                    shutil.rmtree(dir_mips)
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)

            if os.path.exists(dir_armeabi):
                if os.path.exists(dir_x86):
                    shutil.rmtree(dir_x86)
                if os.path.exists(dir_x86_64):
                    shutil.rmtree(dir_x86_64)
                if os.path.exists(dir_mips):
                    shutil.rmtree(dir_mips)
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)

            if os.path.exists(dir_x86):
                if os.path.exists(dir_x86_64):
                    shutil.rmtree(dir_x86_64)
                if os.path.exists(dir_mips):
                    shutil.rmtree(dir_mips)
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)

            if os.path.exists(dir_x86_64):
                if os.path.exists(dir_mips):
                    shutil.rmtree(dir_mips)
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)

            if os.path.exists(dir_mips):
                if os.path.exists(dir_mips64):
                    shutil.rmtree(dir_mips64)


if __name__ == '__main__':
    conf = configparser.ConfigParser()
    conf.read('config.ini')

    root = conf.get('folder', 'folder_path_one').strip('"')

    # "E:\apkfile\finish123456788\ANDROID_WEAR\apk"
    # root = "E:/apkfile/AAAAAAA"
    # 遍历第一层文件名（只包含文件夹名） 放到file_list中
    apk_craw_files = find_file_first(root)
    print(apk_craw_files)

    # 把每个文件夹里面的东西删一删
    # 进入到lib里面 先看里面有几个，
    handle_dir(apk_craw_files)

    # 对每个文件夹的so文件进行反编译
    lib = file_so_ida(apk_craw_files)
    print("下面是包含.so文件的文件夹")
    print(lib)


