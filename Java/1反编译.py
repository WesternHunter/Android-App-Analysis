# 文件名：apk.py
# 创建时间：2023/7/12
# 文件的目的/作用：使用Apktool对下载完成的apk文件进行反编译。
import configparser
import os
import subprocess


# 遍历第一层文件名 放到file_list中
def find_first_file(root1):
    data = []
    for (path, subdirs, files) in os.walk(root1):
        for name in files:
            file_name = os.path.join(path, name)
            print(file_name)
            data.append(file_name)
        break
    print(len(data))
    return data


# 识别出所有后缀为 .apk的文件
def find_apk_file(data):
    apk_files1 = []
    for f in data:
        file_type = os.path.splitext(f)[-1]
        if file_type == ".apk":
            # 从后往前找到第一个`\`的索引
            index = f.rfind('\\')

            # 截取`\`后面的内容
            f_new = f[index + 1:]
            # 此时文件路径为D:/apk/test1-111-111\5E3C186499A43E87072A36D4827AE84258D6E12A40041DDC6EDE9E77A5A8FDF4.apk
            # 21代表将D:/apk/test1-111-111\去掉
            # f = f[28:]
            apk_files1.append(f_new)
    print(apk_files1)
    return apk_files1


# 反编译apk文件
def apktool(data):
    i = 1
    for file in data:
        cmd_str = 'java -jar apktool_2.7.0.jar d {}'.format(file)
        print(cmd_str)
        p = subprocess.Popen(cmd_str)
        p.wait()
        print("Done" + str(i))
        i += 1


if __name__ == '__main__':
    # 初始化实例
    conf = configparser.ConfigParser()
    conf.read('config.ini')
    all_smali_file = conf.get('folder', 'folder_path').strip('"')

    os.chdir(all_smali_file)
    print(os.getcwd())
    print("========")
    # 遍历第一层文件名 放到file_list中
    file_list = find_first_file(all_smali_file)
    # 识别出所有后缀为 .apk的文件
    apk_files = find_apk_file(file_list)
    print(apk_files)
    print(len(apk_files))
    # 反编译apk文件
    apktool(apk_files)
