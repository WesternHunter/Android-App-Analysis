import configparser
import os


# 遍历所有文件名 放到file_list中
def walk_through_dir(root):
    file_list = []
    for (path, subdirs, files) in os.walk(root):
        for name in files:
            file_name = os.path.join(path, name)
            file_list.append(file_name)
    return file_list


# 将tee标识放入tee_lists中
def check_tee_list(TEE_list):
    file_list = []
    with open(TEE_list, 'r') as root12:
        for line in root12:
            line = line[:-1]
            file_list.append(line)
    return file_list


# 检查result中每个txt文件是否有相关标识
def check_TEE_APIs(files, list):
    conf1 = configparser.ConfigParser()
    conf.read('config.ini')
    root2 = conf1.get('output_file', 'output_file_path').strip('"')
    # root2 = "D:/apk/list/TEE-result.txt"
    with open(root2, 'a') as result1:
        count1 = 0
        for s_f in files:
            count = 0
            with open(s_f, 'r') as root1:
                for a in list:
                    root1.seek(0)
                    for line in root1:
                        if line.__contains__(a):
                            count += 1
                            if count == 1:
                                count1 += 1
                                result1.write(str(count1) + ':' + s_f + '中存在的函数有:' + '\n')
                            print(s_f)
                            print(a)
                            line = line[:-1]
                            result1.write('-----------' + line + ':' + '------' + a + '\n')
        result1.write('\n\n\n\n')
        result1.write("==============================================" + '\n')


# 遍历所有.so文件生成的函数列表文件，与“二”中创建的TEE-APIs-List.txt文件中的每一个TEE标识比对
# 记录使用TEE标识的.so文件名以及TEE标识信息（.so文件函数列表里所找到的TEE函数名、变量名等）
# 可以写入一个.txt文件保存
if __name__ == '__main__':
    conf = configparser.ConfigParser()
    conf.read('config.ini')

    root = conf.get('folder', 'folder_path').strip('"')
    # 遍历所有文件名 放到file_list中
    all_files = walk_through_dir(root)
    # 将trusty API 放入trusty_list中
    trusty_lists = check_tee_list(conf.get('key_csv_file', 'TEE-APIs-List-path').strip('"'))
    # 检查result中每个txt文件是否有相关标识
    check_TEE_APIs(all_files, trusty_lists)
    print("Done")
