# 文件名：asda
# 创建时间：2023/12/7
# 文件的目的/作用：判断哪些smali文件间接调用了TEE(函数调用)
import csv
import os
import re
import configparser
from datetime import datetime, timedelta
from time import sleep

import chardet

# 输出测试常量
PRINT_TEST = 0

# begin=========================================
KeyStore_list_extra = {"KeyStore$PrivateKeyEntry", "KeyStore$Builder",
                       "KeyStore$CallbackHandlerProtection", "KeyStore$Entry$Attribute", "KeyStore$Entry",
                       "KeyStore$LoadStoreParameter", "KeyStore$PasswordProtection", "KeyStore$SecretKeyEntry",
                       "KeyStore$TrustedCertificateEntry",
                       "KeyStore", "KeyPairGenerator", "KeyGenerator", "EncryptedFile$Builder",
                       "EncryptedFile$FileEncryptionScheme", "EncryptedFile",
                       "EncryptedSharedPreferences$PrefKeyEncryptionScheme", "KeyChain",
                       "EncryptedSharedPreferences$PrefValueEncryptionScheme", "EncryptedSharedPreferences",
                       "MediaDRM", "DrmManagerClient",
                       "android/server/biometrics/AuthService",
                       "android/server/biometrics/Utils",
                       "AuthService",
                       "BiometricManager",
                       "BiometricPrompt",
                       "BiometricScheduler",
                       "FaceAuthenticator",
                       "FingerprintAuthenticator",
                       "FingerprintGestureDispatcher",
                       "FingerprintManager",
                       "FingerprintService",
                       "LockPatternChecker",
                       "LockSettingsService",
                       "LockPatternUtils/StrongAuthTracker",
                       "LockPatternUtils$StrongAuthTracker",
                       "LockPatternUtils",
                       "RecoveryController",
                       "RecoverySession",
                       "ILockSettings$Stub$Proxy",
                       "ILockSettings$Stub",
                       "ILockSettings",
                       "IFingerprintService",
                       "IFaceService",
                       "FaceService",
                       "FaceManager/OnAuthenticationCancelListener",
                       "FaceManager/OnFaceDetectionCancelListener",
                       "FaceManager/OnEnrollCancelListener",
                       "FaceManager$OnAuthenticationCancelListener",
                       "FaceManager$OnFaceDetectionCancelListener",
                       "FaceManager$OnEnrollCancelListener",
                       "FaceManager",
                       "FingerprintManager/OnFingerprintDetectionCancelListener",
                       "FingerprintManager/OnAuthenticationCancelListener",
                       "FingerprintManager/OnEnrollCancelListener",
                       "FingerprintManager$OnFingerprintDetectionCancelListener",
                       "FingerprintManager$OnAuthenticationCancelListener",
                       "FingerprintManager$OnEnrollCancelListener",
                       "IBiometricService",
                       "BiometricService",
                       "BiometricPrompt/OnAuthenticationCancelListener",
                       "BiometricPrompt$OnAuthenticationCancelListener"
                       }

face_finger_list_extra_extra = {"StrongAuthTracker", "AuthService", "Utils", "OnEnrollCancelListener",
                                "OnAuthenticationCancelListener", "OnFingerprintDetectionCancelListener",
                                "OnFaceDetectionCancelListener"}

special_list_extra = {"getLockSettings",
                      "getFingerprintManager",
                      "getFaceManager",
                      "android/security/keystore/KeyGenParameterSpec/Builder",
                      "setAttestationChallenge",
                      "android/security/ConfirmationCallback",
                      "android/security/ConfirmationPrompt",
                      "getService",
                      "getSystemService",
                      "setUserConfirmationRequired"}
special_list_extra_gudingzhi = {"getSystemService", "setUserConfirmationRequired", "getService"}


# ===================================end


# 提取小括号中内容
def extract_text_in_parentheses(text):
    pattern = r'\((.*?)\)'
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    else:
        return ""


# 读csv文件，获取关键字列表
def read_csv_file(root1):
    with open(root1, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']
    # 以读方式打开文件
    with open(root1, encoding=encoding) as f:
        # 基于打开的文件，创建csv.reader实例
        reader = csv.reader(f)
        # 获取第一行的header
        header = next(reader)
        if PRINT_TEST == 1:
            print(header)
            print("=================")
        # header[0] = "id"
        # header[1] = "关键词大类"
        # header[2] = "关键词所在类"
        # header[3] = "关键词类型"
        # header[4] = "关键词名称"
        # header[5] = "返回值类型"
        # header[6] = "参数列表"
        # header[7] = "链接"
        keyword_list = []
        for row in reader:
            # 处理输入参数
            enter_the_parameter = row[6]
            # char[] password,String protectionAlgorithm,AlgorithmParameterSpec protectionParameters用，分隔开
            parameters_lists = enter_the_parameter.split(",")
            # ['char[] password', 'String protectionAlgorithm', 'AlgorithmParameterSpec protectionParameters']
            processed_parameter = []
            for parameters in parameters_lists:
                index = parameters.rfind(' ')
                result = parameters[:index]
                if PRINT_TEST == 1:
                    print(result)
                processed_parameter.append(result)
            if PRINT_TEST == 1:
                print(processed_parameter)
            # 列表去空  上面处理完后[""]这个长度为1，要进行去空
            temp = []
            for parameter in processed_parameter:
                # 处理string当中有set的部分
                if 'set<' in parameter:
                    temp.append('set')
                else:
                    if len(parameter):
                        temp.append(parameter)
            processed_parameter = temp
            if PRINT_TEST == 1:
                print(len(processed_parameter))
            # 将数据存入data
            data = [row[0], row[2], row[3], row[4], processed_parameter, row[5]]
            # 0 header[0] = "id"
            # 1 header[1] = "关键词所在类"
            # 2 header[2] = "关键词类型"
            # 3 header[3] = "关键词名称"
            # 4 header[4] = "参数列表"
            # 5 header[5] = "返回值类型"

            keyword_list.append(data)
        if PRINT_TEST == 1:
            print(keyword_list)
        return keyword_list


# 遍历第一层文件名（只包含文件夹名）
def find_file_first(root):
    data = []
    for (path, subdirs, files) in os.walk(root):
        for name in subdirs:
            file_name = os.path.join(path, name)  # 在这连接的时候导致文件出现\\反斜杠
            if PRINT_TEST == 1:
                print(file_name)
            data.append(file_name)
        break
    if PRINT_TEST == 1:
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


# 检查一个文件夹中所有smali文件中是否有相关TEE标识
def check_TEE_APIs(files, all_keywords_lists, folder_number, sha256):
    data_lists = []  # 记录一下要输出的数据
    cout_all_invoke_list = []  # 记录每个smali文件中的invoke个数
    # 参数folder_number代表这个是第几个文件夹
    folder_smali_number = 0  # 代表这个文件夹中第几个smali文件
    flag = False
    for s_f in files:
        # file_num = 0
        try:
            # time9999 = datetime.now();
            with open(s_f, 'r') as root1:
                # time10101010 = datetime.now()
                # cha5 = time10101010 - time9999
                # global find_time_open
                # find_time_open = cha5 + find_time_open

                # time7777 = datetime.now()
                content = root1.read()
                cout_all_invoke = content.count('invoke')
                test1111111 = [sha256, s_f, cout_all_invoke]
                cout_all_invoke_list.append(test1111111)
                # time8888 = datetime.now()
                # cha4 = time8888 - time7777
                # global find_time_content
                # find_time_content = cha4 + find_time_content
                # if content.find('invoke'):
                # time5555 = datetime.now()
                if any(keyword in content for keyword in KeyStore_list_extra) or any(
                        keyword in content for keyword in special_list_extra):
                    # time6666 = datetime.now()
                    # cha3 = time6666 - time5555
                    # global find_time
                    # find_time = cha3 + find_time
                    flag = True
                    print(folder_smali_number)
                    # file_num = file_num + 1
                    # print(file_num)
                    smali_number = 0  # 变量smali_number代表这个smali文件中的第几个
                    smali_line_number = 0  # 变量smali_line_number代表这个smali文件中的行号
                    root1.seek(0)
                    for line in root1:
                        # 为了让特殊判断能跳出循环
                        special = 0
                        special1 = 0
                        smali_line_number = smali_line_number + 1  # 每遍历一行，行号smali_line_number加1
                        # all_invoke_num = 0   # 记录一个smali文件中一共有多少个函数调用，用来看占比   在这不好实现，因为好多break
                        # 判断常规的
                        if 'invoke' in line:
                            # 计时，比较一下到底哪里耗时
                            # time1111 = datetime.now()
                            # 提取出关键词所在类
                            start_index = line.find('/')
                            end_index = line.find(';->')
                            result_lei = line[start_index + 1:end_index]
                            last_slash_index = result_lei.rfind('/')
                            result_lei = result_lei[last_slash_index + 1:]
                            if PRINT_TEST == 1:
                                print(result_lei)
                            # 这一行中存在关键词所在类的其中一个
                            if result_lei in KeyStore_list_extra or result_lei in face_finger_list_extra_extra:
                                # 再开始看其他关键字
                                for keyword in all_keywords_lists:
                                    # 如果是KeyStore和DRM，正常检测
                                    if 1 < float(keyword[0]) < 2 or 4 < float(keyword[0]) < 5:
                                        # 关键字列表
                                        # 0 header[0] = "id"
                                        # 1 header[1] = "关键词所在类"
                                        # 2 header[2] = "关键词类型"
                                        # 3 header[3] = "关键词名称（用哪个方法）"
                                        # 4 参数列表[4]
                                        # 判断一下是不是entryInstanceOf 这个比较特殊 参数列表有Class<? extends KeyStore$Entry> 但是这个关键词名称只有一个 所以单独判断一下
                                        if keyword[3] == 'entryinstanceof':
                                            if keyword[3] in line:
                                                smali_number = smali_number + 1
                                                if smali_number == 1:
                                                    folder_smali_number = folder_smali_number + 1
                                                # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                                # "这一行的内容", "参数列表", "返回值类型", "关键词所在类", "关键词类型", "关键词名称", "id", "包名", "类别"]
                                                data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                         smali_line_number,
                                                         line, keyword[4], keyword[5], keyword[1], keyword[2],
                                                         keyword[3],
                                                         keyword[0], sha256, str(0)]
                                                data_lists.append(data1)
                                                special1 = 1
                                                break
                                        # 判断关键词所在类和关键词名称是否在smali代码中
                                        if keyword[1] in line and keyword[3] in line:
                                            # 判断参数
                                            if len(keyword[4]) != 0:  # 有参数
                                                # 把line（）里面提取出来   提取参数
                                                line1 = extract_text_in_parentheses(line)
                                                if PRINT_TEST == 1:
                                                    # (LJava/security/spec/AlgorithmParameterSpec;)
                                                    print(line1)  # 输出：sample text
                                                my_list = line1.split(";")
                                                my_list1 = []
                                                if PRINT_TEST == 1:
                                                    print(my_list)
                                                for i in my_list:
                                                    if '[' in i:
                                                        index = i.rfind("/")
                                                        result = i[index + 1:] + '[]'
                                                        if PRINT_TEST == 1:
                                                            print(result)
                                                        my_list1.append(result)
                                                    else:
                                                        if i:
                                                            index = i.rfind("/")
                                                            result = i[index + 1:]
                                                            if PRINT_TEST == 1:
                                                                print(result)
                                                            my_list1.append(result)
                                                if PRINT_TEST == 1:
                                                    print(my_list)
                                                    print(my_list1)
                                                if my_list1 == keyword[4]:
                                                    if PRINT_TEST == 1:
                                                        print("是的")
                                                    # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                                    # "这一行的内容", "关键词所在类", "关键词类型", "关键词名称", "id", "sha256"]
                                                    # 0000000000000000000000000000000000
                                                    smali_number = smali_number + 1
                                                    if smali_number == 1:
                                                        folder_smali_number = folder_smali_number + 1
                                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                             smali_line_number,
                                                             line, keyword[4], keyword[5], keyword[1], keyword[2],
                                                             keyword[3],
                                                             keyword[0], sha256, str(0)]
                                                    data_lists.append(data1)
                                                    special1 = 1
                                                    break
                                                # 添加：如果参数个数相同，但是类型不相同，进行记录111111111111111
                                                if len(my_list1) == len(keyword[4]):
                                                    # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                                    # "这一行的内容", "关键词所在类", "关键词类型", "关键词名称", "id", "sha256"]
                                                    smali_number = smali_number + 1
                                                    if smali_number == 1:
                                                        folder_smali_number = folder_smali_number + 1
                                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                             smali_line_number,
                                                             line, keyword[4], keyword[5], keyword[1], keyword[2],
                                                             keyword[3], keyword[0],
                                                             sha256, str(1)]
                                                    data_lists.append(data1)
                                                    special1 = 1
                                                    break
                                            else:  # 没有参数
                                                smali_number = smali_number + 1
                                                if smali_number == 1:
                                                    folder_smali_number = folder_smali_number + 1
                                                data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                         smali_line_number,
                                                         line, keyword[4], keyword[5], keyword[1], keyword[2],
                                                         keyword[3],
                                                         keyword[0],
                                                         sha256, str(0)]
                                                data_lists.append(data1)
                                                special1 = 1
                                                break
                                    # 判断Gatekeeper和face Fingerprint,不需要判断具体是哪一类了
                                    else:
                                        # 判断关键词所在类和关键词名称是否在smali代码中
                                        if result_lei in line and keyword[3] in line:
                                            # 判断参数
                                            if len(keyword[4]) != 0:  # 有参数
                                                # 把line（）里面提取出来   提取参数
                                                line1 = extract_text_in_parentheses(line)
                                                if PRINT_TEST == 1:
                                                    # (LJava/security/spec/AlgorithmParameterSpec;)
                                                    print(line1)  # 输出：sample text
                                                my_list = line1.split(";")
                                                my_list1 = []
                                                if PRINT_TEST == 1:
                                                    print(my_list)
                                                for i in my_list:
                                                    if '[' in i:
                                                        index = i.rfind("/")
                                                        result = i[index + 1:] + '[]'
                                                        if PRINT_TEST == 1:
                                                            print(result)
                                                        my_list1.append(result)
                                                    else:
                                                        if i:
                                                            index = i.rfind("/")
                                                            result = i[index + 1:]
                                                            if PRINT_TEST == 1:
                                                                print(result)
                                                            my_list1.append(result)
                                                if PRINT_TEST == 1:
                                                    print(my_list)
                                                    print(my_list1)
                                                if my_list1 == keyword[4]:
                                                    if PRINT_TEST == 1:
                                                        print("是的")
                                                    # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                                    # "这一行的内容", "关键词所在类", "关键词类型", "关键词名称", "id", "sha256"]
                                                    # 0000000000000000000000000000000000
                                                    smali_number = smali_number + 1
                                                    if smali_number == 1:
                                                        folder_smali_number = folder_smali_number + 1
                                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                             smali_line_number,
                                                             line, keyword[4], keyword[5], result_lei, keyword[2],
                                                             keyword[3],
                                                             keyword[0], sha256, str(0)]
                                                    data_lists.append(data1)
                                                    special1 = 1
                                                    break
                                                # 添加：如果参数个数相同，但是类型不相同，进行记录111111111111111
                                                if len(my_list1) == len(keyword[4]):
                                                    # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                                    # "这一行的内容", "关键词所在类", "关键词类型", "关键词名称", "id", "sha256"]
                                                    smali_number = smali_number + 1
                                                    if smali_number == 1:
                                                        folder_smali_number = folder_smali_number + 1
                                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                             smali_line_number,
                                                             line, keyword[4], keyword[5], result_lei, keyword[2],
                                                             keyword[3], keyword[0],
                                                             sha256, str(1)]
                                                    data_lists.append(data1)
                                                    special1 = 1
                                                    break
                                            else:  # 没有参数
                                                smali_number = smali_number + 1
                                                if smali_number == 1:
                                                    folder_smali_number = folder_smali_number + 1
                                                data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                         smali_line_number,
                                                         line, keyword[4], keyword[5], result_lei, keyword[2],
                                                         keyword[3],
                                                         keyword[0],
                                                         sha256, str(0)]
                                                data_lists.append(data1)
                                                special1 = 1
                                                break
                            # time2222 = datetime.now()
                            # cha1 = time2222 - time1111
                            # global zero_and_one_time
                            # zero_and_one_time = cha1 + zero_and_one_time
                            # 参数类型在“关键词所在类”列表里存在2222222222222
                            # time3333 = datetime.now()
                            if special1 == 0:
                                # 判断参数
                                # 把line（）里面提取出来   提取参数
                                line1 = extract_text_in_parentheses(line)
                                # 有参数
                                if line1 != "":
                                    if PRINT_TEST == 1:
                                        # (LJava/security/spec/AlgorithmParameterSpec;)
                                        print(line1)  # 输出：sample text
                                    my_list = line1.split(";")
                                    my_list1 = []
                                    if PRINT_TEST == 1:
                                        print(my_list)
                                    for i in my_list:
                                        if '[' in i:
                                            index = i.rfind("/")
                                            result = i[index + 1:] + '[]'
                                            if PRINT_TEST == 1:
                                                print(result)
                                            my_list1.append(result)
                                        else:
                                            if i:
                                                index = i.rfind("/")
                                                result = i[index + 1:]
                                                if PRINT_TEST == 1:
                                                    print(result)
                                                my_list1.append(result)
                                    for key1 in my_list1:
                                        if key1 in KeyStore_list_extra:
                                            smali_number = smali_number + 1
                                            if smali_number == 1:
                                                folder_smali_number = folder_smali_number + 1
                                            data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                                     smali_line_number,
                                                     line, key1, key1, key1, key1, key1,
                                                     "index", sha256, str(2)]
                                            data_lists.append(data1)
                                            break
                            # time4444 = datetime.now()
                            # cha2 = time4444 - time3333
                            # global two_time
                            # two_time = two_time + cha2
                        # 判断特殊的
                        # 出现其中一个关键词名称就先保存下来，供后续分析
                        # time11111111 = datetime.now()
                        for key_protected in special_list_extra:
                            if key_protected in line:
                                # 还需要判断是否存在固定值  记为4
                                if key_protected in special_list_extra_gudingzhi:
                                    smali_number = smali_number + 1
                                    if smali_number == 1:
                                        folder_smali_number = folder_smali_number + 1
                                        # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                        # "这一行的内容", "关键词名称", "关键词名称", "special", "special", "包名", "类别"]

                                        # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                        # "这一行的内容", "参数列表", "返回值类型", "关键词所在类", "关键词类型", "关键词名称", "id", "包名", "类别"]
                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                             smali_line_number, line, key_protected, key_protected, key_protected,
                                             key_protected, "special", "special", sha256, str(4)]
                                    data_lists.append(data1)
                                    break
                                # 不需要判断是否存在固定值 记为3
                                else:
                                    smali_number = smali_number + 1
                                    if smali_number == 1:
                                        folder_smali_number = folder_smali_number + 1
                                        # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                        # "这一行的内容", "关键词名称", "关键词名称", "special", "special", "包名", "类别"]

                                        # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
                                        # "这一行的内容", "参数列表", "返回值类型", "关键词所在类", "关键词类型", "关键词名称", "id", "包名", "类别"]
                                    data1 = [folder_number, folder_smali_number, smali_number, s_f,
                                             smali_line_number, line, key_protected, key_protected, key_protected,
                                             key_protected, "special", "special", sha256, str(3)]
                                    data_lists.append(data1)
                                    break
                        # time12121212 = datetime.now()
                        # cha6 = time12121212 - time11111111
                        # global time_special
                        # time_special = time_special + cha6
        except UnicodeDecodeError as gbk_error:
            print("error")
            continue
    if flag is False:
        empty_sha256.append(sha256)
    return data_lists, cout_all_invoke_list


# 识别出所有后缀为.smali的文件
def find_smali_files(all_files):
    smali_files = []
    for file in all_files:
        file_type = os.path.splitext(file)[-1]
        if file_type == ".smali":
            smali_files.append(file)
            if PRINT_TEST == 1:
                print(file)
    return smali_files


# 读取所有的smali文件
def read_smali_file(root_files):
    # 遍历第一层文件名（只包含文件夹名）
    first_files = find_file_first(root_files)
    if PRINT_TEST == 1:
        print(len(first_files))
        print(first_files)
    smali_files = []
    for first_file in first_files:
        if PRINT_TEST == 1:
            print(first_file)  # D:/apk/test1-111-111\5DD18D4D0AFB7C8428F0AB1BD90EF68AE8AE67F8BC3F00F22758FBA79D805520
        # 遍历所有文件名 放到all_files中
        all_files = walk_through_dir(first_file)
        if PRINT_TEST == 1:
            print(len(all_files))
        # 识别出所有smali文件并将smali文件放到smali_file当中
        smali_file = find_smali_files(all_files)
        # D:/apk/test1-111-111\5DE3E095A96BFF5760D2CD9DD48F1FC31E193850AE84EEB17C7E53300B678D00\lib\arm64-v8a\libmono-native.so
        if PRINT_TEST == 0:
            print(len(smali_file))
            print(first_file)
        if len(smali_file) != 0:
            smali_files.append(smali_file)
    return smali_files


# 对每个文件夹的smali文件进行匹配
def file_smali_invoke_match(all_smali_files, keywords_list):
    folder_number = 1
    results_files = []
    invoke_numbers = []
    for single_all_smali in all_smali_files:

        if PRINT_TEST == 1:
            print(single_all_smali[0])  # 随便拿一个就行，因为这个里面都是一个包的
        # 提取包名
        result = re.search(r'\\([^\\]+)\\', single_all_smali[0])
        if result:
            package_name = result.group(1)
            if PRINT_TEST == 0:
                print("提取的内容为:", package_name)
                print("=====")
        else:
            print("未找到匹配的内容。")

        # 提取sha256
        # sha256 = re.findall(r'(?<=\\)[A-Za-z0-9]{64}(?=\\)', single_all_smali[0])
        # if PRINT_TEST == 1:
        #     print(single_all_smali[0])
        #     print(sha256[0])

        # 检查一个文件夹中所有smali文件中是否有相关TEE标识
        result_csv, cout_invoke_yigewenjian = check_TEE_APIs(single_all_smali, keywords_list, folder_number,
                                                             package_name)
        results_files.append(result_csv)
        invoke_numbers.append(cout_invoke_yigewenjian)
        if PRINT_TEST == 0 or 1:
            print("第" + str(folder_number) + "个执行完毕")
        folder_number = folder_number + 1
    return results_files, invoke_numbers


# 将结果输出到csv文件当中
def write_result(results, output_file):
    with open(output_file, mode="a", encoding="utf-8-sig", newline="") as f:
        # 基于打开的文件，创建 csv.writer 实例
        writer = csv.writer(f)
        header_list = ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个", "所在哪个文件中", "行号",
                       "这一行的内容", "参数列表", "返回值类型", "关键词所在类", "关键词类型", "关键词名称", "id",
                       "包名", "类别"]
        # 写入 header。
        # writerow() 一次只能写入一行。
        writer.writerow(header_list)
        # 写入数据。
        # writerows() 一次写入多行。
        for result in results:
            writer.writerows(result)


# 具体判断参数中是否有AndroidKeyStore参数
def judge_AKS(file_name, line_invoke, contend_invoke, special_key):
    # 文件名 行号 这一行的内容
    # 结构化分析contend_invoke,判断这一行{}里面有几个参数，分别是什么
    # invoke-virtual {p3},{v0, p0},{v5, v6, v4}
    if PRINT_TEST == 1:
        print(file_name)
    # ①使用正则表达式提取大括号中的内容 ②将匹配的内容放入一个字符串中 ③用，分隔开 ④去空格
    matches = re.findall(r'\{(.*?)\}', contend_invoke)
    result = ''.join(matches)
    result1 = result.split(",")
    parameter_list = [x.strip() for x in result1]
    if PRINT_TEST == 1:
        print(parameter_list)
    # 打开要判断这条数据的smali源文件
    with open(file_name, 'r') as smali_file:
        # 记录函数调用之前的行
        line_list = []
        # 记录当前文件的行号
        line_number = 0
        if PRINT_TEST == 1:
            print(1)
        # 比如函数调用在第100行，那么把前15行都先保存起来，然后倒着遍历参数
        for line in smali_file:
            line_number = line_number + 1
            if int(line_invoke) - 15 <= line_number < int(line_invoke):
                line_list.append(line)
        # 开始判断是否存在AndroidKeyStore参数
        for parameter in reversed(parameter_list):
            for line in reversed(line_list):
                if parameter in line and special_key in line:
                    print("确认是传入了" + special_key + "参数")
                    return 1
        return 0


# 判断AndroidKeyStore参数，将旧结果重新写到新文件中
def judge_AndroidKeyStore(output_file, output_file_AKS):
    with open(output_file, 'r', newline='', encoding="utf-8-sig") as infile, open(output_file_AKS, 'w', newline='',
                                                                                  encoding="utf-8-sig") as outfile:
        # header[0] = "第几个文件夹"
        # header[1] = "第几个smali文件"
        # header[2] = "一个smali文件中的第几个"
        # header[3] = "所在哪个文件中"
        # header[4] = "行号"
        # header[5] = "这一行的内容"
        # header[6] = "参数列表"
        # header[7] = "返回值类型"
        # header[8] = "关键词所在类"
        # header[9] = "关键词类型"
        # header[10] = "关键词名称"
        # header[11] = "id"
        # header[12] = "包名"
        # header[13] = "类别"

        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        # 获取第一行的header
        header1 = next(reader)
        print(header1)
        print("=================")
        # ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个","所在哪个文件中", "行号",
        # "这一行的内容", "参数列表", "返回值类型", "关键词所在类", "关键词类型", "关键词名称", "id", "包名", "类别"]
        header_list = ["第几个文件夹", "第几个smali文件", "一个smali文件中的第几个", "所在哪个文件中", "行号",
                       "这一行的内容", "参数列表", "返回值类型",
                       "关键词所在类", "关键词类型", "关键词名称", "id", "包名", "类别", "固定值"]
        # 新的csv文件写入标题header。
        writer.writerow(header_list)
        i = 0
        for row in reader:
            i += 1
            print(i)
            temp = row
            if PRINT_TEST == 1:
                print(temp)
            # 判断是否可能有AndroidKeyStore参数
            if row[11] in ['1.0401', '1.0781', '1.0901']:
                # if PRINT_TEST == 1:
                print("===========androidkeystore")
                # 在这进行具体判断“AndroidKeyStore”
                if judge_AKS(row[3], row[4], row[5], "AndroidKeyStore"):
                    temp.append("AndroidKeyStore")
                    if PRINT_TEST == 1:
                        print(temp)
                else:
                    temp.append("不一定是")
            # 在这进行判断其他的固定值
            # getService-----lock_settings
            # getSystemService------FingerprintManager.class
            # getSystemService------FaceManager.class
            # setUserConfirmationRequired-----true
            if row[8] == "getService":
                # print("=======getService")
                if judge_AKS(row[3], row[4], row[5], "lock_settings"):
                    temp.append("lock_settings")
                    if PRINT_TEST == 1:
                        print(temp)
                else:
                    temp.append("不一定是")
            if row[8] == "getSystemService":
                # print("=======getSystemService")
                if judge_AKS(row[3], row[4], row[5], "FingerprintManager.class"):
                    temp.append("FingerprintManager.class")
                    if PRINT_TEST == 1:
                        print(temp)
                else:
                    temp.append("不一定是")
            if row[8] == "getSystemService":
                if judge_AKS(row[3], row[4], row[5], "FaceManager.class"):
                    temp.append("FaceManager.class")
                    if PRINT_TEST == 1:
                        print(temp)
                else:
                    temp.append("不一定是")
            if row[8] == "setUserConfirmationRequired":
                if judge_AKS(row[3], row[4], row[5], "true"):
                    temp.append("true")
                    if PRINT_TEST == 1:
                        print(temp)
                else:
                    temp.append("不一定是")
            writer.writerow(temp)
    print("数据已成功修改并写入到 output.csv 文件中")


if __name__ == '__main__':
    # global zero_and_one_time
    # global two_time
    # global find_time
    # global find_time_content
    # global find_time_open
    # global time_special
    # zero_and_one_time = timedelta(hours=0, minutes=0)
    # two_time = timedelta(hours=0, minutes=0)
    # find_time = timedelta(hours=0, minutes=0)
    # find_time_content = timedelta(hours=0, minutes=0)
    # find_time_open = timedelta(hours=0, minutes=0)
    # time_special = timedelta(hours=0, minutes=0)
    # print(zero_and_one_time)
    # print(two_time)
    # print(find_time)
    # print(find_time_content)
    # print(find_time_open)
    # print(time_special)
    # 初始化实例
    conf = configparser.ConfigParser()
    conf.read('config.ini')

    empty_sha256 = []

    # ①读csv文件，读取关键词列表
    keywords_lists = read_csv_file(conf.get('key_csv_file', 'key_csv_file_path').strip('"'))
    # ②读取所有的smali文件
    all_smali_file = read_smali_file(conf.get('folder', 'folder_path').strip('"'))
    # ③对每个文件夹中的smali文件进行分析
    result_file, invoke_file = file_smali_invoke_match(all_smali_file, keywords_lists)
    # ④将结果写入到csv文件当中
    write_result(result_file, conf.get('output_file', 'output_file_path').strip('"'))
    write_result(invoke_file, conf.get('output_file', 'output_file_path_invoke').strip('"'))
    # ⑤判断AndroidKeyStore参数
    judge_AndroidKeyStore(conf.get('output_file', 'output_file_path').strip('"'),
                          conf.get('output_file', 'output_file_path_AKS').strip('"'))

    print(empty_sha256)
