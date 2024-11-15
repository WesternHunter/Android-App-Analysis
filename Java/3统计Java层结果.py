import os
import csv
import time
import csv
from datetime import datetime
import configparser

import chardet
import conf

KeyStore_list_extra = {"KeyStore$PrivateKeyEntry", "KeyStore$Builder",
                       "KeyStore$CallbackHandlerProtection", "KeyStore$Entry$Attribute", "KeyStore$Entry",
                       "KeyStore$LoadStoreParameter",
                       "KeyStore$PasswordProtection", "KeyStore$SecretKeyEntry", "KeyStore$TrustedCertificateEntry",
                       "KeyStore",
                       "KeyPairGenerator", "KeyGenerator", "EncryptedFile$Builder",
                       "EncryptedFile$FileEncryptionScheme", "EncryptedFile",
                       "EncryptedSharedPreferences$PrefKeyEncryptionScheme", "KeyChain",
                       "EncryptedSharedPreferences$PrefValueEncryptionScheme", "EncryptedSharedPreferences"}
GateKeeper = ["ILockSettings", "ILockSettings$Stub",
              "ILockSettings$Stub$Proxy", "LockSettingsService",
              "LockPatternUtils", "LockPatternChecker",
              "RecoveryController", "RecoverySession",
              "LockPatternUtils/StrongAuthTracker",
              "LockPatternUtils$StrongAuthTracker",
              "StrongAuthTracker",
              "getService", "getLockSettings"]
FingerprintService = ["FingerprintService",
                      "IFingerprintService",
                      "FingerprintManager",
                      "FingerprintManager.OnEnrollCancelListener",
                      "FingerprintManager.OnAuthenticationCancelListener",
                      "FingerprintGestureDispatcher",
                      "IFaceService",
                      "FaceManager",
                      "FaceService",
                      "FaceAuthenticator",
                      "FaceManager.OnAuthenticationCancelListener",
                      "FaceManager.OnFaceDetectionCancelListener",
                      "FaceManager.OnEnrollCancelListener",
                      "FaceManager/OnAuthenticationCancelListener",
                      "FaceManager/OnFaceDetectionCancelListener",
                      "FaceManager/OnEnrollCancelListener",
                      "FaceManager$OnAuthenticationCancelListener",
                      "FaceManager$OnFaceDetectionCancelListener",
                      "FaceManager$OnEnrollCancelListener",
                      "AuthService",
                      "FingerprintManager",
                      "IFingerprintService",
                      "FingerprintAuthenticator",
                      "FingerprintService",
                      "FingerprintManager$OnAuthenticationCancelListener"
                      "FingerprintManager$OnFingerprintDetectionCancelListener"
                      "FingerprintManager$OnEnrollCancelListener",
                      "FingerprintManager/OnFingerprintDetectionCancelListener",
                      "FingerprintManager/OnAuthenticationCancelListener",
                      "FingerprintManager/OnEnrollCancelListener",
                      "FingerprintGestureDispatcher",
                      "AuthService",
                      "BiometricPrompt",
                      "BiometricManager",
                      "BiometricService",
                      "IBiometricService",
                      "AuthService",
                      "BiometricPrompt.OnAuthenticationCancelListener",
                      "BiometricPrompt/OnAuthenticationCancelListener",
                      "BiometricPrompt$OnAuthenticationCancelListener",
                      "BiometricScheduler",
                      "Utils",
                      "getFingerprintManager", "getFaceManager",
                      "getSystemService"]
DRM = {"MediaDRM", "DrmManagerClient"}
AuthService = "server/biometrics/AuthService"
Utils = "server/biometrics/Utils"

face_finger_special = ["getFingerprintManager", "getFaceManager"]
GateKeeper_special = ["getService", "getLockSettings"]

Android_Protected_Confirmation = ["android/security/keystore/KeyGenParameterSpec/Builder",
                                  "setAttestationChallenge",
                                  "android/security/ConfirmationCallback",
                                  "android/security/ConfirmationPrompt"]


def all_num(dict):
    num = 0
    for key in dict:
        num += dict[key]
    return num


# 111111 求每一个app的TEE相关数量
def read_csv_file_TEE_KeyStore(root_tee):
    # 以读方式打开文件
    with open(root_tee, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    with open(root_tee, 'r', encoding=encoding) as f:
        # 基于打开的文件，创建csv.reader实例
        reader = csv.reader(f)
        header = next(reader)
        i = 1
        # 逐行获取数据，并输出
        for row in reader:
            # print(i)
            # if i < 500:
            # 0第几个文件夹
            # 1第几个smali文件
            # 2一个smali文件中的第几个
            # 3所在哪个文件中
            # 4行号
            # 5这一行的内容
            # 6参数列表
            # 7返回值类型
            # 8关键词所在类
            # 9关键词类型
            # 10关键词名称
            # 11 id
            # 12包名
            # 13类别
            # 14固定值
            # 15固定值
            # 16类型
            name = all_data_dict[row[12]]

            # 11111111111111111111
            if row[13] == str(0):
                if str(1) < row[11] < str(2):
                    all_data_dict[row[12]][1] += 1
                    continue
            if row[13] == str(1):
                if str(1) < row[11] < str(2):
                    all_data_dict[row[12]][1] += 1
                    continue
            if row[13] == str(2):
                if row[8] in KeyStore_list_extra:
                    all_data_dict[row[12]][1] += 1
                    continue
            # 2222222222222
            if row[8] in FingerprintService:
                if row[13] == str(0):
                    if str(2) < row[11] < str(3):
                        if row[8] == "AuthService":
                            if row[5].__contains__(AuthService):
                                all_data_dict[row[12]][2] += 1
                            continue
                        elif row[8] == "Utils":
                            if row[5].__contains__(Utils):
                                all_data_dict[row[12]][2] += 1
                            continue
                        else:
                            all_data_dict[row[12]][2] += 1
                            continue
                if row[13] == str(1):
                    if str(2) < row[11] < str(3):
                        temp = row[8] + '-' + row[10]
                        if row[8] == "AuthService":
                            if row[5].__contains__(AuthService):
                                all_data_dict[row[12]][2] += 1
                            continue
                        if row[8] == "Utils":
                            if row[5].__contains__(Utils):
                                all_data_dict[row[12]][2] += 1
                            continue
                        all_data_dict[row[12]][2] += 1
                if row[13] == str(2):
                    if row[8] in FingerprintService:
                        all_data_dict[row[12]][2] += 1
            # 3333333333333
            if row[8] in GateKeeper:
                if row[13] == str(0):
                    if str(3) < row[11] < str(4):
                        all_data_dict[row[12]][3] += 1
                if row[13] == str(1):
                    if str(3) < row[11] < str(4):
                        all_data_dict[row[12]][3] += 1
                if row[13] == str(2):
                    if row[8] in GateKeeper:
                        all_data_dict[row[12]][3] += 1

            # 44444444444444444444
            if row[13] == str(0):
                if str(4) < row[11] < str(5):
                    all_data_dict[row[12]][4] += 1
            if row[13] == str(1):
                if str(4) < row[11] < str(5):
                    all_data_dict[row[12]][4] += 1
            if row[13] == str(2):
                if row[8] in DRM:
                    all_data_dict[row[12]][4] += 1

            # 555555555555555555555
            if row[13] == str(3):
                if row[8] in Android_Protected_Confirmation:
                    all_data_dict[row[12]][5] += 1
            if row[13] == str(4):
                if row[8] == "setUserConfirmationRequired":
                    all_data_dict[row[12]][5] += 1


def read_csv_file(root_tee, name1):
    with open(root_tee, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    with open(root_tee, 'r', encoding=encoding) as f:
        # 基于打开的文件，创建csv.reader实例
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if row[12] not in all_data_dict:
                all_data_dict[row[12]] = [name1, 0, 0, 0, 0, 0]


def write_csv_file_sha256(output_file):
    with open(output_file, 'w', newline='', encoding="utf-8-sig") as outfile:
        my_sha256_list = []
        writer = csv.writer(outfile)

        print("=================")
        header_list = ["包名", "类型", "Keystore", "Biometrics-based authentication", "GateKeeper", "DRM",
                       "Android_Protected_Confirmation", "TEE总数", "invoke总数"]
        # 新的csv文件写入标题header。
        writer.writerow(header_list)
        writer.writerows(list123)


# 求每一个app的invoke数量
def read_csv_file_invoke(root_invoke):
    with open(root_invoke, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    with open(root_invoke, 'r', encoding=encoding) as f:
        # 以读方式打开文件
        # 基于打开的文件，创建csv.reader实例
        reader = csv.reader(f)
        header = next(reader)
        # 逐行获取数据，并输出
        for row in reader:
            if row[0] not in dict_invoke:
                dict_invoke[row[0]] = int(row[2])
            else:
                dict_invoke[row[0]] += int(row[2])


def merge_invoke_TEE(name1):
    for asd in all_data_dict:
        temp = all_data_dict[asd][1] + all_data_dict[asd][2] + all_data_dict[asd][3] + all_data_dict[asd][4] + all_data_dict[asd][5]
        dict_final[asd] = [asd, all_data_dict[asd][0], all_data_dict[asd][1], all_data_dict[asd][2],
                           all_data_dict[asd][3], all_data_dict[asd][4], all_data_dict[asd][5], temp, dict_invoke[asd]]

        del dict_invoke[asd]
    for asd in dict_invoke:
        dict_final[asd] = [asd, name1, 0, 0, 0, 0, 0, 0, dict_invoke[asd]]


if __name__ == '__main__':
    # 初始化实例
    conf = configparser.ConfigParser()
    conf.read('config.ini')

    all_data_dict = {}
    repeat_data = {}
    repeat_data2 = {}
    # 包名 类别 KeyStore Biometrics-based-authentication  GateKeeper  DRM  Android_Protected_Confirmation
    root1 = conf.get('output_file', 'output_file_path_AKS').strip('"')
    print(root1)
    # 哪个类别
    name = conf.get('output_file', 'kind_name').strip('"')
    print(name)
    read_csv_file(root1, name)
    print(all_data_dict)
    print(len(all_data_dict))

    read_csv_file_TEE_KeyStore(root1)
    print(all_data_dict)
    print(len(all_data_dict))

    # 获取invoke数量
    root = conf.get('output_file', 'output_file_path_invoke').strip('"')
    dict_invoke = {}
    read_csv_file_invoke(root)
    print(dict_invoke)
    print(len(dict_invoke))

    # 合并invoke总数和TEE数量
    dict_final = {}
    merge_invoke_TEE(name)

    list123 = []
    # 加上TEE总数
    for name in dict_final:
        temp = [dict_final[name][0], dict_final[name][1], dict_final[name][2], dict_final[name][3],
                dict_final[name][4], dict_final[name][5], dict_final[name][6], dict_final[name][7], dict_final[name][8]]
        list123.append(temp)

    print(list123)
    print(len(list123))

    write_csv_file_sha256(conf.get('output_file', 'output_file_result').strip('"'))
