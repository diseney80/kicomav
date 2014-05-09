# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # ���� ������ ���� import
import hashlib # MD5 �ؽø� ���� import
import mmap
import kernel

#---------------------------------------------------------------------
# KavMain Ŭ����
# Ű�޹�� ���� ������� ��Ÿ���� Ŭ�����̴�.
# �� Ŭ������ ������ ��� ���� Ŀ�� ��⿡�� �ε����� �ʴ´�.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # �Ǽ��ڵ带 �˻��Ѵ�.
    # ���ڰ� : mmhandle         - ���� mmap �ڵ�
    #        : scan_file_struct - ���� ����ü
    #        : format           - �̸� �м��� ���� ����
    # ���ϰ� : (�Ǽ��ڵ� �߰� ����, �Ǽ��ڵ� �̸�, �Ǽ��ڵ� ID) ���
    #-----------------------------------------------------------------
    def scan(self, mmhandle, filename, deepname, format) :
        try : # ��� ������ ������ �����ϱ� ���� ���� ó���� ���� 
            mm = mmhandle # ���� mmap �ڵ��� mm�� ����

            buf = mm[0:2] # ���� ó������ 68 Byte�� ����

            if buf == 'va' : # buf�� 68 Byte�� ������?
                v_pattern = mm[0x14:0x14+11]

                if v_pattern == 'fnc = \'ev\';' :
                    # �´ٸ� �˻� ����� �̸�, ID�� ����
                    return (True, 'VIRUS-TEST', 0, kernel.INFECTED)
        except : # ��� ���ܻ����� ó��
            pass
        
        return (False, '', -1, kernel.NOT_FOUND)

    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # �Ǽ��ڵ带 ġ���Ѵ�.
    # ���ڰ� : filename   - ���� �̸�
    #        : malwareID  - ġ���� �Ǽ��ڵ� ID
    # ���ϰ� : �Ǽ��ڵ� ġ�� ����
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # �Ǽ��ڵ� ġ��
        try :
            # �Ǽ��ڵ� ���� ������� ���� ID ���� 0�ΰ�?
            if malwareID == 0 : 
                os.remove(filename) # ���� ����
                return True # ġ�� �Ϸ� ����
        except :
            pass

        return False # ġ�� ���� ����

    #-----------------------------------------------------------------
    # listvirus(self)
    # ����/ġ�� ������ �Ǽ��ڵ��� ����� �˷��ش�.
    #-----------------------------------------------------------------
    def listvirus(self) :
        vlist = [] # ����Ʈ�� ���� ����
        vlist.append('VIRUS-TEST') # �����ϴ� �Ǽ��ڵ� �̸� ���
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = 'Kei Choi' # ������
        info['version'] = '1.0'     # ����
        info['title'] = 'VIRUS-TEST Engine' # ���� ����
        info['kmd_name'] = 'script' # ���� ���ϸ�

        # ���� ������¥�� �ð��� ���ٸ� ���� �ð����� �ڵ� ����
        info['date']    = 0   # ���� ���� ��¥ 
        info['time']    = 0   # ���� ���� �ð� 
        info['sig_num'] = 1 # ���� ��
        return info