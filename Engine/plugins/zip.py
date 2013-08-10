# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

import os # ���� ������ ���� import
import zipfile
import tempfile
import kernel

#---------------------------------------------------------------------
# KavMain Ŭ����
# Ű�޹�� ���� ������� ��Ÿ���� Ŭ�����̴�.
# �� Ŭ������ ������ ��� ���� Ŀ�� ��⿡�� �ε����� �ʴ´�.
#---------------------------------------------------------------------
class KavMain :
    #-----------------------------------------------------------------
    # init(self, plugins)
    # ��� ���� ����� �ʱ�ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def init(self, plugins) : # ��� ��� �ʱ�ȭ
        return 0

    #-----------------------------------------------------------------
    # uninit(self)
    # ��� ���� ����� ����ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def uninit(self) : # ��� ��� ����ȭ
        return 0
    
    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = 'Kei Choi' # ������
        info['version'] = '1.0'     # ����
        info['title'] = 'Zip Engine' # ���� ����
        info['kmd_name'] = 'zip' # ���� ���ϸ�
        info['engine_type'] = kernel.ARCHIVE_ENGINE # ���� Ÿ��
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # ���� ������ ���� ����

            mm = mmhandle
            if mm[0:2] == 'PK' : # ��� üũ
                fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_zip'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def arclist(self, scan_file_struct, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����
        deep_name = ''

        try :
            fformat = format['ff_apk'] # APK ������ �����ϳ�?
            return file_scan_list # APK �����̸� ó�� �� �ʿ� ����
        except :
            pass # APK ������ ������ ZIP ���� ó��

        try :
            # �̸� �м��� ���� �����߿� ZIP ������ �ִ°�?
            fformat = format['ff_zip']

            filename = scan_file_struct['real_filename']
            deep_name = scan_file_struct['deep_filename']
                
            zfile = zipfile.ZipFile(filename)
            for name in zfile.namelist() :
                file_info = {}  # ���� �Ѱ��� ����

                if len(deep_name) != 0 :
                    dname = '%s/%s' % (deep_name, name)
                else :
                    dname = '%s' % (name)

                file_info['is_arc'] = True # ���� ����
                file_info['arc_engine_name'] = 'arc_zip' # ���� ���� ���� ���� ID
                file_info['arc_filename'] = filename # ���� ���� ����
                file_info['arc_in_name'] = name #�������� ��� ����
                file_info['real_filename'] = '' # �˻� ��� ����
                file_info['deep_filename'] = dname  # ���� ������ ���θ� ǥ���ϱ� ���� ���ϸ�
                file_info['display_filename'] = scan_file_struct['display_filename'] # ��¿�

                file_scan_list.append(file_info)
            zfile.close()
        except :
            pass

        return file_scan_list

    def unarc(self, scan_file_struct) :
        try :
            if scan_file_struct['is_arc'] != True : 
                raise SystemError

            if scan_file_struct['arc_engine_name'] != 'arc_zip' :
                raise SystemError

            arc_name = scan_file_struct['arc_filename']
            filename = scan_file_struct['arc_in_name']

            zfile = zipfile.ZipFile(arc_name)
            data = zfile.read(filename)
            zfile.close()

            # ������ �����Ͽ� �ӽ� ������ ����
            rname = tempfile.mktemp(prefix='ktmp')
            fp = open(rname, 'wb')
            fp.write(data)
            fp.close()

            scan_file_struct['real_filename'] = rname

            return scan_file_struct
        except :
            pass

        return None
