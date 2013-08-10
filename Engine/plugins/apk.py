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
        info['title'] = 'APK Engine' # ���� ����
        info['kmd_name'] = 'apk' # ���� ���ϸ�
        info['engine_type'] = kernel.ARCHIVE_ENGINE # ���� Ÿ��

        # ���� ������¥�� �ð��� ���ٸ� ���� �ð����� �ڵ� ����
        info['date']    = 0   # ���� ���� ��¥ 
        info['time']    = 0   # ���� ���� �ð� 
        info['sig_num'] = 1 # ���� ��

        return info

    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # �Ǽ��ڵ带 �˻��Ѵ�.
    # ���ڰ� : mmhandle         - ���� mmap �ڵ�
    #        : scan_file_struct - ���� ����ü
    #        : format           - �̸� �м��� ���� ����
    # ���ϰ� : (�Ǽ��ڵ� �߰� ����, �Ǽ��ڵ� �̸�, �Ǽ��ڵ� ID) ���
    #-----------------------------------------------------------------
    def scan(self, mmhandle, scan_file_struct, format) :
        ret_value = {}
        ret_value['result']     = False # ���̷��� �߰� ����
        ret_value['virus_name'] = ''    # ���̷��� �̸�
        ret_value['scan_state'] = kernel.NOT_FOUND     # 0:����, 1:����, 2:�ǽ�, 3:���
        ret_value['virus_id']   = -1    # ���̷��� ID

        try :
            # �̸� �м��� ���� �����߿� Dummy ������ �ִ°�?
            fformat = format['ff_apk']

            filename = scan_file_struct['real_filename']

            zfile = zipfile.ZipFile(filename)

            count = 0
            infolist = zfile.infolist()
            for l in infolist :
                fname = l.filename.lower()
                if fname == 'classes.dex' :
                    count += 1
                else :
                    continue

            zfile.close()

            # classes.dex�� �Ѱ� �̻��̸� ������� �����Ѵ�.
            if count > 1 :
                # �Ǽ��ڵ� ������ ���ٸ� ��� ���� �����Ѵ�.
                ret_value['result']     = True            # ���̷��� �߰� ����
                ret_value['virus_name'] = 'Exploit.Android.MasterKey.A' # ���̷��� �̸�
                ret_value['scan_state'] = kernel.INFECTED# 0:����, 1:����, 2:�ǽ�, 3:���
                ret_value['virus_id']   = 0               # ���̷��� ID
                return ret_value
        except :
            pass

        # �Ǽ��ڵ带 �߰����� �������� �����Ѵ�.
        return ret_value

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
    def listvirus(self) : # ���� ������ �Ǽ��ڵ� ���
        vlist = [] # ����Ʈ�� ���� ����
        vlist.append('Exploit.Android.MasterKey.A') # �����ϴ� �Ǽ��ڵ� �̸� ���
        return vlist

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # ���� ������ ���� ����

            mm = mmhandle
            if mm[0:2] == 'PK' : # ��� üũ
                if zipfile.is_zipfile(filename) == False :
                    raise SystemError

                zfile = zipfile.ZipFile(filename)
                zfile.getinfo('classes.dex') # classes.dex �� �����ϳ�?
                zfile.getinfo('AndroidManifest.xml') # AndroidManifest.xml �����ϳ�?
                zfile.close()

                fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_apk'] = fformat

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
            # �̸� �м��� ���� �����߿� APK ������ �ִ°�?
            fformat = format['ff_apk']

            filename = scan_file_struct['real_filename']
            deep_name = scan_file_struct['deep_filename']
                
            zfile = zipfile.ZipFile(filename)

            apk_list = []
            infolist = zfile.infolist()
            for l in infolist :
                fname = l.filename.lower()
                if fname == 'classes.dex' or fname == 'androidmanifest.xml' :
                    name = l.filename
                    arc_engine_name = 'arc_apk!%d' % infolist.index(l)
                else :
                    continue

                file_info = {}  # ���� �Ѱ��� ����

                if len(deep_name) != 0 :
                    dname = '%s/%s' % (deep_name, name)
                else :
                    dname = '%s' % (name)

                file_info['is_arc'] = True # ���� ����
                file_info['arc_engine_name'] = arc_engine_name # ���� ���� ���� ���� ID
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

            arc_id = scan_file_struct['arc_engine_name']
            if arc_id[0:7] != 'arc_apk' :
                raise SystemError

            id = int(arc_id[8:]) # ������ �����ϴ� ZIP ID
            if id <= 0 : 
                raise SystemError

            arc_name = scan_file_struct['arc_filename']
            filename = scan_file_struct['arc_in_name']

            # id�� temp ������ ���� ����
            tempdir = tempfile.gettempdir()

            zfile = zipfile.ZipFile(arc_name)
            l = zfile.infolist()
            zfile.extract(l[id], tempdir)
            zfile.close()

            # ���� ������ ���� �̸� ����
            rname = tempfile.mktemp(prefix='ktmp')
            os.rename(tempdir + os.sep + filename, rname)

            scan_file_struct['real_filename'] = rname

            return scan_file_struct
        except :
            pass

        return None
