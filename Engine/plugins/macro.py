# -*- coding:utf-8 -*-

"""
Copyright (C) 2013 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

__revision__ = '$LastChangedRevision: 2 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import os # ���� ������ ���� import
import zlib
import hashlib
import struct, mmap
import kernel
import kavutil
import glob

# ��ũ�� Ÿ��
X95M = 1
X97M = 2
W95M = 3
W97M = 4

SIGTOOL = False

def IsPrint(char) :
    c = ord(char)
    if c > 0x20 and c < 0x80 :
        return True
    else :
        return False

def ExtractMacroData_W95M(data) :
    mac_data = None
    data_size = len(data)

    try :
        if data_size < 0x200 : raise SystemError
        
        version = struct.unpack('<H', data[2:2+2])[0]
        if version > 0xc0 : raise SystemError

        exist_macro = struct.unpack('<L', data[0x11C:0x11C+4])[0]
        if exist_macro <= 2 : raise SystemError

        mac_pos = struct.unpack('<L', data[0x118:0x118+4])[0]
        if ord(data[mac_pos]) != 0xFF : raise SystemError

        while ord(data[mac_pos + 1]) != 0x01 : # chHplmcd
            ch = ord(data[mac_pos + 1])

            val = struct.unpack('<H', data[mac_pos+2:mac_pos+4])[0]
            if   ch == 0x02 : mac_pos += val * 0x4 # chHplacd
            elif ch == 0x03 : mac_pos += val * 0xE # chHplkme
            elif ch == 0x04 : mac_pos += val * 0xE # chHplkmeBad
            elif ch == 0x05 : mac_pos += val * 0xC # chHplmud
            elif ch == 0x12 : mac_pos += 2         # chUnnamedToolbar
            elif ch == 0x40 : raise SystemError    # chTcgEnd
            else            : raise SystemError

            mac_pos += 3

        mac_num = struct.unpack('<H', data[mac_pos+2:mac_pos+4])[0]
        mac_pos += 4

        # print mac_num # ��ũ�� ����

        mac_info = 0 # ��ũ�� �ֿ� ���� ����

        all_code = []

        for i in range(mac_num) :
            if ord(data[mac_pos + (mac_info * 0x18)]) == 0x55 :
                pos = mac_pos + (mac_info * 0x18)
                w95m_key   = ord(data[pos + 1])
                w95m_len   = struct.unpack('<L', data[pos+0x0C:pos+0x0C+4])[0]
                w95m_pos   = struct.unpack('<L', data[pos+0x14:pos+0x14+4])[0]

                # print hex(w95m_key), hex(w95m_len), hex(w95m_pos)

                if w95m_key != 0 :
                    w95m_code = ''
                    for j in range(w95m_len) :
                        ch = ord(data[w95m_pos + j]) ^ w95m_key
                        w95m_code += chr(ch)
                else :
                    w95m_code = data[w95m_pos:w95m_pos + w95m_len]

                all_code.append(w95m_code)
                mac_info += 1

        mac_data = all_code
    except :
        pass

    return mac_data

def ExtractMacroData_X95M(data) :
    mac_data = None
    data_size = len(data)

    try :
        if data_size < 0x200 : raise SystemError
        if ord(data[0]) != 0x01 : raise SystemError

        mac_pos = struct.unpack('<L', data[10:10+4])[0]
        mac_pos += ( 14L + 14L )
        if data_size < mac_pos : raise SystemError

        t = struct.unpack('<L', data[mac_pos:mac_pos+4])[0]
        mac_pos += t + 28L + 18L - 14L;
        if data_size < mac_pos : raise SystemError

        mac_pos = struct.unpack('<L', data[mac_pos:mac_pos+4])[0]
        mac_pos += 0x3C
        if data_size < mac_pos : raise SystemError

        # ��ũ�� ���� ��ġ���� ����
        if ord(data[mac_pos]) != 0xFE or ord(data[mac_pos+1]) != 0xCA :
            raise SystemError

        # ��ũ�� �ҽ� �ڵ��� �� �� ���
        mac_lines = struct.unpack('<H', data[mac_pos+4:mac_pos+6])[0]
        if mac_lines == 0 : raise SystemError 

        mac_pos = mac_pos + 4L + (mac_lines * 12L)
        if data_size < mac_pos : raise SystemError
        
        mac_len = struct.unpack('<L', data[mac_pos+6:mac_pos+10])[0]
        mac_pos += 10

        # print 'ok :', hex(mac_pos), mac_lines, mac_len

        # ��ũ�� ��� ���� ����
        if data_size < (mac_pos + mac_len) : raise SystemError
        mac_data = data[mac_pos:mac_pos + mac_len]

    except :
        pass

    return mac_data


def ExtractMacroData_Macro97(data) :
    mac_data = None
    data_size = len(data)

    try :
        if data_size < 0x200 : raise SystemError
        if ord(data[0]) != 0x01 : raise SystemError # ��ũ�� �ƴ�

        if ord(data[9]) == 0x01 and ord(data[10]) == 0x01 :
            # ���� 97 or ���� 97
            mac_pos  = struct.unpack('<L', data[0xB:0xB+4])[0] + 0x4F
            mac_pos += (struct.unpack('<H', data[mac_pos:mac_pos+2])[0] * 16) + 2
            mac_pos += struct.unpack('<L', data[mac_pos:mac_pos+4])[0] + 10
            mac_pos += struct.unpack('<L', data[mac_pos:mac_pos+4])[0] + 81
            mac_pos  = struct.unpack('<L', data[mac_pos:mac_pos+4])[0] + 60
        else :
            # ���� 2000 or ���� 2000 �̻�
            mac_pos = struct.unpack('<L', data[25:25+4])[0]
            mac_pos = (mac_pos - 1) + 0x3D

        if ord(data[mac_pos]) != 0xFE or ord(data[mac_pos+1]) != 0xCA :
            raise SystemError

        mac_lines = struct.unpack('<H', data[mac_pos+4:mac_pos+6])[0]
        if mac_lines == 0 : raise SystemError 

        mac_pos = mac_pos + 6L + (mac_lines * 12L);

        Len = struct.unpack('<L', data[mac_pos+6:mac_pos+10])[0]
        Off = mac_pos + 10

        '''
        print 'Macro off :', hex(Off)
        print 'Macro len :', Len

        fp = open('w97m.dmp', 'wb')
        fp.write(data[Off:Off+Len])
        fp.close()
        '''

        mac_data = data[Off:Off+Len]
    except :
        pass

    return mac_data


def GetMD5_Macro(data, target_macro) :
    global SIGTOOL

    ret = None

    try :
        max = 0
        buf = ''

        for i in range(len(data)) :
            c = data[i]
            if IsPrint(c) :
                max += 1
            else :
                if max > 3 :
                    if SIGTOOL == True :
                        print data[i-max:i] # ���� ������ ���� (sigtool)
                    buf += data[i-max:i]
                max = 0

        md5 = hashlib.md5()
        md5.update(buf)
        fmd5 = md5.hexdigest().decode('hex')

        if SIGTOOL == True :
            str_macro = ['', 'x95m', 'x97m', 'w95m', 'w97m']
            print '[%s] %s:%s:%s:' % (str_macro[target_macro], len(buf), md5.hexdigest(), len(data)) # ���� ���� (sigtool)

        ret = (len(buf), fmd5, len(data))
    except :
        pass

    return ret



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
        try :
            self.plugins = plugins
            self.x95m_ptn   = []
            self.x95m_iptn  = {}
            self.x97m_ptn   = []
            self.x97m_iptn  = {}
            self.w95m_ptn   = []
            self.w95m_iptn  = {}
            self.w97m_ptn   = []
            self.w97m_iptn  = {}
            self.__signum__ = 0
            self.__date__   = 0
            self.__time__   = 0
            self.max_date   = 0

            if self.__LoadDB__(X95M) == 1 : raise SystemError
            if self.__LoadDB__(X97M) == 1 : raise SystemError
            if self.__LoadDB__(W95M) == 1 : raise SystemError
            if self.__LoadDB__(W97M) == 1 : raise SystemError

            return 0
        except :
            pass

            return 1

    def __LoadDB__(self, target_macro) : # ��� ��� �ʱ�ȭ
        try :
            vdb = kavutil.VDB()

            if target_macro   == X95M : ptn_name = 'x95m'
            elif target_macro == X97M : ptn_name = 'x97m'
            elif target_macro == W95M : ptn_name = 'w95m'
            elif target_macro == W97M : ptn_name = 'w97m'

            flist = glob.glob(self.plugins + os.sep + ptn_name + '.c*')
            for i in range(len(flist)) :
                fname = flist[i]
                
                # ���� �ε�
                ptn_data = vdb.Load(fname)
                if ptn_data == None : # ���� �ε� ����
                    return 1

                if target_macro   == X95M : self.x95m_ptn.append(ptn_data)
                elif target_macro == X97M : self.x97m_ptn.append(ptn_data)
                elif target_macro == W95M : self.w95m_ptn.append(ptn_data)
                elif target_macro == W97M : self.w97m_ptn.append(ptn_data)

                self.__signum__ += vdb.GetSigNum()

                # �ֽ� ��¥ ���ϱ�
                t_d = vdb.GetDate()
                t_t = vdb.GetTime()

                t_date = (t_d << 16) + t_t
                if self.max_date < t_date :
                    self.__date__ = t_d
                    self.__time__ = t_t
                    self.max_date = t_date

            return 0
        except :
            return 1

    #-----------------------------------------------------------------
    # uninit(self)
    # ��� ���� ����� ����ȭ �۾��� �����Ѵ�.
    #-----------------------------------------------------------------
    def uninit(self) : # ��� ��� ����ȭ
        return 0
    
    #-----------------------------------------------------------------
    # scan(self, filehandle, filename)
    # �Ǽ��ڵ带 �˻��Ѵ�.
    # ���ڰ� : mmhandle         - ���� mmap �ڵ�
    #        : scan_file_struct - ���� ����ü
    #        : format           - �̸� �м��� ���� ����
    # ���ϰ� : (�Ǽ��ڵ� �߰� ����, �Ǽ��ڵ� �̸�, �Ǽ��ڵ� ID) ���
    #-----------------------------------------------------------------
    def scan(self, mmhandle, filename, deepname, format) :
        global SIGTOOL

        ret = None
        scan_state = kernel.NOT_FOUND

        try :
            section_name = deepname
            data = mmhandle[:] # ���� ��ü ����

            # _VBA_PROJECT/xxxx �� �����ϴ� ��Ʈ���� ����95 ��ũ�ΰ� �����Ѵ�.
            if section_name.find(r'_VBA_PROJECT/') != -1 :
                ret = self.__ScanVirus_X95M__(data)
                target = 'MSExcel'
            # _VBA_PROJECT_CUR/xxxx �� �����ϴ� ��Ʈ���� ����97 ��ũ�ΰ� �����Ѵ�.
            elif section_name.find(r'_VBA_PROJECT_CUR/') != -1 :
                ret = self.__ScanVirus_Macro97__(data, X97M)
                target = 'MSExcel'
            # WordDocument ��Ʈ���� ����95 ��ũ�ΰ� �����Ѵ�.
            elif section_name.find('WordDocument') != -1 :
                ret = self.__ScanVirus_W95M__(data)
                target = 'MSWord'
            # Macros/xxxx �� �����ϴ� ��Ʈ���� ����97 ��ũ�ΰ� �����Ѵ�.
            elif section_name.find('Macros/') != -1 :
                ret = self.__ScanVirus_Macro97__(data, W97M)
                target = 'MSWord'

            if ret != None :
                scan_state, s, i_num, i_list = ret

                # ���̷��� �̸� ����
                if s[0:2] == 'V.' :
                    s = 'Virus.%s.%s' % (target, s[2:])
                elif s[0:2] == 'J.' :
                    s = 'Joke.%s.%s' % (target, s[2:])

                # �Ǽ��ڵ� ������ ���ٸ� ��� ���� �����Ѵ�.
                return (True, s, 0, scan_state)
        except :
            pass

        # �Ǽ��ڵ带 �߰����� �������� �����Ѵ�.
        return (False, '', -1, kernel.NOT_FOUND)

    def __ScanVirus_W95M__(self, data) :
        ret = None

        try :
            mac_data = ExtractMacroData_W95M(data)
            if mac_data == None : raise SystemError

            for data in mac_data :
                hash_data = GetMD5_Macro(data, W95M)
                ret = self.__ScanVirus_Macro_ExpendDB__(hash_data, W95M)
                if ret != None : return ret
        except :
            pass

        return ret

    def __ScanVirus_X95M__(self, data) :
        ret = None

        try :
            mac_data = ExtractMacroData_X95M(data)
            if mac_data == None : raise SystemError

            hash_data = GetMD5_Macro(mac_data, X95M)
            ret = self.__ScanVirus_Macro_ExpendDB__(hash_data, X95M)
        except :
            pass

        return ret


    def __ScanVirus_Macro97__(self, data, target_macro) :
        ret = None

        try :
            mac_data = ExtractMacroData_Macro97(data)
            if mac_data == None : raise SystemError

            hash_data = GetMD5_Macro(mac_data, target_macro)
            ret = self.__ScanVirus_Macro_ExpendDB__(hash_data, target_macro)
        except :
            pass

        return ret


    def __ScanVirus_Macro_ExpendDB__(self, hash_data, target_macro) :
        ret = None

        try :
            fsize    = hash_data[0] # md5�� ������ ������ ũ��
            fmd5     = hash_data[1] # md5
            mac_size = hash_data[2] # ���� ��ũ�� ũ��

            # ���� ��
            i_num = -1

            if   target_macro == X95M : macro_ptn = self.x95m_ptn
            elif target_macro == X97M : macro_ptn = self.x97m_ptn
            elif target_macro == W95M : macro_ptn = self.w95m_ptn
            elif target_macro == W97M : macro_ptn = self.w97m_ptn

            for i in range(len(macro_ptn)) :
                vpattern = macro_ptn[i]

                try :
                    t = vpattern[fsize] # ���� �߿� ���� ũ��� �� MD5�� �����ϳ�?

                    # MD5�� 6�ڸ� ������ ��ġ�ϴ��� ����
                    id = t[fmd5[0:6]]

                    # ������ 10�ڸ��� ���ؾ� ��
                    i_num = id[0]   # x95m.iXX ���Ͽ�..
                    i_list = id[1]  # ���° ����Ʈ���� �˰� ��
                except :
                    pass

                if i_num != -1 : # MD5 6�ڸ��� ��ġ�ϴ� ���� �߰� �Ǿ��ٸ�
                    try :
                        if target_macro == X95M :
                            e_vlist = self.x95m_iptn[i_num]
                        elif target_macro == X97M :
                            e_vlist = self.x97m_iptn[i_num]
                        elif target_macro == W95M :
                            e_vlist = self.w95m_iptn[i_num]
                        elif target_macro == W97M :
                            e_vlist = self.w97m_iptn[i_num]
                    except :
                        if   target_macro == X95M : ptn_name = 'x95m'
                        elif target_macro == X97M : ptn_name = 'x97m'
                        elif target_macro == W95M : ptn_name = 'w95m'
                        elif target_macro == W97M : ptn_name = 'w97m'

                        fname = '%s%s%s.i%02d' % (self.plugins, os.sep,ptn_name,  i_num)
                        vdb = kavutil.VDB() # ���� �ε�
                        e_vlist = vdb.Load(fname)

                    if e_vlist != None :
                        if   target_macro == X95M : self.x95m_iptn[i_num] = e_vlist
                        elif target_macro == X97M : self.x97m_iptn[i_num] = e_vlist
                        elif target_macro == W95M : self.w95m_iptn[i_num] = e_vlist
                        elif target_macro == W97M : self.w97m_iptn[i_num] = e_vlist

                        p_md5_10 = e_vlist[i_list][0] # MD5 10�ڸ�
                        p_mac_size = int(e_vlist[i_list][1]) # ��ũ�� ũ�� 
                        p_vname = e_vlist[i_list][2]  # ���̷��� �̸�

                        if (p_md5_10 == fmd5[6:]) and (p_mac_size == mac_size) : # ��� ��ġ
                            ret = (kernel.INFECTED, p_vname, i_num, i_list)
                        elif p_md5_10 == fmd5[6:] : # md5�� ��ġ
                            s = p_vname + '.Gen'
                            ret = (kernel.SUSPECT, s, i_num, i_list)
        except :
            pass

        return ret
    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # �Ǽ��ڵ带 ġ���Ѵ�.
    # ���ڰ� : filename   - ���� �̸�
    #        : malwareID  - ġ���� �Ǽ��ڵ� ID
    # ���ϰ� : �Ǽ��ڵ� ġ�� ����
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # �Ǽ��ڵ� ġ��
        try :
            '''
            # �Ǽ��ڵ� ���� ������� ���� ID ���� 0�ΰ�?
            if malwareID == 0 : 
                os.remove(filename) # ���� ����
                return True # ġ�� �Ϸ� ����
            '''
        except :
            pass

        return False # ġ�� ���� ����

    #-----------------------------------------------------------------
    # listvirus(self)
    # ����/ġ�� ������ �Ǽ��ڵ��� ����� �˷��ش�.
    #-----------------------------------------------------------------
    def listvirus(self) : # ���� ������ �Ǽ��ڵ� ���
        vlist = [] # ����Ʈ�� ���� ����
        vlist.append('Virus.MSExcel.Laroux.A') 
        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = __author__    # ������
        info['version'] = __version__  # ����
        info['title'] = 'Macro Engine' # ���� ����
        info['kmd_name'] = 'macro'     # ���� ���ϸ�

        # ���� ������¥�� �ð��� ���ٸ� ���� �ð����� �ڵ� ����
        info['date']    = self.__date__   # ���� ���� ��¥ 
        info['time']    = self.__time__   # ���� ���� �ð� 
        info['sig_num'] = self.__signum__ # ���� ��
        return info

