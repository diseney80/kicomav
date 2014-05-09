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

__revision__ = '$LastChangedRevision: 1 $'
__author__   = 'Kei Choi'
__version__  = '1.0.0.%d' % int( __revision__[21:-2] )
__contact__  = 'hanul93@gmail.com'


import os # ���� ������ ���� import
import kernel
import pefile # PE ���� ������ ���� import
import hashlib
import struct

TARGET_EP      = 0
TARGET_SECTION = 0x80

def int32(iv) :
    if iv & 0x80000000 :
        iv = -0x100000000 + iv
    return iv   

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
        self.pattern = [ \
        #['Notepad (not a virus)', [TARGET_EP, 0x80, 0x1A9393CF], [TARGET_SECTION+0, 0x000003A0, 0x80, 0xE6829D78]]
        ]
        return 0

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
        try : # ��� ������ ������ �����ϱ� ���� ���� ó���� ���� 
            # �̸� �м��� ���� �����߿� pe ������ �ִ°�?
            fformat = format['ff_pe']

            mm = mmhandle # ���� mmap �ڵ��� mm�� ����

            file_pattern_1st = {}

            # EP���� ������ ����
            offset = fformat['pe']['EntryPointRaw']
            # print hex(offset)

            file_pattern_1st[TARGET_EP] = self.__MakePattern__(mm, offset)

            # �� ���ǿ��� ������ ����
            sections = fformat['pe']['Sections']
             
            for i in range(fformat['pe']['SectionNumber']) :
                section = sections[i]
                offset  = section['PointerRawData']
                file_pattern_1st[TARGET_SECTION+i] = self.__MakePattern__(mm, offset)

            # print hex(file_pattern_1st[TARGET_EP][0x80])

            # 1�� ���� ��
            for p in self.pattern :
                vname   = p[0]
                ptn_1st = p[1]
                ptn_2nd = p[2]

                target  = ptn_1st[0] # 1�� ���� ��ġ 
                size    = ptn_1st[1] # 1�� ���� ũ��
                ptn_crc = ptn_1st[2] # 1�� ���� ũ��

                # 1�� ���� ��ġ������ ���� ���� ��
                if file_pattern_1st[target][size] != ptn_crc : 
                    continue

                #2�� ���� ��
                target  = ptn_2nd[0] # 2�� ���� ��ġ 
                pos     = ptn_2nd[1] # 2�� ���� ��ġ 
                size    = ptn_2nd[2] # 2�� ���� ũ��
                ptn_crc = ptn_2nd[3] # 2�� ���� ũ��

                if target == TARGET_EP :
                    offset = fformat['pe']['EntryPointRaw']
                elif target >= TARGET_SECTION :
                    nSec = target - TARGET_SECTION
                    section = sections[nSec]
                    offset  = section['PointerRawData']
                else :
                    raise SystemError

                offset = int32(offset + pos)

                # 2�� ���� ��ġ�Ѵٸ� 
                crc32 = self.__k2crc32__(mm, offset, size)
                '''
                print hex(offset)
                print hex(size)
                print hex(crc32)
                print hex(ptn_crc)
                '''
                if self.__k2crc32__(mm, offset, size) == ptn_crc :
                    # �´ٸ� �˻� ����� �̸�, ID�� ����
                    return (True, vname, 0, kernel.INFECTED)
        except : # ��� ���ܻ����� ó��
            pass

        # �Ǽ��ڵ带 �߰����� �������� �����Ѵ�.
        return (False, '', -1, kernel.NOT_FOUND)

    def __MakePattern__(self, mm, offset) :
        pos = [0x10, 0x20, 0x40, 0x80]
        pattern = {}

        # �ʱ�ȭ
        for i in pos : pattern[i] = 0

        try :
            # ���� ����
            for i in pos :
                pattern[i] = self.__k2crc32__(mm, offset, i)
        except :
            pass

        return pattern
        
    def __k2crc32__(self, data, offset, size) :
        try :
                data = data[offset:offset + size]
                '''
                for i in range(len(data)) :
                    s = '%02X' % ord(data[i])
                    print s,
                print
                '''
                md5 = hashlib.md5()
                md5.update(data)
                fmd5 = md5.digest()

                crc1 = struct.unpack('<L', fmd5[ 0: 4])[0]
                crc2 = struct.unpack('<L', fmd5[ 4: 8])[0]
                crc3 = struct.unpack('<L', fmd5[ 8:12])[0]
                crc4 = struct.unpack('<L', fmd5[12:16])[0]
        except :
            return 0

        return (crc1 ^ crc2 ^ crc3 ^ crc4)

    #-----------------------------------------------------------------
    # disinfect(self, filename, malwareID)
    # �Ǽ��ڵ带 ġ���Ѵ�.
    # ���ڰ� : filename   - ���� �̸�
    #        : malwareID  - ġ���� �Ǽ��ڵ� ID
    # ���ϰ� : �Ǽ��ڵ� ġ�� ����
    #-----------------------------------------------------------------
    def disinfect(self, filename, malwareID) : # �Ǽ��ڵ� ġ��
        return False # ġ�� ���� ����

    #-----------------------------------------------------------------
    # listvirus(self)
    # ����/ġ�� ������ �Ǽ��ڵ��� ����� �˷��ش�.
    #-----------------------------------------------------------------
    def listvirus(self) :
        vlist = [] # ����Ʈ�� ���� ����

        return vlist

    #-----------------------------------------------------------------
    # getinfo(self)
    # ��� ���� ����� �ֿ� ������ �˷��ش�. (����, ������...)
    #-----------------------------------------------------------------
    def getinfo(self) :
        info = {} # ������ ���� ����
        info['author'] = __author__   # ������
        info['version'] = __version__ # ����
        info['title'] = 'COFF Engine' # ���� ����
        info['kmd_name'] = 'coff'     # ���� ���ϸ�

        
        # ���� ������¥�� �ð��� ���ٸ� ���� �ð����� �ڵ� ����
        info['date']    = 0   # ���� ���� ��¥ 
        info['time']    = 0   # ���� ���� �ð� 
        info['sig_num'] = len(self.pattern) # ���� ��
        
        return info

