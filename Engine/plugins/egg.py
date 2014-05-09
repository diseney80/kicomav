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

import struct
import mmap
import zlib
import bz2
import kernel

#---------------------------------------------------------------------
# EggFile Ŭ����
#---------------------------------------------------------------------
SIZE_EGG_HEADER = 14

COMPRESS_METHOD_STORE   = 0
COMPRESS_METHOD_DEFLATE = 1
COMPRESS_METHOD_BZIP2   = 2
COMPRESS_METHOD_AZO     = 3
COMPRESS_METHOD_LZMA    = 4

class EggFile :
    #-----------------------------------------------------------------
    # __init__(self, filename)
    # ������ ������ Egg ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def __init__(self, filename) :
        self.fp = None
        self.mm = None

        try :
            self.fp = open(filename, 'rb') 
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        except :
            pass

    #-----------------------------------------------------------------
    # def close(self)
    # EGG ������ �ݴ´�.
    #-----------------------------------------------------------------
    def close(self) :
        if self.mm != None : self.mm.close()
        if self.fp != None : self.fp.close()

    #-----------------------------------------------------------------
    # read(self, filename)
    # EGG ���� ������ ������ ���� �����Ѵ�.
    # ���ϰ� : ���� ������ data ��Ʈ��
    #-----------------------------------------------------------------
    def read(self, filename) :
        ret_data = None

        try :
            fname = self.__FindFirstFileName__()
            while fname != None :
                if fname == filename :
                    # print fname, '{OK]'

                    data, method, self.egg_pos = self.__ReadBlockData__()
                    if   method == COMPRESS_METHOD_STORE :
                        ret_data = data
                        break
                    elif method == COMPRESS_METHOD_DEFLATE :
                        ret_data = zlib.decompress(data, -15)
                        break
                    elif method == COMPRESS_METHOD_BZIP2 :
                        ret_data = bz2.decompress(data)
                        break
                    else :
                        # print method
                        pass

                fname = self.__FindNextFileName__()
        except :
            pass

        return ret_data

    #-----------------------------------------------------------------
    # namelist(self)
    # EGG ���� ������ ���ϸ��� �����Ѵ�.
    # ���ϰ� : EGG ���� ������ ���� ���ϸ��� ���� ����Ʈ
    #-----------------------------------------------------------------
    def namelist(self) :
        name_list = []
        ret_data = None

        try :
            fname = self.__FindFirstFileName__()
            while fname != None :
                name_list.append(fname)
                fname = self.__FindNextFileName__()
        except :
            pass

        return name_list

    #-----------------------------------------------------------------
    # EggFile Ŭ������ ���� ��� �Լ���
    #-----------------------------------------------------------------

    #-----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Egg ���� ���ο� ����� ���ϸ��� ù��° �̸��� ���´�.
    # ���ϰ� : ����� ù��° ���ϸ�
    #-----------------------------------------------------------------
    def __FindFirstFileName__(self) :
        self.egg_pos = 0

        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    #-----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Egg ���� ���ο� ����� ���ϸ��� ���� �̸��� ���´�.
    # ���ϰ� : ����� ���� ���ϸ�
    #-----------------------------------------------------------------
    def __FindNextFileName__(self) :
        fname, self.egg_pos = self.__GetFileName__(self.egg_pos)

        return fname

    #-----------------------------------------------------------------
    # __GetFileName__(self, egg_pos)
    # �־��� ��ġ ���ķ� Filename Header�� ã�� �м��Ѵ�.
    # ���ϰ� : Filename Header���� ���ϸ�, ���� ��ġ
    #-----------------------------------------------------------------
    def __GetFileName__(self, egg_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            while egg_pos < data_size :
                Magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]

                if Magic == 0x0A8591AC : # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                    return fname, egg_pos
                else :
                    egg_pos = self.__DefaultMagicIDProc__(Magic, egg_pos)
                    if egg_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __ReadBlockData__(self)
    # ���� ��ġ�������� Block Header�� ã�� �м��Ѵ�.
    # ���ϰ� : ����� data ��Ʈ��, ���� ���, ���� ��ġ
    #-----------------------------------------------------------------
    def __ReadBlockData__(self) :
        egg_pos      = self.egg_pos
        mm           = self.mm
        data_size    = len(mm)

        try :
            while egg_pos < data_size :
                Magic = struct.unpack('<L', mm[egg_pos:egg_pos+4])[0]

                if Magic == 0x02B50C13 : # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    Compress_Method_M = ord(mm[egg_pos+4])
                    Compress_Method_H = ord(mm[egg_pos+5])
                    Uncompress_Size   = struct.unpack('<L', mm[egg_pos+6:egg_pos+10])[0]
                    Compress_Size     = struct.unpack('<L', mm[egg_pos+10:egg_pos+14])[0]
                    CRC               = struct.unpack('<L', mm[egg_pos+14:egg_pos+18])[0]
                    Compressed_Data   = mm[egg_pos+22:egg_pos+22+Compress_Size]
                    egg_pos += size
                    return Compressed_Data, Compress_Method_M, egg_pos
                else :
                    egg_pos = self.__DefaultMagicIDProc__(Magic, egg_pos)
                    if egg_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1, -1

    #-----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, egg_pos)
    # �־��� ��ġ�� Magic�� �м��ϰ� �Ľ��Ѵ�.
    # ���ϰ� : ���� Magic�� ��ġ
    #-----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, Magic, egg_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            if egg_pos < data_size :
                if   Magic == 0x41474745 : # EGG Header
                    # print 'EGG Header'
                    if self.__EGG_Header__(mm) == -1 : raise SystemError # ��� üũ
                    egg_pos += (SIZE_EGG_HEADER)
                elif Magic == 0x0A8590E3 : # File Header
                    # print 'File Header'
                    egg_pos += 16
                elif Magic == 0x02B50C13 : # Block Header
                    # print 'Block Header'
                    size = self.__EGG_Block_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x08D1470F : # Encrypt Header
                    # print 'Encrypt Header'
                    size = self.__EGG_Encrypt_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x2C86950B : # Windows File Information
                    # print 'Windows File Information'
                    egg_pos += 16
                elif Magic == 0x1EE922E5 : # Posix File Information
                    # print 'Posix File Information'
                    egg_pos += 27
                elif Magic == 0x07463307 : # Dummy Header
                    size = self.__EGG_Dummy_Header_Size__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x0A8591AC : # Filename Header
                    # print 'Filename Header'
                    size, fname = self.__EGG_Filename_Header__(mm[egg_pos:])
                    if size == -1 : raise SystemError
                    egg_pos += size
                elif Magic == 0x04C63672 : # Comment Header
                    # print 'Comment Header'
                    raise SystemError # �� �������� ���� �ȵ�
                elif Magic == 0x24F5A262 : # Split Compression
                    # print 'Split Compression'
                    egg_pos += 15
                elif Magic == 0x24E5A060 : # Solid Compression
                    # print 'Solid Compression'
                    egg_pos += 7
                elif Magic == 0x08E28222 : # End of File Header
                    # print 'End of File Header'
                    egg_pos += 4
                else :
                    # print 'Not Support Header :', hex(egg_pos)
                    raise SystemError
        except :
            return -1

        return egg_pos

    #-----------------------------------------------------------------
    # __EGG_Header__(self, data)
    # Egg ������ ����� �м��Ѵ�.
    # ���ϰ� : 0 (����), -1(����)
    #-----------------------------------------------------------------
    def __EGG_Header__(self, data) :
        try :
            Magic = struct.unpack('<L', data[0:4])[0]
            if Magic != 0x41474745 : raise SystemError

            Version = struct.unpack('<H', data[4:6])[0]
            if Version != 0x0100 : raise SystemError

            HeaderID = struct.unpack('<L', data[6:10])[0]
            if HeaderID == 0 : raise SystemError

            Reserved = struct.unpack('<L', data[10:14])[0]
            if Reserved != 0 : raise SystemError

            return 0
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Encrypt_Header_Size__(self, data)
    # Egg ������ Encrypt Header�� �м��Ͽ� ��� ũ�⸦ ���Ѵ�.
    # ���ϰ� : Encrypt Header ũ��
    #-----------------------------------------------------------------
    def __EGG_Encrypt_Header_Size__(self, data) :
        try :
            Encrypt_Method = ord(data[7])
            if   Encrypt_Method == 0 :
                return (4 + 1 + 2 + 1 + 12 + 4)
            elif Encrypt_Method == 1 :
                return (4 + 1 + 2 + 1 + 10 + 10)
            elif Encrypt_Method == 2 :
                return (4 + 1 + 2 + 1 + 18 + 10)
            else :
                raise SystemError
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Dummy_Header_Size__(self, data)
    # Egg ������ Dummy Header�� �м��Ͽ� ��� ũ�⸦ ���Ѵ�.
    # ���ϰ� : Dummy Header ũ��
    #-----------------------------------------------------------------
    def __EGG_Dummy_Header_Size__(self, data) :
        try :
            Dummy_Size = struct.unpack('<H', data[5:7])[0]
            return (5 + 2 + Dummy_Size)
        except :
            pass

        return -1

    #-----------------------------------------------------------------
    # __EGG_Filename_Header__(self, data)
    # Egg ������ Filename Header�� �м��Ͽ� ��� ũ�⸦ ���Ѵ�.
    # ���ϰ� : Filename Header ũ��, ����� ���ϸ�
    #-----------------------------------------------------------------
    def __EGG_Filename_Header__(self, data) :
        size = -1
        fname = None

        try :
            fname_size = struct.unpack('<H', data[5:7])[0]
            fname = data[7:7+fname_size]
            size = 7 + fname_size
        except :
            pass

        return size, fname

    #-----------------------------------------------------------------
    # __EGG_Block_Header_Size__(self, data)
    # Egg ������ Block Header�� �м��Ͽ� ��� ũ�⸦ ���Ѵ�.
    # ���ϰ� : Block Header ũ��
    #-----------------------------------------------------------------
    def __EGG_Block_Header_Size__(self, data) :
        size = -1

        try :
            Block_Size = (18 + 4)
            Compress_Size = struct.unpack('<L', data[10:14])[0]
            size = Block_Size + Compress_Size
        except :
            pass

        return size

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
'''
if __name__ == '__main__' :
    egg = EggFile('winhex.egg')

    print egg.read('234/egg.py')
    for name in egg.namelist() :
        print name
    egg.close()    
'''

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
        info['author'] = __author__ # ������
        info['version'] = __version__     # ����
        info['title'] = 'Egg Engine' # ���� ����
        info['kmd_name'] = 'egg' # ���� ���ϸ�
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
            if mm[0:4] == 'EGGA' : # ��� üũ
                fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_egg'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� ���� ������ ����� ���ϸ��� ����Ʈ�� �����Ѵ�.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����

        try :
            # �̸� �м��� ���� �����߿� EGG ������ �ִ°�?
            fformat = format['ff_egg']
                
            eggfile = EggFile(filename)
            for name in eggfile.namelist() :
                file_scan_list.append(['arc_egg', name])
            eggfile.close()
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_egg' :
                raise SystemError

            eggfile = EggFile(arc_name)
            data = eggfile.read(arc_in_name)
            eggfile.close()

            return data
        except :
            pass

        return None
