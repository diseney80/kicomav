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
# AlzFile Ŭ����
#---------------------------------------------------------------------
COMPRESS_METHOD_STORE   = 0
COMPRESS_METHOD_BZIP2   = 1
COMPRESS_METHOD_DEFLATE = 2

class AlzFile :
    #-----------------------------------------------------------------
    # __init__(self, filename)
    # ������ ������ Alz ������ �����Ѵ�.
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
            fname, data = self.__FindFirstFileName__()
            while fname != None :
                if fname == filename :
                    # print fname, '{OK]'

                    data, method = self.__ReadFileData__(data)
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

                fname, data = self.__FindNextFileName__()
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
            fname, data = self.__FindFirstFileName__()
            while fname != None :
                name_list.append(fname)
                fname, data = self.__FindNextFileName__()
        except :
            pass

        return name_list

    #-----------------------------------------------------------------
    # AlzFile Ŭ������ ���� ��� �Լ���
    #-----------------------------------------------------------------

    #-----------------------------------------------------------------
    # __FindFirstFileName__(self)
    # Alz ���� ���ο� ����� ���ϸ��� ù��° �̸��� ���´�.
    # ���ϰ� : ����� ù��° ���ϸ�, ���� ��Ʈ��
    #-----------------------------------------------------------------
    def __FindFirstFileName__(self) :
        self.alz_pos = 8
        start        = 8
        end          = 0

        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end = self.alz_pos

        return fname, self.mm[start:end]

    #-----------------------------------------------------------------
    # __FindNextFileName__(self)
    # Alz ���� ���ο� ����� ���ϸ��� ���� �̸��� ���´�.
    # ���ϰ� : ����� ���� ���ϸ�, ���� ��Ʈ��
    #-----------------------------------------------------------------
    def __FindNextFileName__(self) :
        start = self.alz_pos
        fname, self.alz_pos = self.__GetFileName__(self.alz_pos)
        end   = self.alz_pos

        return fname, self.mm[start:end]

    #-----------------------------------------------------------------
    # __GetFileName__(self, alz_pos)
    # �־��� ��ġ ���ķ� Filename Header�� ã�� �м��Ѵ�.
    # ���ϰ� : Filename Header���� ���ϸ�, ���� ��ġ
    #-----------------------------------------------------------------
    def __GetFileName__(self, alz_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            while alz_pos < data_size :
                Magic = struct.unpack('<L', mm[alz_pos:alz_pos+4])[0]

                if Magic == 0x015A4C42 : # Local File Header
                    size, fname = self.__ALZ_LocalFile_Header__(mm[alz_pos:])
                    if size == -1 : raise SystemError
                    alz_pos += size
                    return fname, alz_pos
                else :
                    alz_pos = self.__DefaultMagicIDProc__(Magic, alz_pos)
                    if alz_pos == -1 :
                        raise SystemError
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __ReadFileData__(self)
    # ���� ��ġ�������� Block Header�� ã�� �м��Ѵ�.
    # ���ϰ� : ����� data ��Ʈ��, ���� ���
    #-----------------------------------------------------------------
    def __ReadFileData__(self, data) :
        alz_pos      = self.alz_pos
        mm           = self.mm
        data_size    = len(mm)

        try :
            Magic = struct.unpack('<L', data[0:4])[0]

            if Magic == 0x015A4C42 : # Local File Header
                fname_size        = struct.unpack('<H', data[4:6])[0]
                file_desc         = ord(data[11])
                Compress_Method_M = ord(data[13])

                size = 19
                if   file_desc & 0x10 : 
                    Compress_Size   = ord(data[size])
                    Uncompress_Size = ord(data[size+1])
                    size += (1 * 2) # ���� ũ�Ⱑ 2�� ��(������, ���� ��)
                elif file_desc & 0x20 : 
                    Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                    Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                    size += (2 * 2)
                elif file_desc & 0x40 : 
                    Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                    Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                    size += (4 * 2)
                elif file_desc & 0x80 : 
                    Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                    Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                    size += (8 * 2)
                else                  : raise SystemError

                size += fname_size # ���� �̸�
                
                if file_desc & 1 :
                    size += 12 # Encrypt Block

                Compressed_Data = data[size:size+Compress_Size]

                return Compressed_Data, Compress_Method_M
        except :
            pass

        return None, -1

    #-----------------------------------------------------------------
    # __DefaultMagicIDProc__(self, Magic, alz_pos)
    # �־��� ��ġ�� Magic�� �м��ϰ� �Ľ��Ѵ�.
    # ���ϰ� : ���� Magic�� ��ġ
    #-----------------------------------------------------------------
    def __DefaultMagicIDProc__(self, Magic, alz_pos) :
        mm           = self.mm
        data_size    = len(mm)

        try :
            if alz_pos < data_size :
                if   Magic == 0x015A4C41 : # ALZ Header
                    alz_pos += 8
                    #print 'ALZ Header', hex(alz_pos)
                elif Magic == 0x015A4C42 : # Local File Header
                    size = self.__ALZ_LocalFile_Header_Size__(mm[alz_pos:])
                    alz_pos += size
                    #print 'Local File Header', hex(alz_pos)
                elif Magic == 0x015A4C43 : # Central Directory Structure
                    alz_pos += 12
                    #print 'Central Directory Structure', hex(alz_pos)
                elif Magic == 0x025A4C43 : # EOF Central Directory Record
                    alz_pos += 4
                    #print 'EOF Central Directory Record', hex(alz_pos)
                else :
                    # print 'Not Support Header :', hex(alz_pos)
                    raise SystemError
        except :
            return -1

        return alz_pos

    #-----------------------------------------------------------------
    # __ALZ_LocalFile_Header_Size__(self, data)
    # ���� ������ LocalFile Header�� ũ�⸦ ���Ѵ�.
    # ���ϰ� : LocalFile Header�� ũ��
    #-----------------------------------------------------------------
    def __ALZ_LocalFile_Header_Size__(self, data) :
        size = 0

        try :
            size += 4 # 0X015A4C42 ���

            fname_size = struct.unpack('<H', data[size:size+2])[0]
            size += 2 # ���� �̸� ����
            size += 1 # ���� �Ӽ�
            size += 4 # ���� ��¥/�ð�

            file_desc = ord(data[size])
            size += 1 # ���� ��ũ��Ʈ 
                      # 1 ��Ʈ ON - ��ȣ 0x10 : ����ũ�� 1Byte, 0x20 : 2Byte...
            size += 1 # unknown

            compress_method = ord(data[size])
            size += 1 # ���� ��� (0:�������, 1:BZip2, 2:Deflate)
            size += 1 # unknown
            size += 4 # CRC

            if   file_desc & 0x10 : 
                Compress_Size   = ord(data[size])
                Uncompress_Size = ord(data[size+1])
                size += (1 * 2) # ���� ũ�Ⱑ 2�� ��(������, ���� ��)
            elif file_desc & 0x20 : 
                Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                size += (2 * 2)
            elif file_desc & 0x40 : 
                Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                size += (4 * 2)
            elif file_desc & 0x80 : 
                Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                size += (8 * 2)
            else                  : raise SystemError

            # print data[size:size+fname_size], hex(Compress_Size), hex(Uncompress_Size), compress_method
            size += fname_size # ���� �̸�
            
            if file_desc & 1 :
                size += 12 # Encrypt Block

            #code = data[size:size+Compress_Size]
            #print zlib.decompress(code, -15)
            size += Compress_Size
        except :
            return -1

        return size

    #-----------------------------------------------------------------
    # __ALZ_LocalFile_Header__(self, data)
    # ���� ������ LocalFile Header�� �Ľ��Ѵ�.
    # ���ϰ� : LocalFile Header�� ũ��, ���� ���ϸ�
    #-----------------------------------------------------------------
    def __ALZ_LocalFile_Header__(self, data) :
        size = 0
        fname = None

        try :
            size += 4
            fname_size = struct.unpack('<H', data[size:size+2])[0]

            size += 7 
            file_desc = ord(data[size])

            size += 2
            compress_method = ord(data[size])

            size += 6

            if   file_desc & 0x10 : 
                Compress_Size   = ord(data[size])
                Uncompress_Size = ord(data[size+1])
                size += (1 * 2) # ���� ũ�Ⱑ 2�� ��(������, ���� ��)
            elif file_desc & 0x20 : 
                Compress_Size   = struct.unpack('<H', data[size  :size+2])[0]
                Uncompress_Size = struct.unpack('<H', data[size+2:size+4])[0]
                size += (2 * 2)
            elif file_desc & 0x40 : 
                Compress_Size   = struct.unpack('<L', data[size  :size+4])[0]
                Uncompress_Size = struct.unpack('<L', data[size+4:size+8])[0]
                size += (4 * 2)
            elif file_desc & 0x80 : 
                Compress_Size   = struct.unpack('<Q', data[size  :size+ 8])[0]
                Uncompress_Size = struct.unpack('<Q', data[size+8:size+16])[0]
                size += (8 * 2)
            else                  : raise SystemError

            fname = data[size:size+fname_size]
            size += fname_size # ���� �̸�
            
            if file_desc & 1 :
                size += 12 # Encrypt Block

            size += Compress_Size
        except :
            return -1

        return size, fname

#---------------------------------------------------------------------
# TEST
#---------------------------------------------------------------------
'''
if __name__ == '__main__' :
    alz = AlzFile('unalz.alz')

    print alz.read('readme.txt')

    for name in alz.namelist() :
        print name

    alz.close()    
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
        info['title'] = 'Alz Engine' # ���� ����
        info['kmd_name'] = 'alz' # ���� ���ϸ�
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
            if mm[0:4] == 'ALZ\x01' : # ��� üũ
                fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_alz'] = fformat

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
            # �̸� �м��� ���� �����߿� ALZ ������ �ִ°�?
            fformat = format['ff_alz']
                
            alzfile = AlzFile(filename)
            for name in alzfile.namelist() :
                file_scan_list.append(['arc_alz', name])
            alzfile.close()
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_alz' :
                raise SystemError

            alzfile = AlzFile(arc_name)
            data = alzfile.read(arc_in_name)
            alzfile.close()

            return data
        except :
            pass

        return None
