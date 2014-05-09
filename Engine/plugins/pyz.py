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
import zlib
import struct
import marshal
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
        info['title'] = 'PYZ Engine' # ���� ����
        info['kmd_name'] = 'pyz' # ���� ���ϸ�
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
            if mm[0:4] == 'PYZ\x00' : # ��� üũ
                off = struct.unpack('>L', mm[8:0xC])[0] # PKZ ���Ͽ��� TOC ��ġ
                fformat['TOC_off'] = off 

                ret = {}
                ret['ff_pyz'] = fformat

                return ret
        except :
            pass

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����

        try :
            # �̸� �м��� ���� �����߿� ZIP ������ �ִ°�?
            fformat = format['ff_pyz']
            toc_off = fformat['TOC_off']

            fp = open(filename, 'rb')
            fp.seek(toc_off)
            toc = fp.read()
            tocs = marshal.loads(toc)
            fp.close()

            for name in tocs.keys() :
                file_scan_list.append(['arc_pyz', name])
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_pyz' :
                raise SystemError

            fp = open(arc_name, 'rb')
            buf = fp.read(0x10)
            toc_off = struct.unpack('>L', buf[8:0xC])[0]
            fp.seek(toc_off)
            toc_buf = fp.read()
            tocs = marshal.loads(toc_buf)

            toc = tocs[arc_in_name]
            start = toc[1]
            size  = toc[2]

            fp.seek(start)
            buf = fp.read(size)

            data = zlib.decompress(buf)

            fp.close()

            return data
        except :
            pass

        return None
