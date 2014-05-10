# -*- coding:utf-8 -*-

"""
Copyright (C) 2013-2014 Nurilab.

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
import struct

def GetString(buf, off) :
    ret_str = ''

    try :
        pos = off
        while 1 :
            c = buf[pos]
            if c == '\x00' : break
            ret_str += c
            pos += 1
    except :
        pass

    return ret_str


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
        info['title'] = 'Ole10Native Engine' # ���� ����
        info['kmd_name'] = 'ole10native' # ���� ���ϸ�
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # ���� ������ ���� ����

            mm = mmhandle
            size = struct.unpack('<L', mm[0:4])[0]
            
            if mm[4:6] == '\x02\x00' :
                if len(mm) == size + 4 : 
                    fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                    label = GetString(mm, 6)
                    fformat['label'] = label

                    off = 6+len(label)+1
                    fname = GetString(mm, off)

                    off += len(fname) + 1
                    off += 2 # flag
                    
                    unknown_size = ord(mm[off])
                    off += 1 + unknown_size + 2

                    command = GetString(mm, off)
                    off += len(command) + 1

                    data_size = struct.unpack('<L', mm[off:off+4])[0]

                    fformat['data_off'] = off + 4
                    fformat['data_size'] = data_size

                    if len(mm) < off + data_size : # ����
                        raise SystemError

                    ret = {}
                    ret['ff_ole10native'] = fformat

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
            # �̸� �м��� ���� �����߿� ff_ole10native ������ �ִ°�?
            fformat = format['ff_ole10native']
                
            name = fformat['label'] # OLE ���ο� ������ ���� ��

            off       = fformat['data_off']
            data_size = fformat['data_size']

            arc_name = 'arc_ole10native!%s!%s' % (off, data_size)
            file_scan_list.append([arc_name, name])

        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            fformat = arc_engine_id.split('!')

            if fformat[0] != 'arc_ole10native' :
                raise SystemError

            off       = int(fformat[1])
            data_size = int(fformat[2])

            fp = open(arc_name, 'rb')
            fp.seek(off)
            data = fp.read(data_size)
            fp.close()

            return data
        except :
            pass

        return None
