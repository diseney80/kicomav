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

import mmap
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
        info['author'] = __author__ # ������
        info['version'] = __version__     # ����
        info['title'] = 'Attach Engine' # ���� ����
        info['kmd_name'] = 'attach' # ���� ���ϸ�
        return info

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� ���� ������ ����� ���ϸ��� ����Ʈ�� �����Ѵ�.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����

        try :
            # �̸� �м��� ���� �����߿� �߰� ������ �ִ°�?
            fformat = format['ff_attach']

            pos = fformat['Attached_Pos']
            if pos <= 0 : 
                raise SystemError

            name = 'Attached'
            arc_name = 'arc_attach!%s' % pos

            file_scan_list.append([arc_name, name])
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        fp = None
        mm = None

        try :
            arc_id = arc_engine_id
            if arc_id[0:10] != 'arc_attach' :
                raise SystemError

            pos = int(arc_id[11:]) # ÷�ε� ������ ��ġ ���
            if pos <= 0 : 
                raise SystemError

            # ÷�� ������ ���� ���� ����
            fp = open(arc_name, 'rb') 
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            data = mm[pos:]

            mm.close()
            fp.close()

            mm = None
            fp = None

            return data
        except :
            pass

        if mm != None : mm.close()
        if fp != None : fp.close()

        return None
