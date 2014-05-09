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
import mmap
import re
import zlib
import kernel

class PDF :
    def __init__(self, fname) :
        self.SPACE = (' ' * 4) # ��� ����
        self.ObjInfo = []
        self.Root = {}
        self.fp = None
        self.mm = None

        self.fp = open(fname, 'rb')
        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        self.re_version   = re.compile('[\d]+.[\d]+')
        self.re_obj       = re.compile('[\d]+ [0] obj[ \r\n]*')
        self.re_endobj    = re.compile('endobj[ \r\n]*')
        self.re_objid     = re.compile('([\d]+) [0] obj[ \r\n]*')
        self.re_stream    = re.compile('stream[\r\n]*')
        self.re_endstream = re.compile('[\r\n]*endstream[\r\n]*')
        self.re_shapchar  = re.compile('#([0-9A-Fa-f]{2})')
        self.re_refer     = re.compile('([\d]+) [0] [R]')
        self.re_trailer   = re.compile('trailer[ \r\n]*<<')
        self.re_root      = re.compile('/Root ([\d]+) [0] [R]')
        self.re_filter    = re.compile('/[Ff]ilter.+?([/A-Za-z0-9]+)')

        self.parse()

    def close(self) :
        if self.mm : self.mm.close()
        if self.fp : self.fp.close()

    def parse(self) :
        # if self.__isPDF__() != 0 :
        #     raise ValueError

        # self.version = self.__getPDFVersion__() # ���� üũ
        # if self.version == None :
        #     raise ValueError

        self.ObjNum = self.__getPDFObjectNum__() # Object ���� üũ
        if self.ObjNum == 0 :
            raise ValueError

        # self.__getPDFRoot__()

    def getstream(self, objid) :
        if len(self.ObjInfo) == 0 :
            return

        for obj in self.ObjInfo :
            if obj['Object ID'] == objid :
                s_start, s_end = obj['Object Stream']
                data = self.mm[s_start:s_start+s_end]

                '''
                print hex(s_start), (s_end)
                fp = open(objid, 'wb')
                fp.write(data)
                fp.close()
                '''

                b_start = obj['Object Start']
                b_end   = b_start + obj['Object Size']
                body = self.mm[b_start:b_end]
                if body.find('FlateDecode') != -1 :
                    data = zlib.decompress(data)

                return data

        return ''

    def getinfo(self, objid) :
        ret = None

        if len(self.ObjInfo) == 0 :
            return

        for obj in self.ObjInfo :
            if obj['Object ID'] == objid :
                start = obj['Object Start']
                size  = obj['Object Size']
                ret = self.summuryinfo(self.mm[start:start+size])

        return ret

    # �־��� ������Ʈ �������� ������Ʈ ID ���ϱ�
    def __parseObjID__(self, data) :
        id = self.re_objid.search(data)
        if id :
            return id.groups()[0]
        else :
            return -1

    def __parseObjSteam__(self, data) :
        stream_data = None
        start = 0
        size  = 0

        try :
            stream_s = self.re_stream.search(data)
            if stream_s == None :
                raise SystemError

            stream_e = self.re_endstream.search(data)
            if stream_e == None :
                raise SystemError

            start = stream_s.end()
            end   = stream_e.start()

            size  = end - start

            stream_data = data[start:end]
        except :
            pass

        return stream_data, start, size

    def __getPDFObjectNum__(self) :
        num = 0

        pos = 0
        while 1 :
            obj = self.re_obj.search(self.mm[pos:])
            if obj : # obj �� �ְ�
                endobj = self.re_endobj.search(self.mm[pos:])
                if endobj : #endobj�� �����Ҷ� �������� obj ����
                    objid = {}

                    obj_start_pos = pos + obj.start()
                    obj_size      = endobj.end() - obj.start()

                    objid['Object Start'] = obj_start_pos
                    objid['Object Size']  = obj_size

                    # Obj�� ������ ����
                    # body = self.summuryinfo(self.mm[obj_start_pos:obj_start_pos+obj_size])
                    # objid['Object Body'] = body

                    # Obj�� ���� ���� ������Ʈ�� ����
                    # objid['Object Reference'] = self.re_refer.findall(body)


                    # ������Ʈ ���� �����ϱ�
                    id = self.__parseObjID__(self.mm[obj_start_pos:obj_start_pos+obj_size])
                    if id != -1:
                        objid['Object ID'] = id
                        num += 1

                        # Stream �����ϱ�
                        stream, stream_start, stream_size = self.__parseObjSteam__(self.mm[obj_start_pos:obj_start_pos+obj_size])
                        if stream != None :
                            objid['Object Stream'] = (obj_start_pos + stream_start, stream_size)
                        else :
                            objid['Object Stream'] = (0, 0)

                        # ������ ������ Object ID�� �ִ��� �����Ѵ�.
                        # PDF�� ���� ������Ʈ ����� �����ϱ� �����̴�.
                        for o in self.ObjInfo :
                            if o['Object ID'] == id :
                                i = self.ObjInfo.index(o)
                                self.ObjInfo.pop(i) # ���� ������ ����

                        self.ObjInfo.append(objid) # ���� ���� ����

                    pos = obj_start_pos + obj_size
                else :
                    break
            else :
                break

        return num

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
        info['title'] = 'PDF Engine' # ���� ����
        info['kmd_name'] = 'pdf' # ���� ���ϸ�
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        try :
            fformat = {} # ���� ������ ���� ����

            mm = mmhandle

            if mm[0:7] == '%PDF-1.' : # ��� üũ
                fformat['size'] = len(mm) # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_pdf'] = fformat

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
            fformat = format['ff_pdf']

            pdf = PDF(filename)

            for obj in pdf.ObjInfo :
                if obj['Object Stream'][0] != 0 :
                    name = 'Object#' + obj['Object ID']
                    file_scan_list.append(['arc_pdf', name])
                    # print obj['Object ID']
            # print pdf.ObjInfo
            pdf.close()
            
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_pdf' :
                raise SystemError

            pdf = PDF(arc_name)
            data = pdf.getstream(arc_in_name[7:])
            pdf.close()
            
            return data
        except :
            pass

        return None
