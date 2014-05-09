# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

# EXTRA BBD ���� ����
# mmap ����
import os
import struct
import mmap
import tempfile
import kavutil

#---------------------------------------------------------------------
# GetDword(s, offset)
# GetWord(s, offset)
# GetRead(s, offset, size)
# ���ۿ��� ������ ũ�⸸ŭ �о�´�
#---------------------------------------------------------------------
# ���� �����Ϳ��� 4Byte �� ����
def GetDword(s, offset) :
  return struct.unpack("<L", s[offset:offset+4])[0]

# ���� �����Ϳ��� 2Byte �� ����
def GetWord(s, offset) :
  return struct.unpack("<H", s[offset:offset+2])[0]

# ���� �����Ϳ��� Ư�� ũ�⸸ŭ �б�
def GetRead(s, offset, size) :
  return s[offset:offset+size]


#---------------------------------------------------------------------
# OLE Ŭ����
#---------------------------------------------------------------------
class OLE :
    def __init__ (self, filename) :
        self.bbd_list      = []
        self.bbd_list_pos  = []
        self.sbd_list      = []
        self.sbd_list_pos  = []
        self.root_list     = []
        self.root_list_pos = []
        self.pps_list      = []
        self.sdb_list     = []
        self.sdb_list_pos = []
        self.deep  = 0
        self.Error = -1
        self.bbd = ""
        self.sbd = ""

        self.olefile = filename
        self.open()

    def open(self) :
        self.fp = open(self.olefile, 'rb')
        self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)

        _OLE_HEADER = (
            'OLE_Header', 
            (
                'L,e_magic1',
                'L,e_magic2',
                'L,e_reserved1',
                'L,e_reserved2',
                'L,e_reserved3',
                'L,e_reserved4',
                'H,e_reserved5',
                'H,e_reserved6',
                'H,e_reserved7',
                'B,e_reserved8',
                'B,e_reserved9',
                'L,e_reserved10',
                'L,e_reserved11',
                'L,e_reserved12',
                'L,e_num_of_bbd_blocks', # 0x2C
                'L,e_root_startblock',
                'L,e_reserved13',
                'L,e_reserved14',
                'L,e_sbd_startblock',
                'L,e_num_of_sbd_blocks',
                'L,e_xbbd_start',
                'L,e_num_of_Xbbd_blocks'
            )
        )

        self.OleHeader = kavutil.Structure(_OLE_HEADER, self.mm[0:0x200], 0)
        self.OleHeader.analysis()
        # print self.OleHeader.dump()

    def close(self) :
        self.mm.close()
        self.fp.close()

    def isOLE(self) :
        if self.OleHeader.e_magic1 != 0xe011cfd0L or self.OleHeader.e_magic2 != 0xe11ab1a1L:
            return 0
        else :
            return 1 # OLE ���� ����

    def readBDB(self, num_of_bbd_blocks) :
        if num_of_bbd_blocks > 109 :
            j = 109
        else :
            j = num_of_bbd_blocks

        for i in range(j) :
            self.bbd_list.append(GetDword(self.mm, 0x4c + (i*4)))
            self.bbd_list_pos.append((self.bbd_list[i]+1) << 9)


    def parse(self) :
        try :
            # OLE ���� �ñ׳�ó üũ
            if self.isOLE() == 0:
                self.Error = -1
                raise AttributeError

            # BBD �� ������ŭ BDB �б�
            num_of_bbd_blocks = self.OleHeader.e_num_of_bbd_blocks
            self.readBDB(num_of_bbd_blocks)

            # XBBD �� ó��
            num_of_Xbbd_blocks = self.OleHeader.e_num_of_Xbbd_blocks
            xbbd_start         = self.OleHeader.e_xbbd_start


            if xbbd_start != 0xFFFFFEL :
                xbbd = ""
                val = xbbd_start

                for i in range(num_of_Xbbd_blocks) :
                    buf = GetRead(self.mm, (val+1)<<9, 0x200)
                    xbbd += buf[0:0x1FC]
                    val = GetDword(buf, 0x1FC)

                for i in range(num_of_bbd_blocks-109) :
                    val = GetDword(xbbd, (i*4))
                    self.bbd_list.append(val)
                    self.bbd_list_pos.append((val+1) << 9)

            # BBD ����
    #       bbd = ""
            for i in range(num_of_bbd_blocks) :
                self.bbd += GetRead(self.mm, self.bbd_list_pos[i], 0x200)

            # SBD �� ������ŭ SBD �б�
            sbd_startblock = self.OleHeader.e_sbd_startblock
            num_of_sbd_blocks = self.OleHeader.e_num_of_sbd_blocks

            self.sbd_list.append(sbd_startblock)
            self.sbd_list_pos.append((sbd_startblock+1)<<9)

            i = sbd_startblock
            while True :
                val = GetDword(self.bbd, i*4)
                if val == 0xFFFFFFFEL :
                    break
                self.sbd_list.append(val)
                self.sbd_list_pos.append((val+1)<<9)
                i = val

            # SBD ����
    #       sbd = ""
            for i in range(num_of_sbd_blocks) :
                self.sbd += GetRead(self.mm, self.sbd_list_pos[i], 0x200)


            # Root Entry ��ô�ϱ�
            root_startblock = self.OleHeader.e_root_startblock

            self.root_list.append(root_startblock)
            self.root_list_pos.append((root_startblock+1)<<9)

            i = root_startblock
            while True :
                val = GetDword(self.bbd, i*4)
                if val == 0xfffffffeL :
                    break
                self.root_list.append(val)
                self.root_list_pos.append((val+1)<<9)
                i = val  

            # root ����
            root = ""
            for i in range(len(self.root_list_pos)) :
                root += GetRead(self.mm, self.root_list_pos[i], 0x200)

            # PPS ����
            for i in range(len(self.root_list_pos) * 4) :
                pps = {}
                pps_buf = GetRead(root, i*0x80, 0x80)
                # {'Name':'Root Entry', NameSize:16, Type:5, Prev:0xFFFFFFFF, Next:0xFFFFFFFF, Dir:0x3, StartBlock:0x3, Size:0x1000]
                pps['Name']       = pps_buf[0:GetWord(pps_buf, 0x40)]
                pps['NameSize']   = GetWord(pps_buf, 0x40)
                pps['Type']       = ord(pps_buf[0x42])
                pps['Prev']       = GetDword(pps_buf, 0x44)
                pps['Next']       = GetDword(pps_buf, 0x48)
                pps['Dir']        = GetDword(pps_buf, 0x4c)
                pps['StartBlock'] = GetDword(pps_buf, 0x74)
                pps['Size']       = GetDword(pps_buf, 0x78)

                self.pps_list.append(pps)

            # SDB ����
            sdb_startblock = self.pps_list[0]['StartBlock']

            self.sdb_list.append(sdb_startblock)
            self.sdb_list_pos.append((sdb_startblock+1)<<9)

            i = sdb_startblock
            while True :
                val = GetDword(self.bbd, i*4)
                if val == 0xfffffffeL :
                    break
                self.sdb_list.append(val)
                self.sdb_list_pos.append((val+1)<<9)
                i = val  

            self.Error = 0
        except :
            pass

        return self.Error

    # PPS Ʈ���� ��´�
    def GetPPSList(self) :
        self.PPSNum = 0
        self.GetPPSNum()

        # ���� ���� PPS ������
        for i in range(len(self.pps_list) - self.PPSNum) :
            self.pps_list.pop()

        return self.pps_list

    def GetPPSNum(self, node=0) :
        if self.Error == -1 :
            return -1

        self.PPSNum += 1 # �����ϴ� PPS

        if self.pps_list[node]['Dir'] != 0xFFFFFFFFL :
            self.deep += 1
            self.GetPPSNum(self.pps_list[node]['Dir'])
            self.deep -= 1

        if self.pps_list[node]['Prev'] != 0xFFFFFFFFL :
            self.GetPPSNum(self.pps_list[node]['Prev'])

        if self.pps_list[node]['Next'] != 0xFFFFFFFFL :
            self.GetPPSNum(self.pps_list[node]['Next'])

        return 0


    # PPS Ʈ�� ����ϱ�
    def PrintTree(self, node=0, prefix="") :
        if self.Error == -1 :
            return -1

        print ("    %02d : " + "%s" + "%s") % (node, self.deep*"   ", self.pps_list[node]['Name'][0:self.pps_list[node]['NameSize']:2])

        if self.pps_list[node]['Dir'] != 0xFFFFFFFFL :
            self.deep += 1
            self.PrintTree(self.pps_list[node]['Dir'])
            self.deep -= 1

        if self.pps_list[node]['Prev'] != 0xFFFFFFFFL :
            self.PrintTree(self.pps_list[node]['Prev'])

        if self.pps_list[node]['Next'] != 0xFFFFFFFFL :
            self.PrintTree(self.pps_list[node]['Next'])

        return 0

    # PPS�� �����Ѵ�
    def DumpPPS(self, node, fname) :
        '''
        if self.Error == -1 :
            return -1
        '''

        size = self.pps_list[node]['Size']
        sb = self.pps_list[node]['StartBlock'] 

        if size < 0x1000 :
            block_depot = self.sbd
            pps_size    = 0x40
        else :
            block_depot = self.bbd
            pps_size    = 0x200

        bd_list = []
        bd_list.append(sb);

        # PPS ������ ���� �� ������ �̷�������� ���
        tmp_size = (size/pps_size) * pps_size
        if size % pps_size :
            tmp_size += pps_size
        
        i = sb
        for count in range(tmp_size/pps_size) :
            val = GetDword(block_depot, i*4)
            if val == 0xFFFFFFFEL or val == 0 :
                val = i+1
            bd_list.append(val)
            i = val

        bd_list_pos = []

        for i in range(len(bd_list)) :
            if size < 0x1000 :
                v1 = bd_list[i] / 8
                v2 = bd_list[i] % 8
                bd_list_pos.append(self.sdb_list_pos[v1] + (0x40 * v2))
            else :
                bd_list_pos.append((bd_list[i]+1)<<9)

        fp1 = open(fname, "wb")

        for i in range(len(bd_list)) :
            pps_buf = GetRead(self.mm, bd_list_pos[i], pps_size)
            fp1.write(pps_buf)

        fp1.truncate(size)
        fp1.close()

        return 0



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
        info['title'] = 'OLE Engine' # ���� ����
        info['kmd_name'] = 'ole' # ���� ���ϸ�
        return info

    #-----------------------------------------------------------------
    # format(self, mmhandle, filename)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def format(self, mmhandle, filename) :
        ole = None

        try :
            fformat = {} # ���� ������ ���� ����

            ole = OLE(filename)
            if ole.parse() == 0 : # OLE �ļ�
                fformat['pps'] = ole.GetPPSList() # ���� �ֿ� ���� ����

                ret = {}
                ret['ff_ole'] = fformat
                ole.close()
                return ret
        except :
            pass

        if ole != None :
            ole.close()

        return None

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� �м����̴�.
    #-----------------------------------------------------------------
    def FullpathPPSList(self, pps_list) :
        self.pps_list = pps_list
        self.full_list = []
        self.deep = 0

        self.GetPPSpath()
        return self.full_list

    def GetPPSpath(self, node=0, prefix='') :
        if node == 0 :
            pps_name = ''
            name = prefix + pps_name
        else :
            pps_name = self.pps_list[node]['Name'][0:self.pps_list[node]['NameSize']-2:2]
            name = prefix + '/' + pps_name
            # print ("%02d : %d %s") % (node, self.deep, name)
            if self.pps_list[node]['Type'] == 2 : # Stream�� ����
                plist = {}
                plist['Node'] = node
                plist['Name'] = name[1:]
                self.full_list.append(plist)

        if self.pps_list[node]['Dir'] != 0xFFFFFFFFL :
            self.deep += 1
            self.GetPPSpath(self.pps_list[node]['Dir'], name)
            self.deep -= 1

        if self.pps_list[node]['Prev'] != 0xFFFFFFFFL :
            self.GetPPSpath(self.pps_list[node]['Prev'], prefix)

        if self.pps_list[node]['Next'] != 0xFFFFFFFFL :
            self.GetPPSpath(self.pps_list[node]['Next'], prefix)

        return 0

    #-----------------------------------------------------------------
    # arclist(self, scan_file_struct, format)
    # ���� ���� ������ ����� ���ϸ��� ����Ʈ�� �����Ѵ�.
    #-----------------------------------------------------------------
    def arclist(self, filename, format) :
        file_scan_list = [] # �˻� ��� ������ ��� ����

        try :
            # �̸� �м��� ���� �����߿� ZIP ������ �ִ°�?
            fformat = format['ff_ole']

            all_pps = fformat['pps']
            full_path_list = self.FullpathPPSList(all_pps)

            for pps in  full_path_list:
                name = pps['Name']
                file_scan_list.append(['arc_ole', name])
        except :
            pass

        return file_scan_list

    #-----------------------------------------------------------------
    # unarc(self, scan_file_struct)
    # �־��� ����� ���ϸ����� ������ �����Ѵ�.
    #-----------------------------------------------------------------
    def unarc(self, arc_engine_id, arc_name, arc_in_name) :
        try :
            if arc_engine_id != 'arc_ole' :
                raise SystemError

            # ������ �����Ͽ� �ӽ� ������ ����
            rname = tempfile.mktemp(prefix='ktmp')

            ofile = OLE(arc_name)
            if ofile.parse() == 0 :
                all_pps = ofile.GetPPSList()
                full_path_list = self.FullpathPPSList(all_pps)

                node = 0
                for pps in  full_path_list:
                    file_info = {}  # ���� �Ѱ��� ����

                    node = pps['Node']
                    name = pps['Name']

                    if arc_in_name == name :
                        break

                ofile.DumpPPS(node, rname)
            ofile.close()


            fp = open(rname, 'rb')
            data = fp.read()
            fp.close()

            os.remove(rname)

            return data
        except :
            pass

        return None
