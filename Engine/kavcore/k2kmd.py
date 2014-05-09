# -*- coding:utf-8 -*-

import os
import sys
import imp
import hashlib
import zlib
import struct
import StringIO
import datetime
import marshal
import base64
from k2rc4    import K2RC4
from k2ctime  import K2CTIME

#---------------------------------------------------------------------
# KMD Ŭ����
#---------------------------------------------------------------------
class K2KMD :
    def __init__(self) :
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

    def GetLastUpdate(self) :
        return self.max_datetime

    def GetList(self, plugins) :
        kmd_list = []

        try :
            # RSA ����Ű �ε�
            fp = open(plugins + os.sep + 'kicomav.pkr', 'rt') # ����Ű
            b = fp.read()
            fp.close()
            s = base64.b64decode(b)
            self.PU = marshal.loads(s)

            # kicom.kmd ������ ��ȣȭ
            ret, buf = self.Decrypt(plugins + os.sep + 'kicom.kmd')

            if ret == True : # ����
                msg = StringIO.StringIO(buf) # ���� IO �غ�

                while 1 :
                    # ���� �� ���� �о� ����Ű ����
                    line = msg.readline().strip()
                    if line.find('.kmd') != -1 : # kmd Ȯ���ڰ� �����Ѵٸ�
                        kmd_list.append(line) # kmd ���� ����Ʈ�� �߰�
                    else :
                        break
        except :
            pass

        return kmd_list # kmd ���� ����Ʈ ����

    def RSACrypt(self, buf, PR) :
        plantext_ord = 0
        for i in range(len(buf)) :
            plantext_ord |= ord(buf[i]) << (i*8)

        val = pow(plantext_ord, PR[0], PR[1]) # ����Ű�� ��ȣȭ

        ret = ''
        for i in range(32) :
            b = val & 0xff
            val >>= 8
            ret += chr(b)

            if val == 0 :
                break

        return ret

    def Decrypt(self, fname) :
        t = K2CTIME()
        header_length = 8
        hash_length = 0x40

        try : # ���ܰ� �߻��� ���ɼ��� ���� ó��
            # kmd ���� �б�
            fp = open(fname, 'rb') 
            buf = fp.read()
            fp.close()

            # ���Ͽ��� �� �κ� �и�
            e_md5         = buf[len(buf)-32:]
            buf           = buf[:len(buf)-32]
            header        = buf[:4]
            reserved_area = buf[4:4+32]
            rc4_key       = buf[36:36+32]
            enc_data      = buf[36+32:]

            # ��� üũ
            if header != 'KAVM' :
                raise ValueError

            # ���� �� md5 ������ ���Ἲ üũ
            e_md5hash = self.RSACrypt(e_md5, self.PU)

            md5 = hashlib.md5()
            md5hash = buf
            for i in range(3): 
                md5.update(md5hash)
                md5hash = md5.hexdigest()   

            if e_md5hash != md5hash.decode('hex') :
                raise ValueError

            # RC4 Key ��ȣȭ
            key = self.RSACrypt(rc4_key, self.PU)
            
            # RC4 ��ȣȭ
            e_rc4 = K2RC4()  # ��ȣȭ
            e_rc4.SetKey(key)
            data = e_rc4.Crypt(enc_data)

            # ���� ����
            data = zlib.decompress(data)

            # �ֱ� ��¥ ���ϱ�
            kmd_date = reserved_area[0:2]
            kmd_time = reserved_area[2:4]

            d_y, d_m, d_d = t.GetDate(struct.unpack('<H', kmd_date)[0])
            t_h, t_m, t_s = t.GetTime(struct.unpack('<H', kmd_time)[0])
            t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

            if self.max_datetime < t_datetime :
                self.max_datetime = t_datetime

            return True, data # kmd ��ȣȭ ���� �׸��� ��ȣȭ�� ���� ����
        except : # ���� �߻�
            import traceback
            print traceback.format_exc()
            return False, '' # ����

    def Import(self, plugins, kmd_list) :
        mod_list = []

        for kmd in kmd_list :
            ret_kmd, buf = self.Decrypt(plugins + os.sep + kmd)

            if ret_kmd == True :
                ret_imp, mod = self.LoadModule(kmd.split('.')[0], buf)
                if ret_imp == True :
                    mod_list.append(mod)

        return mod_list

    def LoadModule(self, kmd_name, buf) :
        try :
            code = marshal.loads(buf[8:]) # ���۸� ������ ������ ����ȭ �� ���ڿ��� ��ȯ
            module = imp.new_module(kmd_name) # ���ο� ��� ����
            exec(code, module.__dict__) # ����ȭ �� ���ڿ��� �������Ͽ� ���� ����
            sys.modules[kmd_name] = module # �������� ��밡���ϰ� ���
            return True, module
        except :
            import traceback
            print traceback.format_exc()

            return False, None

    def ExecKavMain(self, module) :
        obj = None

        # �ε��� ��⿡�� KavMain�� �ִ��� �˻�
        # KavMain�� �߰ߵǾ����� Ŭ������ �ν��Ͻ� ����
        if dir(module).count('KavMain') != 0 :
            obj = module.KavMain()

        # ������ �ν��Ͻ��� ���ٸ� ���� �ε��� ����� ���
        if obj == None :
            # �ε� ���
            del sys.modules[kmd_name]
            del module

        return obj # ������ �ν��Ͻ� ����

