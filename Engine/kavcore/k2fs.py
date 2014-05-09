# -*- coding:utf-8 -*-

#---------------------------------------------------------------------
# K2FileStruct Ŭ����
#---------------------------------------------------------------------
class K2FileStruct :
    def __init__(self) :
        self.fs = {}

    def Set(self, filename) : # ���Ͽ� ���� �ϳ��� K2FileStruct�� �����Ѵ�.
        self.fs['is_arc'] = False # ���� ����
        self.fs['arc_engine_name'] = -1 # ���� ���� ���� ���� ID
        self.fs['arc_filename'] = '' # ���� ���� ����
        self.fs['arc_in_name'] = '' #�������� ��� ����
        self.fs['real_filename'] = filename # �˻� ��� ����
        self.fs['deep_filename'] = ''  # ���� ������ ���θ� ǥ���ϱ� ���� ���ϸ�
        self.fs['display_filename'] = filename # ��¿�

    def IsArchive(self) : # ���� ����
        return self.fs['is_arc']

    def GetArchiveEngine(self) : # ���� ���� ID
        return self.fs['arc_engine_name']

    def GetArchiveFilename(self) : # ���� ���� ����
        return self.fs['arc_filename']

    def GetArchiveInFilename(self) : # �������� ��� ����
        return self.fs['arc_in_name']

    def GetFilename(self) : # ���� �۾� ���ϸ��� ����
        return self.fs['real_filename']

    def SetFilename(self, fname) : # ���� �۾� ���ϸ��� ����
        self.fs['real_filename'] = fname

    def GetMasterFilename(self) : # ������ ��� �ֻ��� ����
        return self.fs['display_filename'] # ��¿�

    def GetDeepFilename(self) : # ���� ������ ���θ� ǥ���ϱ� ���� ���ϸ�
        return self.fs['deep_filename']

    def SetArchive(self, engine_id, rname, fname, dname, mname) :
        self.fs['is_arc'] = True # ���� ����
        self.fs['arc_engine_name'] = engine_id # ���� ���� ���� ���� ID
        self.fs['arc_filename'] = rname # ���� ���� ����
        self.fs['arc_in_name'] = fname #�������� ��� ����
        self.fs['real_filename'] = '' # �˻� ��� ����
        self.fs['deep_filename'] = dname  # ���� ������ ���θ� ǥ���ϱ� ���� ���ϸ�
        self.fs['display_filename'] = mname
