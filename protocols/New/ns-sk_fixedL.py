# -*- generated by 1.0.12 -*-
import da
PatternExpr_183 = da.pat.TuplePattern([da.pat.ConstantPattern('msg3'), da.pat.TuplePattern([da.pat.FreePattern('A'), da.pat.FreePattern('B'), da.pat.FreePattern('nA'), da.pat.FreePattern('encBS')])])
PatternExpr_197 = da.pat.BoundPattern('_BoundPattern198_')
PatternExpr_269 = da.pat.TuplePattern([da.pat.ConstantPattern('msg2'), da.pat.FreePattern('encBS')])
PatternExpr_276 = da.pat.BoundPattern('_BoundPattern277_')
PatternExpr_311 = da.pat.TuplePattern([da.pat.ConstantPattern('msg4'), da.pat.FreePattern('encAS')])
PatternExpr_318 = da.pat.BoundPattern('_BoundPattern319_')
PatternExpr_359 = da.pat.TuplePattern([da.pat.ConstantPattern('msg6'), da.pat.FreePattern('encBA')])
PatternExpr_366 = da.pat.BoundPattern('_BoundPattern367_')
PatternExpr_429 = da.pat.TuplePattern([da.pat.ConstantPattern('msg1'), da.pat.FreePattern('A')])
PatternExpr_436 = da.pat.BoundPattern('_BoundPattern437_')
PatternExpr_459 = da.pat.TuplePattern([da.pat.ConstantPattern('msg5'), da.pat.FreePattern('encSB')])
PatternExpr_466 = da.pat.BoundPattern('_BoundPattern467_')
PatternExpr_513 = da.pat.TuplePattern([da.pat.ConstantPattern('msg7'), da.pat.FreePattern('enc_AB')])
PatternExpr_520 = da.pat.BoundPattern('_BoundPattern521_')
_config_object = {}
from sa.secalgoB import *

class RoleS(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleSReceivedEvent_0', PatternExpr_183, sources=[PatternExpr_197], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleS_handler_182])])

    def setup(self, kAS, kBS, **rest_599):
        super().setup(kAS=kAS, kBS=kBS, **rest_599)
        self._state.kAS = kAS
        self._state.kBS = kBS
        at_fork()
        self._state.terminate = False

    def run(self):
        super()._label('_st_label_178', block=False)
        _st_label_178 = 0
        while (_st_label_178 == 0):
            _st_label_178 += 1
            if self._state.terminate:
                _st_label_178 += 1
            else:
                super()._label('_st_label_178', block=True)
                _st_label_178 -= 1

    def _RoleS_handler_182(self, A, B, nA, encBS):
        nB1 = None

        def ExistentialOpExpr_200():
            nonlocal nB1
            for (_BoundPattern203_, nB1) in [decrypt(encBS, key=self._state.kBS)]:
                if (_BoundPattern203_ == A):
                    if True:
                        return True
            return False
        if ExistentialOpExpr_200():
            kAB = keygen('shared')
            self.send(('msg4', encrypt((nA, kAB, B, encrypt((kAB, nB1, A), key=self._state.kBS)), key=self._state.kAS)), to=A)
        self._state.terminate = True
    _RoleS_handler_182._labels = None
    _RoleS_handler_182._notlabels = None

class RoleA(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._RoleAReceivedEvent_0 = []
        self._RoleAReceivedEvent_1 = []
        self._RoleAReceivedEvent_2 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_0', PatternExpr_269, sources=[PatternExpr_276], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_1', PatternExpr_311, sources=[PatternExpr_318], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_2', PatternExpr_359, sources=[PatternExpr_366], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kAS, B, **rest_599):
        super().setup(S=S, kAS=kAS, B=B, **rest_599)
        self._state.S = S
        self._state.kAS = kAS
        self._state.B = B
        at_fork()

    def run(self):
        self.send(('msg1', self._id), to=self._state.B)
        super()._label('_st_label_266', block=False)
        encBS = None

        def ExistentialOpExpr_267():
            nonlocal encBS
            for (_, (_, _, _BoundPattern284_), (_ConstantPattern286_, encBS)) in self._RoleAReceivedEvent_0:
                if (_BoundPattern284_ == self._state.B):
                    if (_ConstantPattern286_ == 'msg2'):
                        if True:
                            return True
            return False
        _st_label_266 = 0
        while (_st_label_266 == 0):
            _st_label_266 += 1
            if ExistentialOpExpr_267():
                _st_label_266 += 1
            else:
                super()._label('_st_label_266', block=True)
                _st_label_266 -= 1
        nA = nonce()
        self.send(('msg3', (self._id, self._state.B, nA, encBS)), to=self._state.S)
        super()._label('_st_label_308', block=False)
        kAB = encAS = encSB = None

        def ExistentialOpExpr_309():
            nonlocal kAB, encAS, encSB
            for (_, (_, _, _BoundPattern326_), (_ConstantPattern328_, encAS)) in self._RoleAReceivedEvent_1:
                if (_BoundPattern326_ == self._state.S):
                    if (_ConstantPattern328_ == 'msg4'):

                        def ExistentialOpExpr_332(encAS):
                            nonlocal kAB, encSB
                            for (_BoundPattern335_, kAB, _BoundPattern338_, encSB) in [decrypt(encAS, key=self._state.kAS)]:
                                if (_BoundPattern335_ == nA):
                                    if (_BoundPattern338_ == self._state.B):
                                        if True:
                                            return True
                            return False
                        if ExistentialOpExpr_332(encAS=encAS):
                            return True
            return False
        _st_label_308 = 0
        while (_st_label_308 == 0):
            _st_label_308 += 1
            if ExistentialOpExpr_309():
                _st_label_308 += 1
            else:
                super()._label('_st_label_308', block=True)
                _st_label_308 -= 1
        self.send(('msg5', encSB), to=self._state.B)
        super()._label('_st_label_356', block=False)
        encBA = None

        def ExistentialOpExpr_357():
            nonlocal encBA
            for (_, (_, _, _BoundPattern374_), (_ConstantPattern376_, encBA)) in self._RoleAReceivedEvent_2:
                if (_BoundPattern374_ == self._state.B):
                    if (_ConstantPattern376_ == 'msg6'):
                        if True:
                            return True
            return False
        _st_label_356 = 0
        while (_st_label_356 == 0):
            _st_label_356 += 1
            if ExistentialOpExpr_357():
                _st_label_356 += 1
            else:
                super()._label('_st_label_356', block=True)
                _st_label_356 -= 1
        nB = decrypt(encBA, key=kAB)
        self.send(('msg7', encrypt((nB - 1), key=kAB)), to=self._state.B)
        self.output('A - Key Exchange Complete')

class RoleB(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._RoleBReceivedEvent_1 = []
        self._RoleBReceivedEvent_2 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_0', PatternExpr_429, sources=[PatternExpr_436], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleB_handler_428]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_1', PatternExpr_459, sources=[PatternExpr_466], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_2', PatternExpr_513, sources=[PatternExpr_520], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kBS, **rest_599):
        super().setup(S=S, kBS=kBS, **rest_599)
        self._state.S = S
        self._state.kBS = kBS
        at_fork()
        self._state.terminate = False

    def run(self):
        super()._label('_st_label_424', block=False)
        _st_label_424 = 0
        while (_st_label_424 == 0):
            _st_label_424 += 1
            if self._state.terminate:
                _st_label_424 += 1
            else:
                super()._label('_st_label_424', block=True)
                _st_label_424 -= 1

    def _RoleB_handler_428(self, A):
        nB1 = nonce()
        self.send(('msg2', encrypt((A, nB1), key=self._state.kBS)), to=A)
        super()._label('_st_label_456', block=False)
        kAB = encSB = None

        def ExistentialOpExpr_457():
            nonlocal kAB, encSB
            for (_, (_, _, _BoundPattern474_), (_ConstantPattern476_, encSB)) in self._RoleBReceivedEvent_1:
                if (_BoundPattern474_ == A):
                    if (_ConstantPattern476_ == 'msg5'):

                        def ExistentialOpExpr_480(encSB):
                            nonlocal kAB
                            for (kAB, _BoundPattern485_, _BoundPattern486_) in [decrypt(encSB, key=self._state.kBS)]:
                                if (_BoundPattern485_ == nB1):
                                    if (_BoundPattern486_ == A):
                                        if True:
                                            return True
                            return False
                        if ExistentialOpExpr_480(encSB=encSB):
                            return True
            return False
        _st_label_456 = 0
        while (_st_label_456 == 0):
            _st_label_456 += 1
            if ExistentialOpExpr_457():
                _st_label_456 += 1
            else:
                super()._label('_st_label_456', block=True)
                _st_label_456 -= 1
        nB2 = nonce()
        self.send(('msg6', encrypt(nB2, key=kAB)), to=A)
        super()._label('_st_label_510', block=False)
        enc_AB = None

        def ExistentialOpExpr_511():
            nonlocal enc_AB
            for (_, (_, _, _BoundPattern528_), (_ConstantPattern530_, enc_AB)) in self._RoleBReceivedEvent_2:
                if (_BoundPattern528_ == A):
                    if (_ConstantPattern530_ == 'msg7'):
                        if ((nB2 - 1) == decrypt(enc_AB, key=kAB)):
                            return True
            return False
        _st_label_510 = 0
        while (_st_label_510 == 0):
            _st_label_510 += 1
            if ExistentialOpExpr_511():
                _st_label_510 += 1
            else:
                super()._label('_st_label_510', block=True)
                _st_label_510 -= 1
        self.output('B - Key Exchange Complete')
        self._state.terminate = True
    _RoleB_handler_428._labels = None
    _RoleB_handler_428._notlabels = None

class Node_(da.NodeProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._events.extend([])

    def run(self):
        kAS = keygen('shared')
        kBS = keygen('shared')
        S = self.new(RoleS, (kAS, kBS))
        B = self.new(RoleB, (S, kBS))
        A = self.new(RoleA, (S, kAS, B))
        self._start(S)
        self._start(B)
        self._start(A)