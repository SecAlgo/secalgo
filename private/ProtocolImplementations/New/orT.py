# -*- generated by 1.1.0b13 -*-
import da
PatternExpr_190 = da.pat.TuplePattern([da.pat.ConstantPattern('msg2'), da.pat.FreePattern('i'), da.pat.TuplePattern([da.pat.FreePattern('M'), da.pat.FreePattern('A'), da.pat.FreePattern('B'), da.pat.FreePattern('encAS'), da.pat.FreePattern('encBS')])])
PatternExpr_208 = da.pat.FreePattern('B')
PatternExpr_330 = da.pat.TuplePattern([da.pat.ConstantPattern('msg4'), da.pat.BoundPattern('_BoundPattern333_'), da.pat.TuplePattern([da.pat.BoundPattern('_BoundPattern334_'), da.pat.FreePattern('encSA')])])
PatternExpr_340 = da.pat.BoundPattern('_BoundPattern341_')
PatternExpr_408 = da.pat.TuplePattern([da.pat.ConstantPattern('msg1'), da.pat.FreePattern('i'), da.pat.TuplePattern([da.pat.FreePattern('M'), da.pat.FreePattern('A'), da.pat.SelfPattern(), da.pat.FreePattern('encAS')])])
PatternExpr_424 = da.pat.FreePattern('A')
PatternExpr_455 = da.pat.TuplePattern([da.pat.ConstantPattern('msg3'), da.pat.BoundPattern('_BoundPattern458_'), da.pat.TuplePattern([da.pat.BoundPattern('_BoundPattern459_'), da.pat.FreePattern('encSA'), da.pat.FreePattern('encSB')])])
PatternExpr_467 = da.pat.BoundPattern('_BoundPattern468_')
_config_object = {}
from sa.secalgoB import *
from sa.timers import dec_proto_run_timer

class RoleS(da.DistProcess):

    def __init__(self, procimpl, forwarder, **props):
        super().__init__(procimpl, forwarder, **props)
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleSReceivedEvent_0', PatternExpr_190, sources=[PatternExpr_208], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleS_handler_189])])

    def setup(self, kAS, kBS, **rest_566):
        super().setup(kAS=kAS, kBS=kBS, **rest_566)
        self._state.kAS = kAS
        self._state.kBS = kBS
        at_fork()
        self._state.terminate = False

    @dec_proto_run_timer
    def run(self):
        self._state.terminate = False
        super()._label('_st_label_185', block=False)
        _st_label_185 = 0
        while (_st_label_185 == 0):
            _st_label_185 += 1
            if self._state.terminate:
                _st_label_185 += 1
            else:
                super()._label('_st_label_185', block=True)
                _st_label_185 -= 1

    def _RoleS_handler_189(self, i, M, A, B, encAS, encBS):
        nA = None

        def ExistentialOpExpr_211():
            nonlocal nA
            for (nA, _BoundPattern216_, _BoundPattern217_, _BoundPattern218_) in [decrypt(encAS, key=self._state.kAS)]:
                if (_BoundPattern216_ == M):
                    if (_BoundPattern217_ == A):
                        if (_BoundPattern218_ == B):
                            if True:
                                return True
            return False
        if ExistentialOpExpr_211():
            nB = None

            def ExistentialOpExpr_228():
                nonlocal nB
                for (nB, _BoundPattern233_, _BoundPattern234_, _BoundPattern235_) in [decrypt(encBS, key=self._state.kBS)]:
                    if (_BoundPattern233_ == M):
                        if (_BoundPattern234_ == A):
                            if (_BoundPattern235_ == B):
                                if True:
                                    return True
                return False
            if ExistentialOpExpr_228():
                kAB = keygen('shared')
                self.send(('msg3', i, (M, encrypt((nA, kAB), key=self._state.kAS), encrypt((nB, kAB), key=self._state.kBS))), to=B)
        self._state.terminate = True
    _RoleS_handler_189._labels = None
    _RoleS_handler_189._notlabels = None

class RoleA(da.DistProcess):

    def __init__(self, procimpl, forwarder, **props):
        super().__init__(procimpl, forwarder, **props)
        self._RoleAReceivedEvent_0 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_0', PatternExpr_330, sources=[PatternExpr_340], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kAS, B, **rest_566):
        super().setup(S=S, kAS=kAS, B=B, **rest_566)
        self._state.S = S
        self._state.kAS = kAS
        self._state.B = B
        at_fork()
        self._state.i = 1

    @dec_proto_run_timer
    def run(self):
        M = nonce()
        nA = nonce()
        self.send(('msg1', self._state.i, (M, self._id, self._state.B, encrypt((nA, M, self._id, self._state.B), key=self._state.kAS))), to=self._state.B)
        super()._label('_st_label_327', block=False)
        encSA = kAB = None

        def ExistentialOpExpr_328():
            nonlocal encSA, kAB
            for (_, (_, _, _BoundPattern348_), (_ConstantPattern350_, _BoundPattern352_, (_BoundPattern354_, encSA))) in self._RoleAReceivedEvent_0:
                if (_BoundPattern348_ == self._state.B):
                    if (_ConstantPattern350_ == 'msg4'):
                        if (_BoundPattern352_ == self._state.i):
                            if (_BoundPattern354_ == M):

                                def ExistentialOpExpr_357(encSA):
                                    nonlocal kAB
                                    for (_BoundPattern360_, kAB) in [decrypt(encSA, key=self._state.kAS)]:
                                        if (_BoundPattern360_ == nA):
                                            if True:
                                                return True
                                    return False
                                if ExistentialOpExpr_357(encSA=encSA):
                                    return True
            return False
        _st_label_327 = 0
        while (_st_label_327 == 0):
            _st_label_327 += 1
            if ExistentialOpExpr_328():
                _st_label_327 += 1
            else:
                super()._label('_st_label_327', block=True)
                _st_label_327 -= 1
        self.output('A - Key Exchange Complete')
        self._state.i += 1

class RoleB(da.DistProcess):

    def __init__(self, procimpl, forwarder, **props):
        super().__init__(procimpl, forwarder, **props)
        self._RoleBReceivedEvent_1 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_0', PatternExpr_408, sources=[PatternExpr_424], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleB_handler_407]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_1', PatternExpr_455, sources=[PatternExpr_467], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kBS, **rest_566):
        super().setup(S=S, kBS=kBS, **rest_566)
        self._state.S = S
        self._state.kBS = kBS
        at_fork()
        self._state.terminate = False

    @dec_proto_run_timer
    def run(self):
        self._state.terminate = False
        super()._label('_st_label_403', block=False)
        _st_label_403 = 0
        while (_st_label_403 == 0):
            _st_label_403 += 1
            if self._state.terminate:
                _st_label_403 += 1
            else:
                super()._label('_st_label_403', block=True)
                _st_label_403 -= 1

    def _RoleB_handler_407(self, i, M, A, encAS):
        nB = nonce()
        self.send(('msg2', i, (M, A, self._id, encAS, encrypt((nB, M, A, self._id), key=self._state.kBS))), to=self._state.S)
        super()._label('_st_label_452', block=False)
        encSB = encSA = kAB = None

        def ExistentialOpExpr_453():
            nonlocal encSB, encSA, kAB
            for (_, (_, _, _BoundPattern475_), (_ConstantPattern477_, _BoundPattern479_, (_BoundPattern481_, encSA, encSB))) in self._RoleBReceivedEvent_1:
                if (_BoundPattern475_ == self._state.S):
                    if (_ConstantPattern477_ == 'msg3'):
                        if (_BoundPattern479_ == i):
                            if (_BoundPattern481_ == M):

                                def ExistentialOpExpr_485(encSB):
                                    nonlocal kAB
                                    for (_BoundPattern488_, kAB) in [decrypt(encSB, key=self._state.kBS)]:
                                        if (_BoundPattern488_ == nB):
                                            if True:
                                                return True
                                    return False
                                if ExistentialOpExpr_485(encSB=encSB):
                                    return True
            return False
        _st_label_452 = 0
        while (_st_label_452 == 0):
            _st_label_452 += 1
            if ExistentialOpExpr_453():
                _st_label_452 += 1
            else:
                super()._label('_st_label_452', block=True)
                _st_label_452 -= 1
        self.send(('msg4', i, (M, encSA)), to=A)
        self.output('B - Key Exchange Complete')
        self._state.terminate = True
    _RoleB_handler_407._labels = None
    _RoleB_handler_407._notlabels = None

class Node_(da.NodeProcess):

    def __init__(self, procimpl, forwarder, **props):
        super().__init__(procimpl, forwarder, **props)
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