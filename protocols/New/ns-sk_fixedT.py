# -*- generated by 1.0.12 -*-
import da
PatternExpr_192 = da.pat.TuplePattern([da.pat.ConstantPattern('msg3'), da.pat.FreePattern('i'), da.pat.TuplePattern([da.pat.FreePattern('A'), da.pat.FreePattern('B'), da.pat.FreePattern('nA'), da.pat.FreePattern('encBS')])])
PatternExpr_208 = da.pat.BoundPattern('_BoundPattern209_')
PatternExpr_291 = da.pat.TuplePattern([da.pat.ConstantPattern('msg2'), da.pat.BoundPattern('_BoundPattern294_'), da.pat.FreePattern('encBS')])
PatternExpr_299 = da.pat.BoundPattern('_BoundPattern300_')
PatternExpr_336 = da.pat.TuplePattern([da.pat.ConstantPattern('msg4'), da.pat.BoundPattern('_BoundPattern339_'), da.pat.FreePattern('encAS')])
PatternExpr_344 = da.pat.BoundPattern('_BoundPattern345_')
PatternExpr_387 = da.pat.TuplePattern([da.pat.ConstantPattern('msg6'), da.pat.BoundPattern('_BoundPattern390_'), da.pat.FreePattern('encBA')])
PatternExpr_395 = da.pat.BoundPattern('_BoundPattern396_')
PatternExpr_469 = da.pat.TuplePattern([da.pat.ConstantPattern('msg1'), da.pat.FreePattern('i'), da.pat.FreePattern('A')])
PatternExpr_478 = da.pat.BoundPattern('_BoundPattern479_')
PatternExpr_502 = da.pat.TuplePattern([da.pat.ConstantPattern('msg5'), da.pat.BoundPattern('_BoundPattern505_'), da.pat.FreePattern('encSB')])
PatternExpr_510 = da.pat.BoundPattern('_BoundPattern511_')
PatternExpr_559 = da.pat.TuplePattern([da.pat.ConstantPattern('msg7'), da.pat.BoundPattern('_BoundPattern562_'), da.pat.FreePattern('enc_AB')])
PatternExpr_567 = da.pat.BoundPattern('_BoundPattern568_')
_config_object = {}
import sys
from sa.secalgoB import *

class RoleS(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleSReceivedEvent_0', PatternExpr_192, sources=[PatternExpr_208], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleS_handler_191])])

    def setup(self, kAS, kBS, loops, **rest_666):
        super().setup(kAS=kAS, kBS=kBS, loops=loops, **rest_666)
        self._state.kAS = kAS
        self._state.kBS = kBS
        self._state.loops = loops
        at_fork()
        self._state.terminate = False

    @dec_proto_run_timer
    def run(self):
        self._state.terminate = False
        super()._label('_st_label_187', block=False)
        _st_label_187 = 0
        while (_st_label_187 == 0):
            _st_label_187 += 1
            if self._state.terminate:
                _st_label_187 += 1
            else:
                super()._label('_st_label_187', block=True)
                _st_label_187 -= 1

    def _RoleS_handler_191(self, i, A, B, nA, encBS):
        nB1 = None

        def ExistentialOpExpr_211():
            nonlocal nB1
            for (_BoundPattern214_, nB1) in [decrypt(encBS, key=self._state.kBS)]:
                if (_BoundPattern214_ == A):
                    if True:
                        return True
            return False
        if ExistentialOpExpr_211():
            kAB = keygen('shared')
            self.send(('msg4', i, encrypt((nA, kAB, B, encrypt((kAB, nB1, A), key=self._state.kBS)), key=self._state.kAS)), to=A)
        self._state.terminate = True
    _RoleS_handler_191._labels = None
    _RoleS_handler_191._notlabels = None

class RoleA(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._RoleAReceivedEvent_0 = []
        self._RoleAReceivedEvent_1 = []
        self._RoleAReceivedEvent_2 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_0', PatternExpr_291, sources=[PatternExpr_299], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_1', PatternExpr_336, sources=[PatternExpr_344], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleAReceivedEvent_2', PatternExpr_387, sources=[PatternExpr_395], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kAS, B, loops, **rest_666):
        super().setup(S=S, kAS=kAS, B=B, loops=loops, **rest_666)
        self._state.S = S
        self._state.kAS = kAS
        self._state.B = B
        self._state.loops = loops
        at_fork()
        self._state.i = 1

    @dec_proto_run_timer
    def run(self):
        self.send(('msg1', self._state.i, self._id), to=self._state.B)
        super()._label('_st_label_288', block=False)
        encBS = None

        def ExistentialOpExpr_289():
            nonlocal encBS
            for (_, (_, _, _BoundPattern307_), (_ConstantPattern309_, _BoundPattern311_, encBS)) in self._RoleAReceivedEvent_0:
                if (_BoundPattern307_ == self._state.B):
                    if (_ConstantPattern309_ == 'msg2'):
                        if (_BoundPattern311_ == self._state.i):
                            if True:
                                return True
            return False
        _st_label_288 = 0
        while (_st_label_288 == 0):
            _st_label_288 += 1
            if ExistentialOpExpr_289():
                _st_label_288 += 1
            else:
                super()._label('_st_label_288', block=True)
                _st_label_288 -= 1
        nA = nonce()
        self.send(('msg3', self._state.i, (self._id, self._state.B, nA, encBS)), to=self._state.S)
        super()._label('_st_label_333', block=False)
        kAB = encAS = encSB = None

        def ExistentialOpExpr_334():
            nonlocal kAB, encAS, encSB
            for (_, (_, _, _BoundPattern352_), (_ConstantPattern354_, _BoundPattern356_, encAS)) in self._RoleAReceivedEvent_1:
                if (_BoundPattern352_ == self._state.S):
                    if (_ConstantPattern354_ == 'msg4'):
                        if (_BoundPattern356_ == self._state.i):

                            def ExistentialOpExpr_359(encAS):
                                nonlocal kAB, encSB
                                for (_BoundPattern362_, kAB, _BoundPattern365_, encSB) in [decrypt(encAS, key=self._state.kAS)]:
                                    if (_BoundPattern362_ == nA):
                                        if (_BoundPattern365_ == self._state.B):
                                            if True:
                                                return True
                                return False
                            if ExistentialOpExpr_359(encAS=encAS):
                                return True
            return False
        _st_label_333 = 0
        while (_st_label_333 == 0):
            _st_label_333 += 1
            if ExistentialOpExpr_334():
                _st_label_333 += 1
            else:
                super()._label('_st_label_333', block=True)
                _st_label_333 -= 1
        self.send(('msg5', self._state.i, encSB), to=self._state.B)
        super()._label('_st_label_384', block=False)
        encBA = None

        def ExistentialOpExpr_385():
            nonlocal encBA
            for (_, (_, _, _BoundPattern403_), (_ConstantPattern405_, _BoundPattern407_, encBA)) in self._RoleAReceivedEvent_2:
                if (_BoundPattern403_ == self._state.B):
                    if (_ConstantPattern405_ == 'msg6'):
                        if (_BoundPattern407_ == self._state.i):
                            if True:
                                return True
            return False
        _st_label_384 = 0
        while (_st_label_384 == 0):
            _st_label_384 += 1
            if ExistentialOpExpr_385():
                _st_label_384 += 1
            else:
                super()._label('_st_label_384', block=True)
                _st_label_384 -= 1
        nB = decrypt(encBA, key=kAB)
        self.send(('msg7', self._state.i, encrypt((nB - 1), key=kAB)), to=self._state.B)
        self.output('A - Key Exchange Complete')
        self._state.i += 1

class RoleB(da.DistProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._RoleBReceivedEvent_1 = []
        self._RoleBReceivedEvent_2 = []
        self._events.extend([da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_0', PatternExpr_469, sources=[PatternExpr_478], destinations=None, timestamps=None, record_history=None, handlers=[self._RoleB_handler_468]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_1', PatternExpr_502, sources=[PatternExpr_510], destinations=None, timestamps=None, record_history=True, handlers=[]), da.pat.EventPattern(da.pat.ReceivedEvent, '_RoleBReceivedEvent_2', PatternExpr_559, sources=[PatternExpr_567], destinations=None, timestamps=None, record_history=True, handlers=[])])

    def setup(self, S, kBS, loops, **rest_666):
        super().setup(S=S, kBS=kBS, loops=loops, **rest_666)
        self._state.S = S
        self._state.kBS = kBS
        self._state.loops = loops
        at_fork()
        self._state.terminate = False

    @dec_proto_run_timer
    def run(self):
        self._state.terminate = False
        super()._label('_st_label_464', block=False)
        _st_label_464 = 0
        while (_st_label_464 == 0):
            _st_label_464 += 1
            if self._state.terminate:
                _st_label_464 += 1
            else:
                super()._label('_st_label_464', block=True)
                _st_label_464 -= 1

    def _RoleB_handler_468(self, i, A):
        nB1 = nonce()
        self.send(('msg2', i, encrypt((A, nB1), key=self._state.kBS)), to=A)
        super()._label('_st_label_499', block=False)
        encSB = kAB = None

        def ExistentialOpExpr_500():
            nonlocal encSB, kAB
            for (_, (_, _, _BoundPattern518_), (_ConstantPattern520_, _BoundPattern522_, encSB)) in self._RoleBReceivedEvent_1:
                if (_BoundPattern518_ == A):
                    if (_ConstantPattern520_ == 'msg5'):
                        if (_BoundPattern522_ == i):

                            def ExistentialOpExpr_525(encSB):
                                nonlocal kAB
                                for (kAB, _BoundPattern530_, _BoundPattern531_) in [decrypt(encSB, key=self._state.kBS)]:
                                    if (_BoundPattern530_ == nB1):
                                        if (_BoundPattern531_ == A):
                                            if True:
                                                return True
                                return False
                            if ExistentialOpExpr_525(encSB=encSB):
                                return True
            return False
        _st_label_499 = 0
        while (_st_label_499 == 0):
            _st_label_499 += 1
            if ExistentialOpExpr_500():
                _st_label_499 += 1
            else:
                super()._label('_st_label_499', block=True)
                _st_label_499 -= 1
        nB2 = nonce()
        self.send(('msg6', i, encrypt(nB2, key=kAB)), to=A)
        super()._label('_st_label_556', block=False)
        enc_AB = None

        def ExistentialOpExpr_557():
            nonlocal enc_AB
            for (_, (_, _, _BoundPattern575_), (_ConstantPattern577_, _BoundPattern579_, enc_AB)) in self._RoleBReceivedEvent_2:
                if (_BoundPattern575_ == A):
                    if (_ConstantPattern577_ == 'msg7'):
                        if (_BoundPattern579_ == i):
                            if ((nB2 - 1) == decrypt(enc_AB, key=kAB)):
                                return True
            return False
        _st_label_556 = 0
        while (_st_label_556 == 0):
            _st_label_556 += 1
            if ExistentialOpExpr_557():
                _st_label_556 += 1
            else:
                super()._label('_st_label_556', block=True)
                _st_label_556 -= 1
        self.output('B - Key Exchange Complete')
        self._state.terminate = True
    _RoleB_handler_468._labels = None
    _RoleB_handler_468._notlabels = None

class Node_(da.NodeProcess):

    def __init__(self, procimpl, props):
        super().__init__(procimpl, props)
        self._events.extend([])

    def run(self):
        loops = (int(sys.argv[1]) if (len(sys.argv) > 1) else 1)
        kAS = keygen('shared')
        kBS = keygen('shared')
        S = self.new(RoleS, (kAS, kBS, loops))
        B = self.new(RoleB, (S, kBS, loops))
        A = self.new(RoleA, (S, kAS, B, loops))
        self._start(S)
        self._start(B)
        self._start(A)