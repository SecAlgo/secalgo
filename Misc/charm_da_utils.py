import json
from da.endpoint import EndPoint, TcpEndPoint, UdpEndPoint


'''
This class is used as a null group for passing to the bytesToObject, 
objectToBytes methods made available in charm.
'''
class Null_Group():
    def __init__(self):
        pass

    def serialize(self, obj):
        return obj

    def deserialize(self, obj):
        return obj
#end class Null_Group
    
def serialize_endpoint(ep):
    ep_state = ep.__getstate__()
    ep_state = [ep_state[0], list(ep_state[1]), ep_state[2], None]
    return json.dumps(ep_state)
    return ep_state

def deserialize_endpoint(ep_state):
    ep_state = json.loads(ep_state)
    #for st in ep_state:
    #   print('&&&&&&&&&&&&&&&', type(st))
    ep_state[1] = tuple(ep_state[1])
    ep_state = tuple(ep_state)
    ep = EndPoint()
    if ep_state[0] == "TCP":
        ep = TcpEndPoint()
    elif ep_state[0] == "UDP":
        ep = UdpEndPoint()
    ep.__setstate__(ep_state)
    return ep
