from .portal import PortalContext
from .workload_breg import BRegWorkload
from .workload_casework import CaseworkWorkload, HolderCaseworkWorkload

class PersonProducts:
    breg: BRegWorkload
    casework: CaseworkWorkload | HolderCaseworkWorkload
    subject: str
    principal: str
    persona: str
    csrf_token: str

def bind_person(
    context: PortalContext,
    *,
    persona: str,
    breg_url: str,
    casework_url: str,
    casework_profile: str,
) -> PersonProducts: ...
