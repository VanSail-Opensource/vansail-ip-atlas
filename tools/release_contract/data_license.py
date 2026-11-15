"""Owner-approved data license; its exact notice is part of the frozen tree."""
from pathlib import Path
from .contracts import ContractError

LICENSE_ID = 'CC-BY-SA-4.0'
NOTICE = b'''VanSail IP Atlas compiled database

Original compilation material created by VanSail IP Atlas is offered under
Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
https://creativecommons.org/licenses/by-sa/4.0/

This grant covers only rights held by the project. Third-party datasets retain
their own licenses and conditions, described in the global dataset-credit
document accompanying each immutable release. Include applicable source notices
when reusing data. The project's educational-use decisions do not change upstream
terms or grant additional permissions. Public-domain material retains its
public-domain status. Source code and software notices have their own terms.
'''

def validate_data_license_tree(public: Path) -> None:
    path = public / 'data-license.txt'
    if path.is_symlink() or not path.is_file() or path.stat().st_size != len(NOTICE) or path.read_bytes() != NOTICE:
        raise ContractError('compiled database requires the exact approved compilation and source-terms notice')
