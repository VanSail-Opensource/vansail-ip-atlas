"""Owner-approved data license; its exact notice is part of the frozen tree."""
from pathlib import Path
from .contracts import ContractError

LICENSE_ID = 'CC-BY-SA-4.0'
NOTICE = b'''VanSail IP Atlas compiled database

The compiled database and its licensable derived database material are offered
under Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
https://creativecommons.org/licenses/by-sa/4.0/

Include the applicable dataset notices when redistributing the database. Those
notices accompany each immutable release in its global dataset-credit document.
Public-domain material retains its public-domain status. This license applies
to compiled database material; software notices have their own terms.
'''

def validate_data_license_tree(public: Path) -> None:
    path = public / 'data-license.txt'
    if path.is_symlink() or not path.is_file() or path.stat().st_size != len(NOTICE) or path.read_bytes() != NOTICE:
        raise ContractError('compiled database requires the exact owner-approved CC BY-SA 4.0 notice')
