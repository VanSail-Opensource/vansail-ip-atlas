"""Closed, source-free Pages failure labels shared by uploader and CI."""

import re


PREFIX = 'ATLAS_PAGES_FAILURE'
PHASES = frozenset({
    'unknown', 'arguments', 'candidate', 'qualification', 'atlas-validation',
    'binary-inspection', 'frontend-inspection', 'authorization', 'credentials',
    'project', 'asset-preflight', 'asset-token', 'asset-hashes', 'asset-check',
    'asset-upload', 'asset-upsert', 'asset-final-check', 'deployment-create',
    'deployment-wait', 'deployment-identity', 'rollback-target', 'rollback',
    'served-preview', 'served-production', 'report',
})
CLASSES = frozenset({
    'contract', 'io', 'response', 'http-error', 'network-dns', 'network-timeout',
    'network-tls', 'network-connection', 'network-interrupted',
    'network-protocol', 'network-other',
})


def _is_class(value):
    return value in CLASSES or re.fullmatch(r'http-[1-5][0-9]{2}', value) is not None


def failure_marker(phase, classification):
    phase = phase if phase in PHASES else 'unknown'
    classification = classification if _is_class(classification) else 'contract'
    return f'{PREFIX} {phase} {classification}'


def failure_label(line):
    parts = line.split(' ', 3)
    if len(parts) != 3:
        return None
    prefix, phase, classification = parts
    if prefix != PREFIX or phase not in PHASES or not _is_class(classification):
        return None
    return f'pages-{phase}-{classification}'
