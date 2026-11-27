"""Allowlisted, source-free diagnostic projection for the Chrome harness."""

import re

# Keep these in sync with the marker writer in browser-failures.mjs.
SETUP_PHASES = frozenset({
    'startup', 'preview-origin', 'candidate-report', 'corpus', 'graph-fixture', 'accessibility-setup',
    'worker-memory-report', 'browser-launch', 'cold-queries', 'hot-queries', 'cleanup', 'report-write', 'report-validation',
})
SAMPLE_PHASES = frozenset({
    'ui-context', 'hero', 'root-redirect', 'dataset-credits', 'overview', 'quality', 'class-c', 'asn', 'bgp',
    'unknown-states', 'ui-metrics', 'component-context', 'component-fixture', 'component-worker', 'component-keyboard-pan',
    'component-wheel-zoom', 'component-route-focus', 'component-accessibility', 'component-unknown-ipv4',
})
CLASSES = frozenset({
    'contract', 'playwright-timeout', 'runtime', 'report-validation', 'unexpected-request',
    'page-exception', 'asset-accounting', 'resource-observation', 'privacy-contract',
})
REPORT_GATE_CLASSES = frozenset({
    'gate-graph', 'gate-accessibility', 'gate-lcp', 'gate-initial-js', 'gate-cls', 'gate-inp',
    'gate-population', 'gate-candidate-states', 'gate-unknown-states', 'gate-ipv4', 'gate-synthetic-ipv4',
    'gate-worker-memory', 'gate-cold-payload', 'gate-hot-lookup',
})


def failure_label(line):
    parts = line.split(' ', 4)
    if len(parts) != 4:
        return None
    prefix, phase, sample, classification = parts
    if prefix != 'ATLAS_BROWSER_FAILURE':
        return None
    if phase == 'report-validation' and sample == '-' and classification in REPORT_GATE_CLASSES:
        return f'browser-report-validation-{classification}'
    if classification not in CLASSES:
        return None
    if phase in SAMPLE_PHASES and re.fullmatch(r'[1-9]|[12][0-9]|30', sample):
        return f'browser-{phase}-sample-{sample}-{classification}'
    if phase in SETUP_PHASES and sample == '-':
        return f'browser-{phase}-{classification}'
    return None
