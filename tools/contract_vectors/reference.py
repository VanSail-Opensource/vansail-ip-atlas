"""Small P0 contract oracle. Not the production compiler or a source parser.

Only already-normalized synthetic values enter these functions. Admission,
proof, lifetime, bounded parsing, and actual shard lookups remain separate gates.
"""

import ipaddress
import math


def observation(reliability, severity, specificity, age_hours, half_life_hours):
    values = (reliability, severity, specificity, age_hours, half_life_hours)
    if not all(math.isfinite(v) for v in values):
        raise ValueError("nonfinite")
    if not all(0 <= v <= 1 for v in values[:3]) or half_life_hours <= 0:
        raise ValueError("range")
    if age_hours < -24:
        raise ValueError("quarantined")
    return reliability * severity * specificity * 2 ** (
        -max(0, age_hours) / half_life_hours
    )


def layer(observations, signals):
    maximums = {}
    for signal, family, value in observations:
        signal = signals[signal].get("merge_into", signal)
        key = signal, family
        maximums[key] = max(maximums.get(key, 0), value)
    mass = 0.0
    for signal, config in signals.items():
        if "merge_into" in config:
            continue
        family_sum = sum(
            maximums[(signal, family)]
            for family in sorted(f for s, f in maximums if s == signal)
        )
        mass += config["beta"] * family_sum
    return 1 - math.exp(-mass)


def quality(ipv4, layers, complete_families, weights):
    qualifying = set.intersection(*(set(f) for f in complete_families))
    if not ipv4 or any(v is None for v in layers) or len(qualifying) < 2:
        return None, "unrated"
    risk = min(1, max(0, sum(v * w for v, w in zip(layers, weights))))
    score = math.floor(100 * (1 - risk) + 0.5)
    confidence = "high" if len(qualifying) >= 4 else "medium" if len(qualifying) == 3 else "low"
    return score, confidence


def asn_context(risks, families, explicit_risk):
    positive = [r for r in risks if r > 0]
    diversity = min(1, families / 3)
    confidence = diversity * min(1, len(positive) / 64)
    risk = max(explicit_risk, (1 - math.exp(-sum(positive) / 256)) * diversity)
    return risk, confidence, 0.15 * confidence * risk


def neighbor(query, observations):
    prefix = ipaddress.ip_network(query + "/24", strict=False)
    address_risk, families = {}, set()
    for address, risk, family in observations:
        if address == query or ipaddress.ip_address(address) not in prefix or risk <= 0:
            continue
        address_risk[address] = max(address_risk.get(address, 0), risk)
        families.add(family)
    density = sum(address_risk[a] for a in sorted(address_risk, key=ipaddress.ip_address)) / 255
    risk = 1 - math.exp(-16 * density)
    confidence = min(1, len(address_risk) / 16) * min(1, len(families) / 3)
    return density, risk, confidence


def geo_vote(votes, min_support, margin=0.15):
    by_family = {}
    for family, place, weight in votes:
        if place is not None and weight > 0:
            by_family.setdefault(family, []).append((place, weight))
    totals, support = {}, {}
    for records in by_family.values():
        highest = max(w for _, w in records)
        winners = {p for p, w in records if w == highest}
        if len(winners) != 1:
            continue
        place = next(iter(winners))
        totals[place] = totals.get(place, 0) + highest
        support[place] = support.get(place, 0) + 1
    if not totals:
        return None
    ranked = sorted(totals, key=lambda p: (-totals[p], p))
    winner = ranked[0]
    runner_up = totals[ranked[1]] if len(ranked) > 1 else 0
    if totals[winner] == runner_up or support[winner] < min_support:
        return None
    if min_support > 1 and (totals[winner] - runner_up) / sum(totals.values()) < margin:
        return None
    return winner


def relationship(provider, customer, start, end):
    if (start, end) == (customer, provider):
        return "transit_upstream"
    if (start, end) == (provider, customer):
        return "customer"
    return "unknown"


def percentile98(values):
    return sorted(values)[math.ceil(0.98 * len(values)) - 1]


def peer_core(nodes, peers):
    pool = set(nodes)
    edges = {frozenset(pair) for pair in peers}
    while len(pool) >= 3:
        degrees = {n: sum(frozenset((n, other)) in edges for other in pool if other != n) for n in pool}
        threshold = math.ceil(0.80 * (len(pool) - 1))
        if all(degree >= threshold for degree in degrees.values()):
            return sorted(pool)
        pool.remove(min(pool, key=lambda n: (degrees[n], -n)))
    return []


def stable_candidate(current, previous, separation_hours, same_policy, eligible):
    return "tier1_candidate" if (
        current and previous and 24 <= separation_hours <= 720 and same_policy and eligible
    ) else "unknown"


def graph_projection(ranked_routes, budget=24, protected_hops=2, exit_budget=3):
    """Return contiguous visible prefixes, never edges across omitted nodes."""
    selected, nodes = [], set()
    for original in ranked_routes:
        route = [n for i, n in enumerate(original) if i == 0 or n != original[i - 1]]
        if len(set(route)) != len(route):
            continue  # retained original loop has no simple-graph projection
        protected = set(route[:protected_hops + 1])
        if len(nodes | protected) <= budget:
            selected.append(route)
            nodes |= protected
    exits, visible = {}, []
    for route in selected:
        prefix = route[:protected_hops + 1]
        second = route[protected_hops] if len(route) > protected_hops else None
        for index, node in enumerate(route[protected_hops + 1:], protected_hops + 1):
            if len(nodes | {node}) > budget:
                break
            if index == protected_hops + 1 and second is not None:
                known = exits.setdefault(second, set())
                if node not in known and len(known) >= exit_budget:
                    break
                known.add(node)
            prefix.append(node)
            nodes.add(node)
        visible.append(prefix)
    return visible


def rpki(prefix, origin, vrps):
    if vrps is None:
        return "unknown"
    announcement = ipaddress.ip_network(prefix)
    covering = [(ipaddress.ip_network(p), maximum, asn) for p, maximum, asn in vrps
                if announcement.version == ipaddress.ip_network(p).version
                and announcement.subnet_of(ipaddress.ip_network(p))]
    if any(origin == asn and announcement.prefixlen <= maximum for _, maximum, asn in covering):
        return "valid"
    return "invalid" if covering else "not_found"
