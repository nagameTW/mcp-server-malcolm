"""Field renames Malcolm applies during ingest, for the field-not-found path.

Malcolm's logstash pipelines rewrite field names on the way into the index, so
the name an agent reasonably guesses -- the raw Zeek/Suricata name, or the plain
ECS name -- is frequently not the name stored. `MalcolmClient.resolve_field`
already catches the easy misses: separator and case differences
(`http.user_agent` -> `http.useragent`) and close string matches. What string
similarity cannot catch is a rename that shares no spelling with its target:
`suricata.alert.signature` is stored as `rule.name`, and difflib confidently
suggests `suricata.alert.rev` instead.

Only those semantic jumps live here. Every entry comes from a rename/merge in
Malcolm's `logstash/pipelines/` (cited per block); families that the existing
matching already resolves are deliberately left out so the table stays small
and stays true.

This is a correction surfaced only when a lookup has already failed -- it is
never pushed into the agent's context up front.
"""

from __future__ import annotations

# Raw Zeek columns that 1200_zeek_mutate.conf:33-47 hoists out of EVERY
# per-log-type object into one shared top-level field. So `zeek.dns.orig_h`
# does not exist -- `source.ip` does, for every Zeek log type alike.
_ZEEK_HOISTED: dict[str, str] = {
    "ts": "zeek.ts",
    "uid": "zeek.uid",
    "fuid": "zeek.fuid",
    "is_orig": "network.is_orig",
    "orig_h": "source.ip",
    "orig_p": "source.port",
    "orig_l2_addr": "source.mac",
    "resp_h": "destination.ip",
    "resp_p": "destination.port",
    "resp_l2_addr": "destination.mac",
    "proto": "network.transport",
    "service": "network.protocol",
    "user": "related.user",
    "password": "related.password",
    "community_id": "network.community_id",
}

# Prefixes whose trailing column name goes through _ZEEK_HOISTED: the nested
# form (zeek.conn.orig_h), Zeek's own JSON connection object (id.orig_h), and
# the pre-mutate staging object (zeek_cols.orig_h).
_ZEEK_PREFIXES = ("zeek.", "id.", "zeek_cols.")

_ALIASES: dict[str, str] = {
    # Suricata global renames, applied to every EVE event type.
    # suricata/11_suricata_logs.conf:161-172 (rename -- the source is gone).
    "suricata.src_ip": "source.ip",
    "suricata.src_port": "source.port",
    "suricata.dest_ip": "destination.ip",
    "suricata.dest_port": "destination.port",
    "suricata.proto": "network.transport",
    "suricata.app_proto": "network.protocol",
    "suricata.event_type": "event.dataset",
    "suricata.community_id": "network.community_id",
    "suricata.vlan": "network.vlan.id",
    "suricata.ether.src_mac": "source.mac",
    "suricata.ether.dest_mac": "destination.mac",
    # Suricata alert -> ECS rule.*
    # suricata/11_suricata_logs.conf:370-371 (rename), :379-384 (merge),
    # :437-446 (the source fields are then removed).
    "suricata.alert.signature": "rule.name",
    "suricata.alert.signature_id": "rule.id",
    "suricata.alert.category": "rule.category",
    "suricata.alert.metadata.former_category": "rule.category",
    # Zeek intel -> ECS threat.*  zeek/1300_zeek_normalize.conf:115
    "zeek.intel.seen_indicator": "threat.indicator.name",
    # DNS: Malcolm keeps Arkime's short names, not the ECS ones an agent
    # trained on ECS will reach for. zeek/1200_zeek_mutate.conf:515,536
    "dns.question.name": "dns.host",
    "dns.question.type": "dns.qt",
    # MAC vendor lookup lands in *.oui. enrichment/11_lookups.conf:51,95
    "source.mac_vendor": "source.oui",
    "destination.mac_vendor": "destination.oui",
    # Cross-log correlation: Malcolm parks the Zeek connection UID in Arkime's
    # rootId so Zeek logs, Suricata alerts and file-scan records that belong to
    # one flow can be joined. There is no `related.zeek.uid`.
    # zeek/1200_zeek_mutate.conf:69-74, filescan/11_parse.conf:126-128
    "related.zeek.uid": "rootId",
    "zeek.related.uid": "rootId",
}


def alias_for(name: str) -> str | None:
    """Return the indexed field name for a renamed field, or None if unknown.

    Args:
        name: The field name that was not found in the index mapping.

    Returns:
        The name Malcolm actually stores the value under, or None when no
        pipeline rename is known for this field.
    """
    if target := _ALIASES.get(name):
        return target

    if name.startswith(_ZEEK_PREFIXES):
        target = _ZEEK_HOISTED.get(name.rsplit(".", 1)[-1])
        # zeek.ts resolves to itself; that is a hit, not a rename.
        if target and target != name:
            return target

    return None
