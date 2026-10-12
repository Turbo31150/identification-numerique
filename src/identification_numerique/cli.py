"""
Interface en ligne de commande (CLI) pour l'Identification Numérique Souveraine.
Commandes : create, list, verify, revoke, audit.
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from datetime import datetime
from .core import SovereignIdentityManager, format_duration


def get_status_str(record) -> str:
    if record.revoked:
        return "❌ RÉVOQUÉ"
    if record.is_expired:
        return "⌛ EXPIRÉ"
    return "✅ ACTIF"


def cmd_create(args, manager: SovereignIdentityManager):
    raw_token, record = manager.create_identity(
        label=args.label,
        scope=args.scope,
        ttl=args.ttl,
        prefix=args.prefix
    )
    if args.json:
        print(json.dumps({
            "token": raw_token,
            "id": record.id,
            "label": record.label,
            "scope": record.scope,
            "expires_at": record.expires_at
        }, indent=2))
        return

    print("════════════════════════════════════════════════════════════════")
    print(" 🛡️  IDENTIFICATION NUMÉRIQUE SOUVERAINE — JETON GÉNÉRÉ")
    print("════════════════════════════════════════════════════════════════")
    print(f" ID        : {record.id}")
    print(f" Label     : {record.label}")
    print(f" Scope     : {record.scope}")
    print(f" Durée/TTL : {args.ttl}")
    exp_str = "Jamais (permanent)" if record.expires_at == 0 else datetime.fromtimestamp(record.expires_at).strftime("%Y-%m-%d %H:%M:%S")
    print(f" Expiration: {exp_str}")
    print("────────────────────────────────────────────────────────────────")
    print(f" Clé secrète (ATTENTION : affichée UNE SEULE FOIS) :")
    print(f"\n   👉  \033[1;32m{raw_token}\033[0m\n")
    print("────────────────────────────────────────────────────────────────")
    print(" ℹ️  Seule l'empreinte SHA-256 a été enregistrée de manière chiffrée.")
    print("════════════════════════════════════════════════════════════════")


def cmd_list(args, manager: SovereignIdentityManager):
    records = manager.list_identities(include_revoked=not args.active_only)
    if args.json:
        data = [{
            "id": r.id,
            "label": r.label,
            "scope": r.scope,
            "status": "revoked" if r.revoked else ("expired" if r.is_expired else "active"),
            "created_at": r.created_at,
            "expires_at": r.expires_at
        } for r in records]
        print(json.dumps(data, indent=2))
        return

    print("═════════════════════════════════════════════════════════════════════════════════")
    print(" 🛡️  REGISTRE D'IDENTIFICATION NUMÉRIQUE")
    print("═════════════════════════════════════════════════════════════════════════════════")
    print(f" {'ID':<15} {'LABEL':<24} {'SCOPE':<12} {'STATUT':<12} {'EXPIRATION'}")
    print("─────────────────────────────────────────────────────────────────────────────────")
    if not records:
        print("  Aucune identité enregistrée.")
    for r in records:
        exp = "Permanente" if r.expires_at == 0 else datetime.fromtimestamp(r.expires_at).strftime("%Y-%m-%d %H:%M")
        stat = get_status_str(r)
        print(f" {r.id:<15} {r.label[:22]:<24} {r.scope:<12} {stat:<12} {exp}")
    print("═════════════════════════════════════════════════════════════════════════════════")


def cmd_verify(args, manager: SovereignIdentityManager):
    res = manager.verify(args.token, required_scope=args.scope)
    if args.json:
        print(json.dumps({
            "valid": res.valid,
            "reason": res.reason,
            "label": res.record.label if res.record else None,
            "scope": res.record.scope if res.record else None
        }, indent=2))
        sys.exit(0 if res.valid else 1)

    if res.valid and res.record:
        print(f"\033[1;32m✓ IDENTITÉ VALIDE\033[0m : {res.record.label} (ID: {res.record.id}, Scope: {res.record.scope})")
        sys.exit(0)
    else:
        print(f"\033[1;31m✗ REJET D'AUTHENTIFICATION\033[0m : {res.reason}")
        sys.exit(1)


def cmd_revoke(args, manager: SovereignIdentityManager):
    ok = manager.revoke(args.target)
    if ok:
        print(f"\033[1;32m✓ Identité '{args.target}' révoquée avec succès.\033[0m")
    else:
        print(f"\033[1;33m⚠️ Aucune identité active trouvée pour '{args.target}'.\033[0m")


def main():
    parser = argparse.ArgumentParser(
        prog="identite",
        description="Gestionnaire d'Identification Numérique Souveraine — Zero-Trust & Protection des Accès."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = sub.add_parser("create", help="Créer une nouvelle identité / clé d'accès")
    p_create.add_argument("--label", "-l", required=True, help="Nom ou email de l'entité")
    p_create.add_argument("--scope", "-s", default="orbe", help="Portée / rôle (ex: orbe, admin, *)")
    p_create.add_argument("--ttl", "-t", default="30d", help="Durée de validité (ex: 30d, 24h, 0 pour illimité)")
    p_create.add_argument("--prefix", "-p", default="id_sec", help="Préfixe du jeton")
    p_create.add_argument("--json", action="store_true", help="Sortie JSON")

    # list
    p_list = sub.add_parser("list", help="Lister les identités enregistrées")
    p_list.add_argument("--active-only", "-a", action="store_true", help="Afficher uniquement les identités actives")
    p_list.add_argument("--json", action="store_true", help="Sortie JSON")

    # verify
    p_verify = sub.add_parser("verify", help="Vérifier la validité d'un jeton")
    p_verify.add_argument("token", help="Le jeton secret à vérifier")
    p_verify.add_argument("--scope", "-s", default=None, help="Scope minimal requis")
    p_verify.add_argument("--json", action="store_true", help="Sortie JSON")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Révoquer une identité par son ID ou Label")
    p_revoke.add_argument("target", help="ID (ex: id_a1b2c3) ou Label de l'identité")

    args = parser.parse_args()
    manager = SovereignIdentityManager()

    if args.command == "create":
        cmd_create(args, manager)
    elif args.command == "list":
        cmd_list(args, manager)
    elif args.command == "verify":
        cmd_verify(args, manager)
    elif args.command == "revoke":
        cmd_revoke(args, manager)


if __name__ == "__main__":
    main()
