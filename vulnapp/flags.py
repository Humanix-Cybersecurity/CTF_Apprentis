"""
Dérivation des flags pour le CTF.

Deux modes :
- Statique (par défaut) : les flags sont en clair. Simple à corriger côté prof.
- Unique par élève : si la variable d'env STUDENT_ID est définie, chaque flag
  reçoit un suffixe HMAC-SHA256 tronqué (8 hex) pour l'anti-triche.

Formule (mode unique) :
    flag = "HUMANIX{" + base + "_" + hmac_sha256(STUDENT_ID, base)[:8] + "}"
"""
import hmac
import hashlib
import os

# Base de chaque flag -> numéro de challenge
_BASES = {
    "idor_profile_leak":           1,
    "view_source_is_your_friend":  2,
    "admin_admin_classic":         3,
    "debug_left_in_prod":          4,
    "alert_xss_pwned":             5,
    "or_1_equals_1_works":         6,
    "base64_is_not_crypto":        7,
    "jwt_alg_none_lol":            8,
    "api_leaks_everything":        9,
    "business_logic_broken":       10,
    "dot_dot_slash_classic":       11,
    "no_rate_limit_no_problem":    12,
    "union_select_treasure":       13,
    "md5_is_dead_use_argon2":      14,
    "cors_star_with_creds":        15,
    "coupon_stacking_oops":        16,
    "logs_should_not_leak":        17,
    "ssti_jinja_owned":            18,
    "ssrf_localhost_oracle":       19,
    "stored_xss_persistent_pain":  20,
    # --- Bonus : hors OWASP Top 10 ---
    "race_condition_double_spend":     21,
    "crlf_injection_header_split":     22,
    "host_header_poisoning":           23,
    "mass_assignment_role_escalation": 24,
    "insecure_random_predictable":     25,
    "open_redirect_unvalidated":       26,
    "timing_attack_side_channel":      27,
    "eval_code_execution":             28,
    "pickle_deserialization_rce":      29,
    "redos_catastrophic_backtrack":    30,
}

STUDENT_ID = os.environ.get("STUDENT_ID", "").strip()


def flag(base: str) -> str:
    """Renvoie le flag canonique pour une base donnée."""
    if base not in _BASES:
        raise KeyError(f"Base de flag inconnue : {base!r}")
    if STUDENT_ID:
        digest = hmac.new(
            STUDENT_ID.encode(), base.encode(), hashlib.sha256
        ).hexdigest()[:8]
        return f"HUMANIX{{{base}_{digest}}}"
    return f"HUMANIX{{{base}}}"


def all_flags() -> dict:
    """Tous les flags indexés par numéro de challenge (1..20)."""
    return {num: flag(base) for base, num in sorted(_BASES.items(), key=lambda x: x[1])}


if __name__ == "__main__":
    mode = f"UNIQUE (STUDENT_ID={STUDENT_ID!r})" if STUDENT_ID else "STATIQUE"
    print(f"Mode : {mode}\n")
    for num, fl in all_flags().items():
        print(f"  #{num:>2}  {fl}")
