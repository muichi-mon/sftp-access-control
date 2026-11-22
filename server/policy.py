"""authorize(): DAC, MAC and RBAC.

Part 3 - Policy core: authorize(), DAC, MAC, audit logging of every decision
         (use audit.log(user, op, path, allowed, reason)).
Part 4 - RBAC and how the three models combine.
"""

import posixpath
import audit


# Translating each SFTP operation into RBAC permission 
OP_TO_RBAC_ACTION = {
    "realpath": "read",
    "stat": "read",
    "list": "read",
    "mkdir": "write",
    "write": "write",
    "remove": "delete",
    "rmdir": "delete",
}

#Stores the configuration from data at the startup of the server with init(data)
_DATA = None

# Saves the data in memory at the startup
def init(data):
    global _DATA
    _DATA = data

# Cleans up SFTP paths so comparisons are possible and easier
def _norm_path(path):
    if not path:
        return "/"
    norm = posixpath.normpath(path if path.startswith("/") else "/" + path)
    return "/" if norm in ("", ".") else norm

#Return True if "vpath" equls "prefix" or the folder of "prefix"
def _prefix_matches(vpath, prefix):
    prefix = _norm_path(prefix)
    if prefix == "/":
        return vpath.startswith("/")
    return vpath == prefix or vpath.startswith(prefix + "/")

#Decides wetehr the user is allowed to do an "operation" on "path" in RBAC
#Return (allowed: bool, reason: str)
def check_rbac(user, op, path, data=None):
    cfg = data if data is not None else _DATA
    #If policy data has not been loaded yet 
    if not cfg:
        return False, "RBAC: policy data not initialized"

    #Translate the SFTP operation into RBAC
    action = OP_TO_RBAC_ACTION.get(op)
    if action is None:
        return False, f"RBAC: unsupported operation {op!r}"

    vpath = _norm_path(path)
    user_roles = cfg.get("user_roles", {})
    role_perms = cfg.get("role_perms", {})

    # For unkown users: deny
    if user not in user_roles:
        return False, f"RBAC: unknown user {user!r}"
        
    # If user_overrrides - configured -> check "deny" for every user 
    overrides = (cfg.get("user_overrides") or {}).get(user, {})
    for rule in overrides.get("deny", []):
        if rule.get("action") == action and _prefix_matches(vpath, rule.get("prefix", "/")):
            return False, f"RBAC: explicit user deny on {rule.get('prefix')}"

    for rule in overrides.get("allow", []):
        if rule.get("action") == action and _prefix_matches(vpath, rule.get("prefix", "/")):
            return True, f"RBAC: explicit user allow on {rule.get('prefix')}"

    # Check every role assigned to the user and combine the permission
    roles = user_roles.get(user, [])
    allowed_actions = set()
    matched_prefixes = []

    # Find matching prefixes for this role; prefer longest (most specific) match
    for role in roles:
        perms_by_prefix = role_perms.get(role, {})
        matching = [
            (pfx, acts)
            for pfx, acts in perms_by_prefix.items()
            if _prefix_matches(vpath, pfx)
        ]
        # If a role has rules for both "/" and "/proejct" 
        #Sort by prefix length so most specific path is more important than"/""
        if matching:
            matching.sort(key=lambda item: len(_norm_path(item[0])), reverse=True)
            best_pfx, best_acts = matching[0]

            # Add the role'sallowed actions inot the combindes peremission from earlier
            allowed_actions |= set(best_acts)
            matched_prefixes.append(f"{role}:{best_pfx}")

    # Allow only if the required action was granted by at least one fo the user's roles
    #If not -> deny by default
    if action in allowed_actions:
        return True, f"RBAC: allowed ({action}) via {', '.join(matched_prefixes)}"

    return False, f"RBAC: denied ({action}) for roles {roles} on {vpath}"