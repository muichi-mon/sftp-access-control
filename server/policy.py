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
    "read": "read",
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


# ---------------------------------------------------------------- Part 3: DAC, MAC, authorize()

# Unix style permission bits
R, W, X = 0o4, 0o2, 0o1

# Which mode (file_mode or dir_mode) and which bits each SFTP operation needs in DAC.
# Making, removing or deleting something changes the directory, so like on Unix
# it needs write + execute on the directory.
DAC_NEEDS = {
    "read": ("file", R),
    "write": ("file", W),
    "stat": ("file", R),
    "list": ("dir", R | X),
    "mkdir": ("dir", W | X),
    "rmdir": ("dir", W | X),
    "remove": ("dir", W | X),
}

# In MAC every operation is either reading information or writing it
MAC_READ_OPS = {"read", "stat", "list"}
MAC_WRITE_OPS = {"write", "mkdir", "rmdir", "remove"}


# Finds the most specific (longest) prefix in "table" that covers vpath
def _longest_match(vpath, table):
    best = None
    for prefix in table:
        if _prefix_matches(vpath, prefix):
            if best is None or len(_norm_path(prefix)) > len(_norm_path(best)):
                best = prefix
    return best


# A user is in the group named after each of their roles
def _in_group(cfg, user, group):
    if group in cfg.get("user_roles", {}).get(user, []):
        return True
    return user in (cfg.get("groups") or {}).get(group, [])


# DAC: owner / group / other bits from dac_owners.csv
# Return (allowed: bool, reason: str)
def check_dac(user, op, path, data=None):
    cfg = data if data is not None else _DATA
    if not cfg:
        return False, "DAC: policy data not initialized"
    if op not in DAC_NEEDS:
        return False, f"DAC: unsupported operation {op!r}"

    vpath = _norm_path(path)
    dac = cfg.get("dac", {})
    prefix = _longest_match(vpath, dac)
    if prefix is None:
        return False, f"DAC: no owner entry for {vpath}"
    entry = dac[prefix]

    kind, needed = DAC_NEEDS[op]
    # stat on one of the folders from dac_owners.csv is about the folder itself
    if op == "stat" and vpath == _norm_path(prefix):
        kind = "dir"
    mode = entry["dir_mode"] if kind == "dir" else entry["file_mode"]

    # Pick which three bits apply to this user: owner first, then group, then other
    if user == entry["owner"]:
        who, bits = "owner", (mode >> 6) & 0o7
    elif _in_group(cfg, user, entry["group"]):
        who, bits = "group", (mode >> 3) & 0o7
    else:
        who, bits = "other", mode & 0o7

    if bits & needed == needed:
        return True, f"DAC: {who} has {oct(needed)} on {prefix} ({kind} mode {oct(mode)})"
    return False, f"DAC: {who} lacks {oct(needed)} on {prefix} ({kind} mode {oct(mode)})"


# MAC: Bell-LaPadula, no read up and no write down
# Return (allowed: bool, reason: str)
def check_mac(user, op, path, data=None):
    cfg = data if data is not None else _DATA
    if not cfg:
        return False, "MAC: policy data not initialized"

    mac = cfg.get("mac", {})
    levels = mac.get("levels", [])
    clearance = mac.get("users", {}).get(user)
    if clearance not in levels:
        return False, f"MAC: no clearance for {user!r}"

    vpath = _norm_path(path)
    labels = mac.get("labels", {})
    prefix = _longest_match(vpath, labels)
    if prefix is None or labels[prefix] not in levels:
        return False, f"MAC: no label for {vpath}"
    label = labels[prefix]

    # Higher index = more secret (levels are listed lowest first)
    u, r = levels.index(clearance), levels.index(label)
    if op in MAC_READ_OPS:
        if u >= r:
            return True, f"MAC: {clearance} may read {label}"
        return False, f"MAC: no read up ({clearance} -> {label})"
    if op in MAC_WRITE_OPS:
        if u <= r:
            return True, f"MAC: {clearance} may write {label}"
        return False, f"MAC: no write down ({clearance} -> {label})"
    return False, f"MAC: unsupported operation {op!r}"


# The gate server.py calls before every filesystem action.
# Allowed only if DAC, MAC and RBAC all allow it. Every decision is audited.
# Return (allowed: bool, reason: str)
def authorize(user, op, path):
    vpath = _norm_path(path)

    if _DATA is None:
        allowed, reason = False, "policy data not initialized (default deny)"
    elif op == "realpath":
        # realpath only turns the path into its clean form, it never touches a file,
        # so every logged in user may do it (otherwise eve could not even start at "/")
        allowed, reason = True, "realpath only normalizes the path"
    elif op not in DAC_NEEDS:
        allowed, reason = False, f"unknown operation {op!r} (default deny)"
    else:
        results = [check_dac(user, op, vpath), check_mac(user, op, vpath), check_rbac(user, op, vpath)]
        allowed = all(ok for ok, _ in results)
        if allowed:
            reason = "allowed: " + "; ".join(r for _, r in results)
        else:
            reason = "denied: " + "; ".join(r for ok, r in results if not ok)

    audit.log(user, op, vpath, allowed, reason)
    return allowed, reason
