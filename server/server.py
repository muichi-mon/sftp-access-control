"""SSH transport + SFTP v3 handling.

Part 1 - Server protocol and hardening.
Uses loader.load_data() at startup, auth.check_password() for logins and
policy.authorize() before every file operation.
"""
