from __future__ import annotations

import getpass

from backend.app.security import hash_password


def main() -> None:
    password = getpass.getpass("New CyberGuard analyst password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords did not match.")
    try:
        encoded_hash = hash_password(password)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print("\nSet this value as CYBERGUARD_ANALYST_PASSWORD_HASH in your local environment:")
    print(encoded_hash)
    print("Do not commit this value or share it in chat.")


if __name__ == "__main__":
    main()
