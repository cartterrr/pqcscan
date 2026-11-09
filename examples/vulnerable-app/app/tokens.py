import jwt


def issue(claims, key):
    return jwt.encode(claims, key, algorithm="RS256")
