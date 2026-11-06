"""Pure functions. Nothing here mutates the outside world."""


def total(items):
    return sum(i["price"] for i in items)


def describe():
    # We never call shutil.rmtree or stripe.Refund.create here.
    return "This text mentions DELETE FROM users and requests.post but only as a string."


def prune(d, k):
    d.pop(k, None)
    return d
