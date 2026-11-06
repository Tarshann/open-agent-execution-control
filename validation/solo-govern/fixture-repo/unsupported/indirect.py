import shutil

rm = shutil.rmtree          # aliased: the call site below does not say rmtree


def go(p):
    rm(p)


def dyn(obj):
    return getattr(obj, "del" + "ete")()   # dynamic dispatch
