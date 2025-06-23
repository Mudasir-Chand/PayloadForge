import random

def obfuscate(payload):
    return payload.replace(" ", random.choice(["/**/", "%20", "+"]))
