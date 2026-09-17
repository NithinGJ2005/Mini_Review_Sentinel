def run(code):
    # Demonstrates dangerous dynamic execution of untrusted input
    return eval(code)
