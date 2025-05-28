from builder.keybuilder import create_spiderkey

def run(name, password, seed=None):
    print(f"Creating SpiderKey '{name}'")
    if seed:
        print(f"Using seed: {seed}")
    else:
        print("Generating with random entropy")

    create_spiderkey(name=name, password=password, seed=seed)

