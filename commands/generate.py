from builder.keybuilder import create_spiderkey

def run(name, password, seed=None):
    print(f"Creating SpiderKey '{name}'")

    create_spiderkey(name=name, password=password, seed=seed)

