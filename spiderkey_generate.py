import argparse
from commands import generate

def main():
    parser = argparse.ArgumentParser(
        prog="spiderkey_generate",
        description="SpiderKey Generator – create a unique encryption and decryption program"
    )

    parser.add_argument("--name", required=True, help="Output name for the SpiderKey (e.g., mykey)")
    parser.add_argument("--password", required=True, help="Password to lock the key program")
    parser.add_argument("--seed", required=False, help="Optional seed to allow deterministic regeneration")

    args = parser.parse_args()

    generate.run(name=args.name, password=args.password, seed=args.seed)

if __name__ == "__main__":
    main()
