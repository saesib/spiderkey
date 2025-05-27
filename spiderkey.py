import argparse
from commands import generate

def main():
    parser = argparse.ArgumentParser(
        prog="spiderkey",
        description="SpiderKey Generator – create a unique encryption and decryption program"
    )
    subparsers = parser.add_subparsers(dest="command")

    # spiderkey generate --name ... --password ... [--seed ...]
    gen_parser = subparsers.add_parser("generate", help="Generate a new SpiderKey program")
    gen_parser.add_argument("--name", required=True, help="Output name for the SpiderKey (e.g., mykey)")
    gen_parser.add_argument("--password", required=True, help="Password to lock the key program")
    gen_parser.add_argument("--seed", required=False, help="Optional seed to allow deterministic regeneration")

    args = parser.parse_args()

    if args.command == "generate":
        print(f"Generating SpiderKey with name: {args.name}, password: {args.password}, seed: {args.seed}")
        generate.run(name=args.name, password=args.password, seed=args.seed)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
