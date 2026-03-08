"""Minimal OpenEnv client demo for a running OpenRange server."""

from __future__ import annotations

import argparse

from open_range import OpenRangeEnv, RangeAction


def main() -> None:
    parser = argparse.ArgumentParser(description="Connect to a running OpenRange server")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="OpenEnv server base URL",
    )
    args = parser.parse_args()

    with OpenRangeEnv(base_url=args.base_url).sync() as env:
        result = env.reset()
        print(result.observation.stdout)

        result = env.step(
            RangeAction(command="nmap -sV 10.0.1.0/24", mode="red")
        )
        print(result.observation.stdout)
        print(f"reward={result.reward} done={result.done}")


if __name__ == "__main__":
    main()
