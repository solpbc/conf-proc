"""Shared command-line locations for pinned input acquisition."""
import argparse
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'acquisition'


def arguments() -> tuple[Path, Path]:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace.resolve()
    root.mkdir(parents=True, exist_ok=True)
    evidence = root / 'acquisition-evidence'
    evidence.mkdir(exist_ok=True)
    return root, evidence
