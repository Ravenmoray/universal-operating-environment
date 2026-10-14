"""Compatibility entry point for the original graph experiment.

The repository checkout is required; validation and planning live in uoe.graph.
"""
from pathlib import Path
import sys

# Preserve historical module/script invocations from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from uoe.graph import GraphError, load_graph, main, plan, validate  # noqa: E402,F401

if __name__ == "__main__":
    main()
