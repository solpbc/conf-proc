#!/usr/bin/python3.10
"""Emit the exact pre-application CPython startup authority as canonical JSON."""

import sys


def authority_identity(value):
    if value is None:
        return None
    module = getattr(value, "__module__", None)
    qualname = getattr(value, "__qualname__", None)
    if type(module) is str and type(qualname) is str:
        return module + "." + qualname
    value_type = type(value)
    return value_type.__module__ + "." + value_type.__qualname__


def path_hook_projection(hook):
    projection = {"identity": authority_identity(hook), "loader_details": None}
    closure = getattr(hook, "__closure__", None)
    if closure is None:
        return projection
    if len(closure) != 2:
        raise RuntimeError("unexpected path-hook closure")
    finder = closure[0].cell_contents
    loader_details = closure[1].cell_contents
    projection["loader_details"] = {
        "finder": authority_identity(finder),
        "loaders": [
            {"loader": authority_identity(loader), "suffixes": list(suffixes)}
            for loader, suffixes in loader_details
        ],
    }
    return projection


observation = {
    "flags": {
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "ignore_environment": sys.flags.ignore_environment,
        "isolated": sys.flags.isolated,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
    },
    "importer_cache": [
        {"finder": authority_identity(sys.path_importer_cache[path]), "path": path}
        for path in sorted(sys.path_importer_cache)
    ],
    "meta_path": [authority_identity(finder) for finder in sys.meta_path],
    "path": list(sys.path),
    "path_hooks": [path_hook_projection(hook) for hook in sys.path_hooks],
}

import json

print(json.dumps(observation, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
