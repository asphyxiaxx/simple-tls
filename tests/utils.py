import functools
import json
import os
from pathlib import Path

import pytest


def format_path(*paths: str):
    return os.path.join(os.path.dirname(__file__), *paths)


def stdout(indicator: str = "."):
    return print(indicator, end="", flush=True)


def load(*paths: str, mode: str = "r"):
    path = format_path(*paths)
    with open(path, mode) as fp:
        return fp.read()


class WycheproofTest:
    def __init__(self, vector, test_group, test_case):
        self.vectors = vector
        self.test_group = test_group
        self.test_case = test_case

    @property
    def type(self):
        return self.test_group["type"]

    @property
    def tc_id(self):
        return self.test_case["tcId"]

    @property
    def valid(self):
        return self.test_case["result"] == "valid"

    @property
    def acceptable(self):
        return self.test_case["result"] == "acceptable"

    @property
    def invalid(self):
        return self.test_case["result"] == "invalid"


@functools.lru_cache(maxsize=32)
def load_wycheproof_json(file_path: Path) -> dict:
    """Load Wycheproof vectors from a local file path."""
    try:
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        pytest.fail(f"Failed to read Wycheproof file at {file_path}: {e}")


def yield_wycheproof_tests(base_dir: Path, *paths: str):
    file_path = base_dir.joinpath(*paths)
    if not file_path.suffix:
        file_path = file_path.with_suffix(".json")

    vectors = load_wycheproof_json(file_path)

    for test_group in vectors["testGroups"]:
        for test_case in test_group["tests"]:
            yield WycheproofTest(vectors, test_group, test_case)


def wycheproof_tests(*paths: str, subdir: str = "testvectors_v1"):
    """
    Pytest decorator that loads local Wycheproof vectors from a directory
    provided via the --wycheproof-dir CLI option.
    """

    def decorator(func):
        @pytest.mark.parametrize("path", paths)
        def wrapper(path, subtests, pytestconfig):
            wycheproof_dir = pytestconfig.getoption(
                "--wycheproof-dir", skip=True
            )
            base_dir = Path(wycheproof_dir)

            for test_case in yield_wycheproof_tests(base_dir, subdir, path):
                with subtests.test(file=path, tc_id=test_case.tc_id):
                    func(test_case)

        wrapper.__name__ = func.__name__
        return wrapper

    return decorator
