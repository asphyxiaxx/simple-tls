def pytest_addoption(parser):
    parser.addoption(
        "--wycheproof-dir",
        action="store",
        default=None,
        help="Path to local directory containing Wycheproof JSON test vectors",
    )
