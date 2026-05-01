def pytest_addoption(parser):
    parser.addoption(
        "--no-wycheproof",
        action="store_true",
        default=False,
        help="Skip downloading and running Wycheproof test vectors",
    )
