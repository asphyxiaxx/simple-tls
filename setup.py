from setuptools import Extension, setup


setup(
    ext_modules=[
        Extension(
            name="simple_tls._crypto",
            sources=[
                "ext/crypto.c",
                "ext/utils.c",
                "ext/mlkem.c",
                "vendor/mlkem_native/mlkem_native_all.c",
            ],
            # Add the submodule directory here so the compiler checks it!
            include_dirs=["vendor", "vendor/mlkem_native"],
        ),
    ],
    package_data={"simple_tls": ["py.typed"]},
    py_limited_api=True,
)
