from setuptools import setup

setup(
    name="api",
    packages=["api", "tests"],
    include_package_data=True,
    install_requires=[
        "flask",
    ],
)
