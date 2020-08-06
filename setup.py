from setuptools import setup, find_packages
setup(
    name="ti-export",
    version="2.0",
    packages=find_packages(),
    install_requires=[
        "requests >= 2.13.0",
        "cybox >= 2.1.0.21",
        "stix >= 1.2.0.8",
        "stix2 >= 2.0.2",
        "tqdm >= 4.43.0",
        "mixbox >= 1.0.3",
    ]
)
