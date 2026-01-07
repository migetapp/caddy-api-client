from setuptools import setup, find_packages
import os

# read the contents of README file
with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="caddy-api-client",
    version="0.2.5",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
    ],
    author="Krzysztof Taraszka",
    author_email="chris@miget.com",
    description="A Python client for the Caddy API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/migetapp/caddy-api-client",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.7",
)
