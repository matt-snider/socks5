#!/usr/bin/env python
import os

from codecs import open

from setuptools import setup, find_packages


# Get the long description from the README file
with open('README.md', 'r', 'utf-8') as f:
    long_description = f.read()


setup(
    name='socks5server',
    version='0.1.0',
    description='A simple asyncio-based socks5 server',
    long_description=long_description,
    url='https://github.com/matt-snider/socks5',
    author='matt-snider',
    author_email='matt.snider@protonmail.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='socks socks5 proxy asyncio',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    python_requires=">=3.6",
    install_requires=[
        'click',
        'kaviar',
    ],
    entry_points={
        'console_scripts': [
            'socks5.server=socks5.cli:run_server',
        ],
    },
    project_urls={
        'Source': 'https://github.com/matt-snider/socks5',
    },
)
