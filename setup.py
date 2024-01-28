#!/usr/bin/env python3
# encoding: utf-8

"""
Flask-RSA
---------

This Flask extension provides server-side implementation of RSA-based request signature validation.
It enhances the security of web applications by ensuring the integrity and authenticity of incoming requests.
The extension allows developers to easily integrate RSA signature validation into their Flask applications.
"""

# Third Party Libs
from setuptools import setup


long_description = open('./README.md').read()
changelog = open('./CHANGELOG.md').read()
long_description += '\n' + changelog

# Get Version
version = open('./VERSION.txt').read().strip()


setup(
    name='flask-rsa',
    url='https://github.com/mwalkowski/flask-rsa',
    version=version,
    author='mwalkowski',
    author_email='michal.walkowski@pwr.edu.pl',
    description='This Flask extension provides server-side implementation of RSA-based request signature validation.',
    long_description=long_description,
    packages=[
        'flask_rsa',
    ],
    install_requires=[
        'flask',
        'requests',
        'pycryptodome==3.19.1',
    ],
    classifiers=[
        'Framework :: Flask',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Development Status :: 5 - Production/Stable',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'License :: Public Domain'
    ],
    license='Public Domain',
    keywords=['Flask', 'RSA', 'REST', 'Views']
)