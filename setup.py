"""install Netfoundry's MOP module"""

from setuptools import setup

with open("README.txt", "r") as fh:
    long_description = fh.read()

setup(
    name='netfoundry',
    py_modules=['netfoundry'],
    author='NetFoundry',
    author_email='ops-mgmt@netfoundry.io',
    url='https://developer.netfoundry.io/',
    description='General purpose library for the NetFoundry network-as-code orchestration Platform',
    long_description=long_description,
    license='MIT',
    version='3.0.0',
    install_requires=[
        'requests >= 2.24.0',
        'pysocks >= 1.7.1',
        'pyjwt >= 1.7.1'
    ]
)
