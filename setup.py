"""install Netfoundry's MOP module"""

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='netfoundry',
    py_modules=['netfoundry'],
    author='NetFoundry',
    author_email='ops-mgmt@netfoundry.io',
    url='https://netfoundry.atlassian.net/wiki/spaces/PUB/blog/2017/10/15/11829509/MOP+for+Python',
    description='API wrappers and configuration for NetFoundry\'s Management Orchestration Platform',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    version='1.0.11',
    install_requires=[
        'requests >= 2.18.4',
        'pysocks >= 1.6.7',
        'pyjwt >= 1.6.0'
    ]
)
