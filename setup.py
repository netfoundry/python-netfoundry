"""install Netfoundry's MOP module"""

from setuptools import setup

setup(
    name='nfmop',
    py_modules=['nfmop'],
    author='NetFoundry',
    author_email='ops-mgmt@netfoundry.io',
    url='https://netfoundry.atlassian.net/wiki/spaces/PUB/blog/2017/10/15/11829509/MOP+for+Python',
    download_url='https://netfoundry.jfrog.io/netfoundry/list/python/nfmop/1.0.8/nfmop-1.0.8.tar.gz',
    description='API wrappers and configuration for NetFoundry\'s Management Orchestration Platform',
    license='MIT',

    version='1.0.8',
    install_requires=[
        'requests >= 2.18.4',
        'pysocks >= 1.6.7',
        'pyjwt >= 1.6.0'
    ]
)
