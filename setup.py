
import versioneer
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='netfoundry',
    py_modules=['netfoundry'],
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    url='https://developer.netfoundry.io/guides/python/',
    description='Interface to the NetFoundry network-as-code orchestration Platform',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    author='Kenneth Bingham',
    author_email='support@netfoundry.io',
    packages=setuptools.find_packages(),
    python_requires='>=3.7',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'requests >= 2.27',
        'pyjwt >= 2.3',
        'inflect >= 5.3',
        'milc >= 1.6.6',
        'pyyaml >= 5.4',
        'platformdirs >= 2.4',
        'tabulate >= 0.8',
        'packaging >= 20.9',
        'pygments >= 2.11'
    ],
    entry_points={
        'console_scripts': [
            'nfdemo = netfoundry.demo:main',
            'nfctl = netfoundry.ctl:cli',
        ]
    }
)
