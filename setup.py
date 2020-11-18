
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='netfoundry',
    version='3.2.0',
    py_modules=['netfoundry'],
    url='https://developer.netfoundry.io/v2/tools/',
    description='Interface to the NetFoundry network-as-code orchestration Platform',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    author='Kenneth Bingham',
    author_email='support@netfoundry.io',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'requests >= 2.24.0',
        'pysocks >= 1.7.1',
        'pyjwt >= 1.7.1'
    ]
)

