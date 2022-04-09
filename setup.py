
import versioneer
import setuptools

if __name__ == "__main__":
    setuptools.setup(
        version=versioneer.get_version(),
        cmdclass=versioneer.get_cmdclass(),
    )
