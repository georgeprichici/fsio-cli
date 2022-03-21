from setuptools import setup, find_packages
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="filescan_cli",
    version="1.0.0",
    description="CLI client for Filescan service",
    author="FileScan GmbH",
    author_email="support@filescan.com",
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/filescanio/fsio-cli",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "aiofiles==0.8.0",
        "aiohttp==3.8.1",
        "aiosignal==1.2.0",
        "ansiwrap==0.8.4",
        "anyio==3.5.0",
        "async-timeout==4.0.2",
        "asyncclick==8.0.3.2",
        "asyncio==3.4.3",
        "attrs==21.4.0",
        "autopep8==1.6.0",
        "blessings==1.7",
        "certifi==2021.10.8",
        "charset-normalizer==2.0.12",
        "colorama==0.4.4",
        "curtsies==0.3.10",
        "cwcwidth==0.1.6",
        "frozenlist==1.3.0",
        "idna==3.3",
        "log-symbols==0.0.14",
        "multidict==6.0.2",
        "pycodestyle==2.8.0",
        "requests==2.27.1",
        "six==1.16.0",
        "sniffio==1.2.0",
        "spinners==0.0.24",
        "termcolor==1.1.0",
        "textwrap3==0.9.2",
        "toml==0.10.2",
        "urllib3==1.26.8",
        "yarl==1.7.2",
        "halo @ git+https://github.com/frostming/halo.git@multiple-spinners"
    ],
    packages=find_packages(),
    package_dir={"": "."},
    python_requires=">=3.8",
    scripts=["filescan.py"]
)
