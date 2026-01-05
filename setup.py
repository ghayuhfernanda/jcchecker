from setuptools import setup, find_packages

setup(
    name="jcchecker",
    version="1.0.0",
    description="JavaCard static analyzer",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="JavaCardChecker Contributors",
    url="https://github.com/yourusername/JavaCardChecker",
    packages=find_packages(),
    install_requires=[
        "javalang>=0.13.0",
    ],
    entry_points={
        "console_scripts": [
            "jcchecker=jcchecker.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
