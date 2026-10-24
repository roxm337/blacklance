"""Setup script for OSINT Agent."""

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
from pathlib import Path


class BuildWithResources(build_py):
    """Keep one authoritative copy of shared data in the source checkout."""

    def run(self):
        super().run()
        root = Path(__file__).resolve().parent
        destination = Path(self.build_lib) / "osint_agent_resources"
        for relative in [Path("config.example.yaml"), *sorted(root.glob("rules/semgrep/*.yaml"))]:
            source = root / relative
            target = destination / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            self.copy_file(str(source), str(target))

setup(
    name="osint-agent",
    version="1.0.0",
    description="LLM-Orchestrated OSINT Reconnaissance Pipeline",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    packages=find_packages(exclude=("tests", "tests.*")),
    cmdclass={"build_py": BuildWithResources},
    package_data={"gui": ["theme.qss"], "knowledge": ["*.yaml"]},
    py_modules=["orchestrator"],
    install_requires=[
        "pyyaml>=6.0",
        "litellm>=1.60",
        "python-dotenv>=1.0",
        "PySide6>=6.7",
        "gravis==0.1.0",
        "setuptools<81",
    ],
    extras_require={
        "full": [
            "aiohttp>=3.8",
            "dnspython>=2.0",
            "python-whois>=0.8",
            "beautifulsoup4>=4.11",
            "lxml>=4.9",
            "playwright>=1.45",
            "h2>=4.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "osint-agent=orchestrator:cli",
            "osint-agent-gui=gui.app:main",
        ],
    },
    python_requires=">=3.10",
)
