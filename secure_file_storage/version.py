"""Contains the version of the package"""

import toml


def get_version():
    """
    Retrieve the current project version from 'pyproject.toml'.

    Returns:
        str: Version string from the 'project.version' field.
    """
    pyproject = toml.load("pyproject.toml")
    return pyproject['project']['version']


__version__ = get_version()
