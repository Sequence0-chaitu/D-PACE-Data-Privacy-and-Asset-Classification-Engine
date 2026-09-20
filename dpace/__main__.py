"""
dpace.__main__
--------------
Package entry point so the documented form works:

    python -m dpace scan --path ./mock_data/

Delegates to dpace.cli:main().
"""

from dpace.cli import main

if __name__ == "__main__":
    main()
