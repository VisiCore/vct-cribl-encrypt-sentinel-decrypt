"""Azure Functions v2 entry point.

The Azure Functions Python v2 host indexes the `FunctionApp` instance named `app`
in `function_app.py`. The actual decrypt route lives in `decrypt_function.py`;
re-export its `app` here so the host discovers the registered route.
"""

from decrypt_function import app  # noqa: F401  (re-exported for the host to index)
