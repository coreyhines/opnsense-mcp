"""Simple form handling for environments where python-multipart isn't available."""

from fastapi import Request


class SimpleFormData:
    """Simple class to handle form data."""

    def __init__(self, username: str = "", password: str = "") -> None:
        """
        Initialize form data helper.

        Args:
            username: Username for the form.
            password: Password for the form (empty for demo/testing).

        """
        # NOTE: Default password is empty for demonstration/testing only.
        # Bandit: # nosec
        self.username = username
        self.password = password


async def parse_form_data(request: Request) -> SimpleFormData:
    """Parse form data from a request."""
    content_type = request.headers.get("content-type", "")

    if "application/x-www-form-urlencoded" in content_type:
        # Parse the form data manually
        form_data = SimpleFormData()
        body = await request.body()
        decoded = body.decode("utf-8")

        # Split by & to get key=value pairs
        pairs = decoded.split("&")

        for pair in pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                if key == "username":
                    form_data.username = value
                elif key == "password":
                    form_data.password = value

        return form_data

    # If we can't parse the form data, return an empty form
    return SimpleFormData()
