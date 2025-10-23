import logging
import httpx
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

LEMONSQUEEZY_API_BASE = "https://api.lemonsqueezy.com/v1"


class LemonSqueezyClient:
    """Client for LemonSqueezy License API."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

    async def validate_license(self, license_key: str) -> Tuple[bool, Optional[dict]]:
        """
        Validate a license key against LemonSqueezy.

        Returns:
            Tuple of (is_valid, license_data)
            - is_valid: True if license exists and is active
            - license_data: License info dict if valid, None otherwise
        """
        url = f"{LEMONSQUEEZY_API_BASE}/licenses/validate"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json={"license_key": license_key}
                )

                if response.status_code == 200:
                    data = response.json()

                    # Check if license is valid
                    if data.get("valid", False):
                        license_data = data.get("license_key", {})
                        status = license_data.get("status")

                        if status == "active":
                            logger.info(f"LemonSqueezy license validated successfully")
                            return True, license_data
                        elif status == "inactive":
                            logger.info(f"LemonSqueezy license is inactive, attempting activation")
                            return False, license_data
                        else:
                            logger.warning(f"LemonSqueezy license has status: {status}")
                            return False, None
                    else:
                        logger.warning("LemonSqueezy license validation returned valid=false")
                        return False, None

                elif response.status_code == 404:
                    logger.warning("LemonSqueezy license not found")
                    return False, None
                else:
                    logger.error(f"LemonSqueezy API error: {response.status_code} - {response.text}")
                    return False, None

        except httpx.TimeoutException:
            logger.error("LemonSqueezy API request timed out")
            return False, None
        except Exception as e:
            logger.error(f"Error validating LemonSqueezy license: {e}")
            return False, None

    async def activate_license(self, license_key: str, instance_name: str = "ollama-proxy") -> Tuple[bool, Optional[dict]]:
        """
        Activate an inactive license.

        Args:
            license_key: The license key to activate
            instance_name: A name for this instance (optional)

        Returns:
            Tuple of (success, license_data)
        """
        url = f"{LEMONSQUEEZY_API_BASE}/licenses/activate"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    headers=self.headers,
                    json={
                        "license_key": license_key,
                        "instance_name": instance_name
                    }
                )

                if response.status_code == 200:
                    data = response.json()

                    if data.get("activated", False):
                        license_data = data.get("license_key", {})
                        logger.info(f"LemonSqueezy license activated successfully")
                        return True, license_data
                    else:
                        error_msg = data.get("error", "Unknown error")
                        logger.warning(f"LemonSqueezy license activation failed: {error_msg}")
                        return False, None
                else:
                    logger.error(f"LemonSqueezy activation API error: {response.status_code} - {response.text}")
                    return False, None

        except httpx.TimeoutException:
            logger.error("LemonSqueezy API request timed out during activation")
            return False, None
        except Exception as e:
            logger.error(f"Error activating LemonSqueezy license: {e}")
            return False, None

    async def validate_and_activate_if_needed(self, license_key: str) -> Tuple[bool, Optional[dict]]:
        """
        Validate a license, and if it's inactive, attempt to activate it.

        Returns:
            Tuple of (is_valid, license_data)
        """
        is_valid, license_data = await self.validate_license(license_key)

        if is_valid:
            return True, license_data

        # If license exists but is inactive, try to activate
        if license_data and license_data.get("status") == "inactive":
            return await self.activate_license(license_key)

        return False, None
