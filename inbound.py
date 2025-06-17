import httpx
import asyncio
import logging
from typing import Optional, Dict, Any, List

# Marzban information
DOMAIN = "domain.com"  # Replace with your actual domain
PORT = 1234  # Replace with the actual port number
USERNAME = "user"  # Replace with your actual username
PASSWORD = "pass"  # Replace with your actual password

# Inbounds Information
PROTOCOL = "shadowsocks"  # Replace with your protocol
INBOUNDS_TO_REMOVE = []  # Replace with your inbounds list
INBOUNDS_TO_ADD = ["Shadowsocks TCP"]  # Replace with your inbounds list
FLOW = "xtls-rprx-vision"  # Replace with your flow (only works for vless)
METHOD = "chacha20-ietf-poly1305"  # Replace with your method (only works for shadowsocks)

# Configure logging
logging.basicConfig(
    filename="script_log.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


class MarzbanClient:
    def __init__(self, domain: str, port: int, username: str, password: str):
        self.base_url = f"https://{domain}:{port}/api"
        self.username = username
        self.password = password
        self.access_token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            verify=True,
            headers={"accept": "application/json"},
        )
        await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()

    async def authenticate(self) -> bool:
        """Get access token and update client headers"""
        url = f"{self.base_url}/admin/token"

        # Use form data for authentication
        form_data = {"username": self.username, "password": self.password}

        try:
            # Remove Content-Type header for form data - let httpx set it automatically
            auth_headers = {
                k: v
                for k, v in self.client.headers.items()
                if k.lower() != "content-type"
            }

            response = await self.client.post(url, data=form_data, headers=auth_headers)
            response.raise_for_status()

            response_data = response.json()
            self.access_token = response_data["access_token"]

            # Update client headers with authorization
            self.client.headers.update({"Authorization": f"Bearer {self.access_token}"})

            return True
        except httpx.HTTPStatusError as e:
            logging.error(
                f"HTTP error occurred while obtaining access token: {e.response.status_code} - {e.response.text}"
            )
            return False
        except httpx.RequestError as e:
            logging.error(f"Request error occurred while obtaining access token: {e}")
            return False
        except KeyError as e:
            logging.error(f"Access token not found in response: {e}")
            return False

    async def get_users_list(self) -> Optional[Dict[str, Any]]:
        """Get list of all users"""
        url = f"{self.base_url}/users"

        try:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logging.error(f"Error occurred while retrieving users list: {e}")
            return None

    async def get_user_details(self, username: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific user"""
        url = f"{self.base_url}/user/{username}"

        try:
            response = await self.client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logging.error(
                f"Error occurred while retrieving user details for {username}: {e}"
            )
            return None

    async def update_user(self, username: str, user_data: Dict[str, Any]) -> bool:
        """Update user configuration"""
        url = f"{self.base_url}/user/{username}"

        try:
            response = await self.client.put(url, json=user_data)
            response.raise_for_status()
            return True
        except httpx.RequestError as e:
            logging.error(f"Error occurred while updating user {username}: {e}")
            return False

    def create_empty_proxy_inbound(
        self, user_details: Dict[str, Any], protocol: str
    ) -> None:
        """Create an empty proxy and inbound for the specified protocol"""
        # Ensure proxies and inbounds exist
        if "proxies" not in user_details:
            user_details["proxies"] = {}
        if "inbounds" not in user_details:
            user_details["inbounds"] = {}

        # Create an empty inbound for the specified protocol
        user_details["inbounds"][protocol] = []

    async def update_inbounds_for_protocol(
        self,
        user_details: dict,
        protocol: str,
        inbounds_to_remove: List[str],
        inbounds_to_add: List[str],
    ) -> bool:
        """Update inbounds for a specific user and protocol"""

        # Ensure inbounds exist
        if "inbounds" not in user_details:
            user_details["inbounds"] = {}

        # Get current inbounds for the protocol
        inbounds = user_details["inbounds"].get(protocol, [])

        # Remove specified inbounds
        if inbounds_to_remove:
            updated_inbounds = [
                inbound for inbound in inbounds if inbound not in inbounds_to_remove
            ]
            user_details["inbounds"][protocol] = updated_inbounds

        # Create empty proxy and inbound if protocol doesn't exist
        if (
            protocol not in user_details.get("proxies", {})
            or protocol not in user_details["inbounds"]
        ):
            self.create_empty_proxy_inbound(user_details, protocol)
        
        if protocol == "vless":
            user_details["proxies"][protocol] = {"flow": FLOW}

        if protocol == "shadowsocks":
            user_details["proxies"][protocol] = {"method": METHOD}

        # Add new inbounds
        if inbounds_to_add:
            user_details["inbounds"][protocol] += inbounds_to_add

        # Update status if not disabled or on hold
        if user_details.get("status") not in ["disabled", "on_hold"]:
            user_details["status"] = "active"

        # Remove empty protocols
        keys_to_remove = []
        for inbound_protocol in user_details.get("inbounds", {}):
            if not user_details["inbounds"][inbound_protocol]:
                keys_to_remove.append(inbound_protocol)

        # Remove the keys
        for key in keys_to_remove:
            user_details["inbounds"].pop(key, None)
            user_details.get("proxies", {}).pop(key, None)

        # Reset links and subscription URL
        user_details["links"] = []
        user_details["subscription_url"] = ""

        return await self.update_user(user_details["username"], user_details)


async def main():
    """Main function to process all users concurrently"""
    async with MarzbanClient(DOMAIN, PORT, USERNAME, PASSWORD) as client:
        users_list = await client.get_users_list()

        if not users_list:
            print("Failed to retrieve the users list.")
            return

        users = users_list.get("users", [])
        total_users = len(users)

        # Prepare tasks for concurrent execution
        tasks = [
            client.update_inbounds_for_protocol(
                user, PROTOCOL, INBOUNDS_TO_REMOVE, INBOUNDS_TO_ADD
            )
            for user in users
        ]

        # Run all tasks concurrently
        results = await asyncio.gather(*tasks)

        # Print results
        success_count = 0
        for user, result in zip(users, results):
            if result:
                print(
                    f"Inbounds updated successfully for user {user['username']} and protocol {PROTOCOL}."
                )
                success_count += 1
            else:
                print(
                    f"Failed to update inbounds for user {user['username']} and protocol {PROTOCOL}."
                )

        print(
            f"Processing completed. {success_count}/{total_users} users updated successfully."
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"An unexpected error occurred: {e}")
