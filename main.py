import hashlib
import getpass
import uuid
from typing import Optional


class User:
    """
    Represents a user with username, password, phone number, and unique identifier.
    """

    def __init__(self, username: str, password: str, number_phone: Optional[str] = None) -> None:
        """
        Initialize a User object.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.
            number_phone (str, optional): The phone number of the user. Defaults to None.
        """
        self.username = username
        self.password = self._hash_password(password)
        self.number_phone = number_phone
        self.id = str(uuid.uuid4())

    def _hash_password(self, password: str) -> str:
        """
        Hashes the password using hashlib.

        Args:
            password (str): The password to be hashed.

        Returns:
            str: The hashed password.
        """
        salt = "somerandomsalt"
        hashed_password = hashlib.sha256(
            (password + salt).encode()).hexdigest()
        return hashed_password

    def verify_password(self, password: str) -> bool:
        """
        Verifies if the provided password matches the stored hashed password.

        Args:
            password (str): The password to be verified.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        hashed_password = hashlib.sha256(
            (password + "somerandomsalt").encode()).hexdigest()
        return self.password == hashed_password

    def __str__(self) -> str:
        """
        Returns a string representation of the User object.

        Returns:
            str: The string representation of the User object.
        """
        return f"Username: {self.username}\nPhone: {self.number_phone}"


class UserManagement:
    """
    Manages user registration, login, and account management.
    """

    def __init__(self) -> None:
        """
        Initialize a UserManagement object.
        """
        self.users = {}

    def register_user(self) -> None:
        """
        Register a new user.
        """
        username = input("Enter username: ")
        while username in self.users:
            print("Username already exists. Please choose another username.")
            username = input("Enter username: ")

        password = getpass.getpass("Enter password (minimum 4 characters): ")
        while len(password) < 4:
            print("Password must be at least 4 characters long.")
            password = getpass.getpass(
                "Enter password (minimum 4 characters): ")

        number_phone = input("Enter phone number (optional): ")
        if not number_phone:
            number_phone = None

        user = User(username, password, number_phone)
        self.users[username] = user
        print("User registered successfully.")

    def login_user(self) -> None:
        """
        Login a user and provide account management options.
        """
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")

        if username in self.users and self.users[username].verify_password(password):
            print("Login successful.")
            while True:
                print("1. View user information")
                print("2. Edit personal information")
                print("3. Change password")
                print("4. Logout")
                choice = input("Enter your choice: ")
                if choice == "1":
                    print(self.users[username])
                elif choice == "2":
                    new_username = input("Enter new username: ")
                    self.users[username].username = new_username
                    new_phone = input("Enter new phone number: ")
                    self.users[username].number_phone = new_phone
                    print("Personal information updated successfully.")
                elif choice == "3":
                    old_password = getpass.getpass("Enter current password: ")
                    new_password = getpass.getpass(
                        "Enter new password (minimum 4 characters): ")
                    confirm_password = getpass.getpass(
                        "Confirm new password: ")

                    if self.users[username].verify_password(old_password) and new_password == confirm_password:
                        self.users[username].password = self.users[username]._hash_password(
                            new_password)
                        print("Password changed successfully.")
                    else:
                        print("Password change unsuccessful. Please try again.")
                elif choice == "4":
                    print("Logged out.")
                    break
                else:
                    print("Invalid choice. Please try again.")
        else:
            print("Invalid username or password.")


def main() -> None:
    """
    Main function to run the program.
    """
    user_manager = UserManagement()
    while True:
        print("Menu:")
        print("0. Exit")
        print("1. Register new user")
        print("2. Login")
        choice = input("Enter your choice: ")
        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "1":
            user_manager.register_user()
        elif choice == "2":
            user_manager.login_user()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
