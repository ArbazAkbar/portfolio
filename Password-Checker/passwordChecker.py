import re
import random
import string

def password_strength_checker(password):
    """
    Checks the strength of a given password.

    Args:
        password (str): The password to check.

    Returns:
        dict: A dictionary containing the password strength results.
    """
    results = {
        'length': False,
        'uppercase': False,
        'lowercase': False,
        'digits': False,
        'special_chars': False
    }

    # Check length
    if len(password) >= 8:
        results['length'] = True

    # Check uppercase
    if re.search(r"[A-Z]", password):
        results['uppercase'] = True

    # Check lowercase
    if re.search(r"[a-z]", password):
        results['lowercase'] = True

    # Check digits
    if re.search(r"\d", password):
        results['digits'] = True

    # Check special characters
    if re.search(r"[!@#$%^&*()_+=-{};:'<>,./?]", password):
        results['special_chars'] = True

    return results

def print_results(results):
    """
    Prints the password strength results.

    Args:
        results (dict): The password strength results.
    """
    print("Password Strength Results:")
    print("---------------------------")
    print(f"Length: {'OK' if results['length'] else 'Weak'}")
    print(f"Uppercase: {'OK' if results['uppercase'] else 'Weak'}")
    print(f"Lowercase: {'OK' if results['lowercase'] else 'Weak'}")
    print(f"Digits: {'OK' if results['digits'] else 'Weak'}")
    print(f"Special Characters: {'OK' if results['special_chars'] else 'Weak'}")

def is_password_secure(results):
    """
    Checks if the password is secure based on the results.

    Args:
        results (dict): The password strength results.

    Returns:
        bool: True if the password is secure, False otherwise.
    """
    return all(results.values())

def generate_password_suggestions(password):
    """
    Generates password suggestions based on the user's input.

    Args:
        password (str): The user's input password.

    Returns:
        list: A list of password suggestions.
    """
    suggestions = []

    # Add uppercase letter if missing
    if not re.search(r"[A-Z]", password):
        suggestions.append(password + random.choice(string.ascii_uppercase))

    # Add lowercase letter if missing
    if not re.search(r"[a-z]", password):
        suggestions.append(password + random.choice(string.ascii_lowercase))

    # Add digit if missing
    if not re.search(r"\d", password):
        suggestions.append(password + str(random.randint(0, 9)))

    # Add special character if missing
    if not re.search(r"[!@#$%^&*()_+=-{};:'<>,./?]", password):
        suggestions.append(password + random.choice(string.punctuation))

    # Add length if too short
    if len(password) < 8:
        suggestions.append(password + ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(8 - len(password))))

    return suggestions

def print_security_status(results, password):
    """
    Prints the password security status and suggestions if not secure.

    Args:
        results (dict): The password strength results.
        password (str): The user's input password.
    """
    if is_password_secure(results):
        print("Password is SECURE!")
    else:
        print("Password is NOT SECURE. Please try again!")
        print("Here are some password suggestions:")
        for suggestion in generate_password_suggestions(password):
            print(f"- {suggestion}")

def main():
    password = input("Enter a password: ")
    results = password_strength_checker(password)
    print_results(results)
    print_security_status(results, password)

if __name__ == "__main__":
    main()