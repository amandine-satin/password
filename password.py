import hashlib
import re

def check_password_strength(password):

    length_error = len(password) < 8
    uppercase_error = not re.search(r'[A-Z]', password)
    lowercase_error = not re.search(r'[a-z]', password)
    digit_error = not re.search(r'\d', password)
    special_char_error = not re.search(r'[!@#$%^&*]', password)

    return not any([length_error, uppercase_error, lowercase_error, digit_error, special_char_error])

def get_valid_password():
    while True:
        password = input("Veuillez entrer un mot de passe : ")
        if check_password_strength(password):
            return password
        else:
            print("Le mot de passe ne respecte pas les exigences de sécurité.")

def hash_password(password):

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def main():
    user_password = get_valid_password()
    hashed_password = hash_password(user_password)
    print(f"Mot de passe sécurisé : {hashed_password}")

if __name__ == "__main__":
    main()
