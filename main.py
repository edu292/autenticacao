from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from getpass import getpass
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError


class AppState(Enum):
    MENU = auto()
    LOGIN = auto()
    CREATE_ACCOUNT = auto()
    LOCKED = auto()
    AUTHENTICATED = auto()
    EXIT = auto()


@dataclass
class Account:
    email: str
    password: str
    name: str


INITIAL_LOCK_TIME = 5 * 60
CONSECUTIVE_LOCK_MULTIPLIER = 6
ATTEMPTS_BEFORE_LOCK = 3
MIN_PASSWORD_LENGTH = 8
PASSWORD_HASHER = PasswordHasher()

SYMBOLS = set(string.punctuation)
CHARACTER_RULES = {
    "Sua senha deve conter pelo menos uma letra maiúscula": str.isupper,
    "Sua senha deve conter pelo menos uma letra minúscula": str.islower,
    "Sua senha deve conter pelo menos um número": str.isdigit,
    "Sua senha deve conter pelo menos um símbolo": lambda char: char in SYMBOLS,
}


accounts: dict[str, Account] = {}
login_attempts = 0
consecutive_locks = 0
locked_since = None
current_state = AppState.MENU
logged_account = None


def validate_password(password: str) -> tuple[bool, list[str]]:
    errors: list[str] = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(
            f"Sua senha deve conter pelo menos {MIN_PASSWORD_LENGTH} caracteres"
        )

    unmet_rules = CHARACTER_RULES.copy()

    for character in password:
        if not unmet_rules:
            break

        for error_msg in list(unmet_rules.keys()):
            test_function = unmet_rules[error_msg]

            if test_function(character):
                del unmet_rules[error_msg]

    errors.extend(unmet_rules.keys())

    is_valid = len(errors) == 0
    return is_valid, errors


while current_state is not AppState.EXIT:
    match current_state:
        case AppState.LOCKED:
            print()
            locked_until = locked_since + timedelta(
                seconds=(
                    INITIAL_LOCK_TIME
                    + (consecutive_locks * CONSECUTIVE_LOCK_MULTIPLIER)
                )
            )
            now = datetime.now()

            if locked_until > now:
                remaining_time = locked_until - now
                minutes, seconds = divmod(int(remaining_time.total_seconds()), 60)
                print(f"Você está bloqueado. Tente novamente em {minutes}m {seconds}s.")
                _ = input("Pressione ENTER para atualizar o contador...")
            else:
                consecutive_locks += 1
                login_attempts = 0
                current_state = AppState.MENU

        case AppState.MENU:
            print("\n--- Menu Principal ---")
            print("0 - Login")
            print("1 - Criar conta")
            print("2 - Sair")
            print()
            opcao = input("Escolha uma opção: ")

            match opcao:
                case "0":
                    current_state = AppState.LOGIN
                case "1":
                    current_state = AppState.CREATE_ACCOUNT
                case "2":
                    current_state = AppState.EXIT
                case _:
                    print("Opção inválida. Tente novamente.")

        case AppState.LOGIN:
            print("\n--- Login ---")
            if login_attempts >= ATTEMPTS_BEFORE_LOCK:
                current_state = AppState.LOCKED
                locked_since = datetime.now()
                continue

            email = input("Digite seu email: ")
            password = getpass("Digite sua senha: ")

            account = accounts.get(email)
            login_success = False

            if account:
                with suppress(VerificationError):
                    login_success = PASSWORD_HASHER.verify(account.password, password)

            if not login_success:
                login_attempts += 1
                print("\nEmail ou senha incorretos. Tente novamente.")
                print(f"Tentativas incorretas: {login_attempts}/{ATTEMPTS_BEFORE_LOCK}")
            else:
                consecutive_locks = 0
                login_attempts = 0
                locked_since = None
                logged_account = account
                current_state = AppState.AUTHENTICATED
                print("\nLogin efetuado com sucesso!")

        case AppState.CREATE_ACCOUNT:
            print("\n--- Criar Conta ---")
            email = input("Digite seu email (Deixe em branco para voltar ao menu): ")
            if not email:
                current_state = AppState.MENU
                continue

            if email in accounts:
                print("\nJá existe uma conta cadastrada com este email. Tente outro.")
                continue

            password = getpass("Digite sua senha: ")
            valid, errors = validate_password(password)

            if not valid:
                print("\nSenha inválida:")
                print(*errors, sep="\n")
                continue

            nome = input("Digite seu nome: ")

            accounts[email] = Account(
                email=email, password=PASSWORD_HASHER.hash(password), name=nome
            )
            print("\nConta criada com sucesso!")
            current_state = AppState.MENU

        case AppState.AUTHENTICATED:
            print(f"\nBem-vindo(a), {logged_account.name}!")
            print("0 - Logout")
            print()
            opcao = input("Escolha uma opção: ")

            if opcao == "0":
                print("\nSaindo da sua conta...")
                logged_account = None
                current_state = AppState.MENU
            else:
                print("Opção inválida.")
