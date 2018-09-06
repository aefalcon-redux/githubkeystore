import datetime
import enum
from abc import ABC, abstractmethod
from typing import (
    Callable,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Union,
)

import Crypto.PublicKey.pubkey

__all__ = [
    'AppHasNoKey',
    'AppHasNoToken',
    'AppTokenFactory',
    'AppId',
    'AppKeyStore',
    'AuthTokenStore',
    'DuplicateKey',
    'InstallationHasNoToken',
    'InstallationId',
    'InstallationTokenFactory',
    'InvalidToken',
    'KeySelector',
    'KeySelectorIdentifier',
    'KeySelectorType',
    'NoSuchKey',
    'NoSuchToken',
    'StoredAppKey',
    'StoredToken',
    'TokenSelector',
    'TokenSelectorType',
]

AppId = Union[str, int]  # pylint: disable=invalid-name
InstallationId = Union[str, int]  # pylint: disable=invalid-name

StoredAppKey = NamedTuple(
    'StoredAppKey', [('key', Crypto.PublicKey.pubkey.pubkey), ('key_id', str),
                     ('fingerprint', str), ('app', AppId), ('invalid', bool)])
StoredToken = NamedTuple(
    'StoredToken',
    [('token_id', str), ('token', str), ('app', AppId),
     ('installation', Optional[InstallationId]), ('issued', datetime.datetime),
     ('expires', datetime.datetime), ('token_request_key', str),
     ('invalid', bool)])

AppTokenFactory = Callable[[AppId, StoredAppKey], str]  # pylint: disable=invalid-name
InstallationTokenFactory = Callable[[str, InstallationId],
                                    Tuple[str, datetime.datetime]]  # pylint: disable=invalid-name


class KeySelectorType(enum.Enum):
    FINGERPRINT = enum.auto()
    KID = enum.auto()


KeySelectorIdentifier = str
KeySelector = NamedTuple('KeySelector', [('type', KeySelectorType),
                                         ('identifier', KeySelectorIdentifier)])


class AppHasNoKey(Exception):

    def __init__(self, app: AppId) -> None:
        super().__init__(app)
        self.app = app

    def __str__(self) -> str:
        return 'App {} has no key'.format(self.app)


class AppHasNoToken(Exception):

    def __init__(self, app: AppId) -> None:
        super().__init__(app)
        self.app = app

    def __str__(self) -> str:
        return 'App {} has no token'.format(self.app)


class InstallationHasNoToken(Exception):

    def __init__(self, app: AppId, installation: InstallationId) -> None:
        super().__init__(app, installation)
        self.app = app
        self.installation = installation

    def __str__(self) -> str:
        return 'Installation {} of app {} has no token'.format(
            self.installation, self.app)


class NoSuchKey(Exception):

    def __init__(self, selector: KeySelector) -> None:
        super().__init__(selector)
        self.selector = selector

    def __str__(self) -> str:
        return 'No key with {} {}'.format(self.selector.type.name,
                                          self.selector.identifier)


class DuplicateKey(Exception):

    def __init__(self, kid: str) -> None:
        super().__init__(kid)
        self.kid = kid

    def __str__(self) -> str:
        return 'Key with id {} already exists'.format(self.kid)


class InvalidToken(Exception):

    def __init__(self, missing_claims: Optional[Set[str]] = None) -> None:
        super().__init__(missing_claims)
        self.missing_claims = missing_claims

    def __str__(self) -> str:
        return 'Token not valid'


class AppKeyStore(ABC):

    @abstractmethod
    def get_app_key(self, key_selector: KeySelector) -> StoredAppKey:
        pass

    @abstractmethod
    def get_app_key_auto(self, app: AppId) -> StoredAppKey:
        pass

    @abstractmethod
    def invalidate_app_key(self, key: KeySelector) -> None:
        pass

    @abstractmethod
    def add_app_key(self, app_id: AppId, key: Crypto.PublicKey.pubkey.pubkey,
                    kid: str) -> None:
        pass

    @abstractmethod
    def remove_app_key(self, key: KeySelector) -> None:
        pass

    @abstractmethod
    def list_app_keys(self, app: AppId,
                      selector: KeySelectorType) -> List[KeySelectorIdentifier]:
        pass


class TokenSelectorType(enum.Enum):
    IDENTITY = enum.auto()
    TID = enum.auto()


TokenSelectorIdentifier = str
TokenSelector = NamedTuple('TokenSelector',
                           [('type', TokenSelectorType),
                            ('identifier', TokenSelectorIdentifier)])


class NoSuchToken(Exception):

    def __init__(self, selector: TokenSelector) -> None:
        super().__init__(selector)
        self.selector = selector

    def __str__(self) -> str:
        return 'No token with {} {}'.format(self.selector.type.name,
                                            self.selector.identifier)


class AuthTokenStore(ABC):

    @abstractmethod
    def get_app_authn_token(self, app_id: AppId) -> StoredToken:
        pass

    @abstractmethod
    def get_installation_authn_token(
            self, app: AppId, installation: InstallationId) -> StoredToken:
        pass

    @abstractmethod
    def require_app_authn_token(self, app_id: AppId,
                                make_new_token: AppTokenFactory) -> StoredToken:
        pass

    @abstractmethod
    def require_installation_authn_token(
            self, app: AppId, installation: InstallationId,
            new_app_token: AppTokenFactory,
            new_installation_token: InstallationTokenFactory) -> StoredToken:
        pass

    @abstractmethod
    def get_authn_token(self, selector: TokenSelector) -> StoredToken:
        pass

    @abstractmethod
    def invalidate_authn_token(self, selector: TokenSelector) -> None:
        pass

    @abstractmethod
    def add_app_authn_token(self, token: str) -> StoredToken:
        pass

    @abstractmethod
    def add_installation_authn_token(
            self, token: str, app: AppId, installation: InstallationId,
            issued: datetime.datetime, expires: datetime.datetime,
            iss_jti: str) -> StoredToken:
        pass

    @abstractmethod
    def remove_authn_token(self, token: TokenSelector) -> None:
        pass

    @abstractmethod
    def list_authn_tokens_for_app(
            self, app_id: AppId, selector_type: TokenSelectorType) -> List[str]:
        pass
