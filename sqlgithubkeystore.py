import datetime
import hashlib
import json
import random
import sqlite3
from typing import Any, Dict, Iterable, List, Tuple, Type

import Crypto.PublicKey.RSA
import Crypto.PublicKey.pubkey
import dateutil.tz
import dateutil.parser
import jose.jwt
import purl
import requests

from githubkeystore import (
    AppHasNoKey,
    AppHasNoToken,
    AppTokenFactory,
    AppId,
    AppKeyStore,
    AuthTokenStore,
    DuplicateKey,
    InstallationHasNoToken,
    InstallationId,
    InstallationTokenFactory,
    InvalidToken,
    KeySelector,
    KeySelectorIdentifier,
    KeySelectorType,
    NoSuchKey,
    NoSuchToken,
    StoredAppKey,
    StoredToken,
    TokenSelector,
    TokenSelectorType,
)


def fingerprint_key(key: Crypto.PublicKey.pubkey.pubkey) -> str:
    public_der: bytes = key.publickey().exportKey('DER')  # type: ignore
    hexdigest = hashlib.new('sha1', public_der).hexdigest()
    return ':'.join(
        [hexdigest[2 * i:2 * i + 2] for i in range(len(hexdigest) // 2)])


def key_selector_column(selector: KeySelectorType) -> str:
    return {
        KeySelectorType.FINGERPRINT.name: 'fingerprint',
        KeySelectorType.KID.name: 'key_id',
    }[selector.name]


def authn_token_selector_column(selector: TokenSelectorType) -> str:
    return {
        TokenSelectorType.IDENTITY.name: "tokein",
        TokenSelectorType.TID.name: "token_id",
    }[selector.name]


tzutc = dateutil.tz.tzutc()  # pylint: disable=invalid-name
epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzutc)  # pylint: disable=invalid-name

def _validate_row(row: sqlite3.Row, expected_types: Iterable[Type]) -> None:
    for i, (row_value, expected_type) in enumerate(zip(row, expected_types)):
        if not isinstance(row_value, expected_type):
            raise ValueError('row[{}] is {} type {}, not type {}'.format(
                i, row_value, type(row_value), expected_type))


def key_row_to_tuple(row: sqlite3.Row) -> StoredAppKey:
    expected_types = (bytes, str, str, int, int)
    _validate_row(row, expected_types)
    pubkey = Crypto.PublicKey.RSA.importKey(row[0])
    return StoredAppKey(*([pubkey] + list(row[1:-1])) + [bool(row[-1])])


def token_row_to_tuple(row: sqlite3.Row) -> StoredToken:
    expected_types = (str, str, int, int, str, str, str, int)
    _validate_row(row, expected_types)
    issued = dateutil.parser.parse(row[4])
    expires = dateutil.parser.parse(row[5])
    return StoredToken(*(list(row[:4]) + [issued, expires, row[6], bool(row[7])]))


class SQLKeyStore(AppKeyStore, AuthTokenStore):

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def add_app_key(self, app_id: AppId, key: Crypto.PublicKey.pubkey.pubkey,
                    kid: str) -> None:
        fingerprint = 'xx:xx'
        der = key.exportKey('DER')  # type: ignore
        fingerprint = fingerprint_key(key)
        with self.conn:
            try:
                self.conn.execute(
                    "INSERT INTO app_keys (key_id, app, fingerprint, invalid, key) VALUES (?, ?, ?, 0, ?)",
                    (kid, int(app_id), fingerprint, der))
            except sqlite3.IntegrityError:
                raise DuplicateKey(kid)

    def _get_app_key_auto(self, app: AppId) -> StoredAppKey:
        select_stmt = "SELECT key, key_id, fingerprint, app, invalid FROM app_keys WHERE app = ? AND invalid = 0 ORDER BY RANDOM() LIMIT 1"
        cur = self.conn.cursor()
        cur.execute(select_stmt, (int(app),))
        if cur.rowcount == 0:
            raise AppHasNoKey(app)
        elif cur.rowcount > 1:
            raise RuntimeError("selected {} app keys".format(cur.rowcount))
        record = cur.fetchone()
        if not record:
            raise AppHasNoKey(app)
        return key_row_to_tuple(record)

    def get_app_key_auto(self, app: AppId) -> StoredAppKey:
        with self.conn:
            return self._get_app_key_auto(app)

    def get_app_key(self, key_selector: KeySelector) -> StoredAppKey:
        id_column = key_selector_column(key_selector.type)
        with self.conn:
            select_stmt = "SELECT key, key_id, fingerprint, app, invalid FROM app_keys WHERE {} = ?".format(
                id_column)
            cur = self.conn.cursor()
            cur.execute(select_stmt, (key_selector.identifier,))
            record = cur.fetchone()
            if not record:
                raise NoSuchKey(key_selector)
            return key_row_to_tuple(record)

    def list_app_keys(self, app: AppId,
                      selector: KeySelectorType) -> List[KeySelectorIdentifier]:
        id_column = key_selector_column(selector)
        with self.conn:
            select_stmt = "SELECT {} FROM app_keys where app = ?".format(
                id_column)
            cur = self.conn.cursor()
            cur.execute(select_stmt, (app,))
            return [row[0] for row in cur.fetchall()]

    def invalidate_app_key(self, key: KeySelector) -> None:
        id_column = key_selector_column(key.type)
        update_stmt = "UPDATE app_keys SET invalid = 'true' WHERE {} = ?".format(
            id_column)
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(update_stmt, (key.identifier,))
            if cur.rowcount == 0:
                raise NoSuchKey(key)
            elif cur.rowcount > 1:
                raise RuntimeError("updated {} keys with selector {} {}".format(
                    cur.rowcount, key.type.name, key.identifier))

    def remove_app_key(self, key: KeySelector) -> None:
        id_column = key_selector_column(key.type)
        with self.conn:
            delete_stmt = "DELETE FROM app_keys WHERE {} = ?".format(id_column)
            cur = self.conn.cursor()
            cur.execute(delete_stmt, (key.identifier,))
            if cur.rowcount == 0:
                raise NoSuchKey(key)
            elif cur.rowcount > 1:
                raise RuntimeError("deleted {} keys with selector {} {}".format(
                    cur.rowcount, key.type.name, key.identifier))

    def _require_app_authn_token(
            self, app_id: AppId,
            make_new_token: AppTokenFactory) -> StoredToken:
        try:
            return self._get_app_authn_token(app_id)
        except AppHasNoToken:
            pass
        stored_key = self._get_app_key_auto(app_id)
        jwt = make_new_token(app_id, stored_key)
        return self._add_app_authn_token(jwt)

    def require_app_authn_token(self, app_id: AppId,
                                make_new_token: AppTokenFactory) -> StoredToken:
        with self.conn:
            return self._require_app_authn_token(app_id, make_new_token)

    def _add_app_authn_token(self, token: str) -> StoredToken:
        unverified_claims = jose.jwt.get_unverified_claims(token)
        missing_claims = set(['iss', 'jti', 'exp', 'mobetter.iss_kid']) - set(
            unverified_claims.keys())
        if missing_claims:
            raise InvalidToken(missing_claims=missing_claims)
        app = int(unverified_claims['iss'])
        token_id = unverified_claims['jti']
        token_request_key = 'key:' + unverified_claims['mobetter.iss_kid']
        issued = epoch + datetime.timedelta(
            seconds=int(unverified_claims['iss']))
        expires = epoch + datetime.timedelta(
            seconds=int(unverified_claims['exp']))
        insert_stmt = (
            "INSERT INTO authn_tokens (token_id, app, token_request_key, issued, expires, invalid, token) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)")
        self.conn.execute(
            insert_stmt,
            (token_id, app, token_request_key, issued, expires, token))
        return StoredToken(token_id, token, app, None, issued, expires,
                           token_request_key, False)

    def add_app_authn_token(self, token: str) -> StoredToken:
        with self.conn:
            return self._add_app_authn_token(token)

    def _add_installation_authn_token(
            self, token: str, app: AppId, installation: InstallationId,
            issued: datetime.datetime, expires: datetime.datetime,
            iss_jti: str) -> StoredToken:
        issued_seconds = int((issued - epoch).total_seconds())
        random_part = random.getrandbits(16).to_bytes(2, 'big').hex()
        token_id = f'{app}:{iss_jti}:{issued_seconds}-{random_part}'
        token_request_key = f'token:{iss_jti}'
        insert_stmt = (
            "INSERT INTO authn_tokens (token_id, app, installation, token_request_key, issued, expires, invalid, token) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?)")
        self.conn.execute(insert_stmt,
                          (token_id, app, installation, token_request_key,
                           issued, expires, token))
        return StoredToken(token_id, token, app, installation, issued, expires,
                           token_request_key, False)

    def add_installation_authn_token(
            self, token: str, app: AppId, installation: InstallationId,
            issued: datetime.datetime, expires: datetime.datetime,
            iss_jti: str) -> StoredToken:
        with self.conn:
            return self._add_installation_authn_token(token, app, installation,
                                                      issued, expires, iss_jti)

    def get_authn_token(self, selector: TokenSelector) -> StoredToken:
        id_column = authn_token_selector_column(selector.type)
        select_stmt = "SELECT token_id, token, app, installation, issued, expires, token_request_key, invalid FROM authn_tokens WHERE {} = ?".format(
            id_column)
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(select_stmt, (selector.identifier,))
            if cur.rowcount == 0:
                raise NoSuchToken(selector)
            elif cur.rowcount > 1:
                raise RuntimeError('{} matching otkens for {} {}'.format(
                    cur.rowcount, selector.type.name, selector.identifier))
            row = cur.fetchone()
            return token_row_to_tuple(row)

    def _get_installation_authn_token(
            self, app: AppId, installation: InstallationId) -> StoredToken:
        select_stmt = (
            "SELECT token_id, token, app, installation, issued, expires, token_request_key, invalid FROM authn_tokens WHERE app = ? AND installation = ? AND invalid = 0 AND expires > DATETIME('now') "
            "ORDER BY expires DESC LIMIT 1")
        cur = self.conn.cursor()
        cur.execute(select_stmt, (int(app), int(installation)))
        record = cur.fetchone()
        if not record:
            raise InstallationHasNoToken(app, installation)
        if cur.rowcount == 0:
            raise RuntimeError('row count = 0')
        elif cur.rowcount > 1:
            raise RuntimeError('selected more than one record')
        return token_row_to_tuple(record)

    def get_installation_authn_token(
            self, app: AppId, installation: InstallationId) -> StoredToken:
        with self.conn:
            return self._get_installation_authn_token(app, installation)

    def require_installation_authn_token(
            self, app: AppId, installation: InstallationId,
            new_app_token: AppTokenFactory,
            new_installation_token: InstallationTokenFactory) -> StoredToken:
        with self.conn:
            try:
                return self._get_installation_authn_token(app, installation)
            except InstallationHasNoToken:
                pass
            app_auth_token = self._require_app_authn_token(app, new_app_token)
            jwt, expires = new_installation_token(app_auth_token.token,
                                                  installation)
            now = datetime.datetime.now(tzutc)
            # TODO: get authenticationt token jti
            return self._add_installation_authn_token(
                jwt, app, installation, now, expires,
                'token:' + app_auth_token.token_id)

    def _get_app_authn_token(self, app_id: AppId) -> StoredToken:
        select_stmt = (
            "SELECT token_id, token, app, installation, issued, expires, token_request_key, invalid FROM authn_tokens "
            "WHERE app = ? AND installation IS NULL AND invalid = 0 AND expires > DATETIME('now') "
            "ORDER BY expires DESC LIMIT 1")
        cur = self.conn.cursor()
        cur.execute(select_stmt, (app_id,))
        record = cur.fetchone()
        if not record:
            raise AppHasNoToken(app_id)
        if cur.rowcount == 0:
            raise RuntimeError('row count = 0')
        elif cur.rowcount > 1:
            raise RuntimeError('selected more than one record')
        return token_row_to_tuple(record)

    def get_app_authn_token(self, app_id: AppId) -> StoredToken:
        with self.conn:
            return self._get_app_authn_token(app_id)

    def invalidate_authn_token(self, selector: TokenSelector) -> None:
        id_column = authn_token_selector_column(selector.type)
        update_stmt = f"UPDATE authn_tokens SET invalid = 'true' WHERE {id_column} = ?"
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(update_stmt, (selector.identifier,))
            if cur.rowcount == 0:
                raise NoSuchToken(selector)
            elif cur.rowcount > 1:
                raise RuntimeError(
                    "updated {} tokens with selector {} {}".format(
                        cur.rowcount, selector.type.name, selector.identifier))

    def remove_authn_token(self, token: TokenSelector) -> None:
        id_column = authn_token_selector_column(token.type)
        delete_stmt = f"DELETE FROM authn_tokens WHERE {id_column} = ?"
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(delete_stmt, (token.identifier,))
            if cur.rowcount == 0:
                raise NoSuchToken(token)
            elif cur.rowcount > 1:
                raise RuntimeError(
                    "deleted {} tokens with selector {} {}".format(
                        cur.rowcount, token.type.name, token.identifier))

    def list_authn_tokens_for_app(
            self, app_id: AppId, selector_type: TokenSelectorType) -> List[str]:
        id_column = authn_token_selector_column(selector_type)
        select_stmt = (
            f"SELECT {id_column} FROM authn_tokens "
            f"WHERE app = ? AND installation IS NULL AND invalid = 0 AND expires > DATETIME('now')"
        )
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(select_stmt, (app_id,))
            return [row[0] for row in cur.fetchall()]


def fix_jose_dict(jose_dict: Dict[str, Any]) -> Dict[str, Any]:
    fixed: Dict[str, Any] = {}
    for key, value in jose_dict.items():
        if isinstance(value, bytes):
            fixed[key] = value.decode('ascii')
        elif isinstance(value, dict):
            fixed[key] = fix_jose_dict(value)
        else:
            fixed[key] = value
    return fixed


def create_app_token(app: AppId, signing_key: StoredAppKey) -> str:
    jwk = fix_jose_dict(
        jose.backends.pycrypto_backend.RSAKey(signing_key.key,
                                              'RS256').to_dict())
    now = datetime.datetime.now(tzutc)
    now_seconds = int((now - epoch).total_seconds())
    random_part = random.getrandbits(16).to_bytes(2, 'big').hex()
    claims = {
        'iat': now_seconds,
        'exp': now_seconds + 600,
        'iss': app,
        'jti': '{}:{}-{}'.format(signing_key.key_id, now_seconds, random_part),
        'mobetter.iss_kid': signing_key.key_id,
    }
    jwt = jose.jwt.encode(claims, jwk, 'RS256')
    if not isinstance(jwt, str):
        raise RuntimeError('received type {} for jwt'.format(jwt))
    return jwt


_installation_access_token_url = purl.Template(
    'https://api.github.com/installations/{installation}/access_tokens')


def create_installation_token(authn_token: str, installation_id: InstallationId
                             ) -> Tuple[str, datetime.datetime]:
    url = str(
        _installation_access_token_url.expand({
            'installation': installation_id
        }))
    headers = {
        'Authorization': f'Bearer {authn_token}',
        'Accept': 'application/vnd.github.machine-man-preview+json',
    }
    resp = requests.post(url, headers=headers)
    resp_doc = json.loads(resp.text)
    token = resp_doc['token']
    expires = dateutil.parser.parse(resp_doc['expires_at'])
    return token, expires


class SqlKeyManager:

    def __init__(self, store: SQLKeyStore) -> None:
        self.store = store

    def get_app_authn_token(self, app: AppId) -> StoredToken:
        return self.store.require_app_authn_token(app, create_app_token)

    def get_installation_authn_token(
            self, app: AppId, installation: InstallationId) -> StoredToken:
        return self.store.require_installation_authn_token(
            app, installation, create_app_token, create_installation_token)

    def bind_app(self, app: AppId) -> 'SqlAppKeyManager':
        return SqlAppKeyManager(self, app)


class SqlAppKeyManager:

    def __init__(self, key_manager: SqlKeyManager, app: AppId) -> None:
        self.key_manager = key_manager
        self.app = app

    def get_app_authn_token(self) -> StoredToken:
        return self.key_manager.get_app_authn_token(self.app)

    def get_installation_authn_token(
            self, installation: InstallationId) -> StoredToken:
        return self.key_manager.get_installation_authn_token(
            self.app, installation)
