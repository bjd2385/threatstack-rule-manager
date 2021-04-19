"""
Manage API calls to TS.

All response objects are returned in a POSTable format, so we can store them on disk that way (and don't have to edit
them later).
"""

from typing import Optional, Dict, Callable, Any

import logging
import requests
import json

from urllib.error import URLError
from mohawk import Sender
from functools import wraps
from time import sleep
from http import HTTPStatus


class RateLimitedError(Exception):
    """
    Raised when an HTTPStatus.TOO_MANY_REQUESTS code is received.
    """
    def __init__(self, message: str ='', delay: float =30.0) -> None:
        super().__init__(message)
        self.message = message
        self.delay = delay

    def __str__(self):
        return f'RateLimitError(message="{self.message}", code="{HTTPStatus.TOO_MANY_REQUESTS}", "x-rate-limit-reset={self.delay}")'


def retry(tries: int) -> Callable:
    """
    A request retry decorator.

    Args:
        tries: number of times to retry the wrapped function call. When `0`, retries indefinitely.

    Returns:
        Either the result of a successful function call (be it via retrying or not).
    """
    if tries < 0:
        raise ValueError(f'Expected positive `tries` values, received: {tries}')

    def _f(f: Callable) -> Callable:
        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Optional[Dict]:
            res: Any = None

            def call() -> bool:
                nonlocal res
                try:
                    res = f(*args, **kwargs)
                    return True
                except RateLimitedError as msg:
                    sleep(msg.delay)
                    return False
                except URLError as msg:
                    return False

            if tries > 0:
                for _ in range(tries):
                    if call():
                        return res
                else:
                    return
            else:
                while not call():
                    pass
                else:
                    return res

        return new_f

    return _f


class API:
    """
    API object that provides a higher level interface to the remote organizations' state.
    """
    def __init__(self, user_id: str, api_key: str, org_id: str) -> None:
        self._user = user_id
        self._key = api_key
        self._ext = org_id

        self._credentials = {
            'id': user_id,
            'key': api_key,
            'algorithm': 'sha256'
        }

        self._sender: Optional[Sender] = None
        self._header: Optional[str] = None

    def _update_sender(self, url: str, data: Optional[Dict] =None) -> None:
        """
        Update the retrieved token.

        Args:
            url: url on which we are about to make a request.

        Returns:
            Nothing.
        """
        self._sender = Sender(
            credentials=self._credentials,
            url=url,
            content=json.dumps(data) if data else data,
            method='GET',
            always_hash_content=False,
            content_type='application/json',
            ext=self._ext
        )
        self._header = self._sender.request_header

    @retry(tries=3)
    def _get(self, url: str) -> Optional[Dict]:
        """
        GET request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url)

        response = requests.get(
            url=url,
            headers={
                'Authorization': self._header,
                'Content-Type': 'application/json'
            }
        )

        try:
            return response.json()
        except json.JSONDecodeError:
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                # Delay the minimal amount of time we can before running another request. `time.sleep` also isn't
                # that accurate, so I add 1/4s for good measure, which is barely noticeable.
                raise RateLimitedError(delay=float(response.headers['x-rate-limit-reset']) / 1_000 + 0.25)
            else:
                raise URLError(
                    f'Did not get valid JSON in response: {response.text if response.text else response.reason} ~ {response.status_code}'
                )

    def get_rulesets(self) -> Dict:
        """
        Return a list of rulesets and rules thereunder. This isn't meant to return an object in a POSTable format,
        unlike other methods.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/list-ruleset

        Returns:
            A dictionary of rulesets and their rules.
        """
        data = self._get('https://api.threatstack.com/v2/rulesets')

        return data

    def get_ruleset(self, ruleset_id: str) -> Dict:
        """
        Return a particular ruleset and rule IDs thereunder.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-a-ruleset

        Args:
            ruleset_id: ruleset ID we'd like to retrieve.

        Returns:
            The ruleset and rule IDs thereunder.
        """
        data = self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}')
        for field in ('updatedAt', 'createdAt'):
            if field in data:
                data.pop(field)
        return data

    def get_ruleset_rules(self, ruleset_id: str) -> Dict:
        """
        List out all rules under a ruleset verbosely.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/list-all-rules-for-a-ruleset

        Args:
            ruleset_id: ruleset under which to retrieve all rules.

        Returns:
            The ruleset and a verbose listing of the rules underneath it.
        """
        data = self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules')

        # Filter rules' fields.
        for i, rule in enumerate(data['rules']):
            # Remove non-POSTable fields by
            # https://apidocs.threatstack.com/v2/rule-sets-and-rules/create-rule-endpoint
            for field in ('rulesetId', 'updatedAt', 'createdAt'):
                if field in data['rules'][i]:
                    data['rules'][i].pop(field)

        return data

    def get_rule(self, ruleset_id: str, rule_id: str) -> Dict:
        """
        Get a particular rule from a ruleset.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-a-rule-for-a-ruleset

        Args:
            ruleset_id: ruleset ID from which to retrieve the rule.
            rule_id: rule ID to retrieve from this ruleset.

        Returns:
            The rule data.
        """
        data = self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules/{rule_id}')
        for field in ('rulesetId', 'updatedAt', 'createdAt'):
            if field in data:
                data.pop(field)
        return data

    def get_rule_tags(self, rule_id) -> Dict:
        """
        Get tags on a rule.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-tags-for-a-rule-endpoint

        Args:
            rule_id: rule ID on which to retrieve the assigned EC2 tags.

        Returns:
            The tag data.
        """
        data = self._get(f'https://api.threatstack.com/v2/rules/{rule_id}/tags')
        for field in ('errors',):
            if field in data:
                data.pop(field)
        return data

    @retry(tries=3)
    def _put(self, url: str, data: Dict) -> Optional[Dict]:
        """
        PUT request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, data)

        response = requests.put(
            url=url,
            data=json.dumps(data),
            headers={
                'Authorization': self._header,
                'Content-Type': 'application/json'
            }
        )

        try:
            return response.json()
        except json.JSONDecodeError:
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                raise RateLimitedError(delay=float(response.headers['x-rate-limit-reset']) / 1_000)
            else:
                raise URLError(
                    f'Did not get valid JSON in response: {response.text if response.text else response.reason} ~ {response.status_code}'
                )

    @retry(tries=3)
    def _delete(self, url: str) -> Optional[Dict]:
        """
        DELETE request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url)

        response = requests.delete(
            url=url,
            headers={
                'Authorization': self._header,
                'Content-Type': 'application/json'
            }
        )

        try:
            return response.json()
        except json.JSONDecodeError:
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                raise RateLimitedError(delay=float(response.headers['x-rate-limit-reset']) / 1_000)
            else:
                raise URLError(
                    f'Did not get valid JSON in response: {response.text if response.text else response.reason} ~ {response.status_code}'
                )

    @retry(tries=3)
    def _post(self, url: str, data: Dict) -> Optional[Dict]:
        """
        POST request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.
            data: payload to submit to the endpoint.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, data)

        response = requests.put(
            url=url,
            data=json.dumps(data),
            headers={
                'Authorization': self._header,
                'Content-Type': 'application/json'
            }
        )

        try:
            return response.json()
        except json.JSONDecodeError:
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                raise RateLimitedError(delay=float(response.headers['x-rate-limit-reset']) / 1_000)
            else:
                raise URLError(
                    f'Did not get valid JSON in response: {response.text if response.text else response.reason} ~ {response.status_code}'
                )


def paginate(f: Callable) -> Optional[Dict]:
    """
    For rules and rulesets, I don't think pagination is yet necessary. When I eventually implement a tasks subparser,
    I could implement this on the GET endpoint.
    """
    raise NotImplementedError
