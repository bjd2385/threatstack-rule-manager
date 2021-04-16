"""
Manage API calls to TS.

All response objects are returned in a POSTable format, so we can store them on disk that way.
"""

from typing import Optional, Dict, Callable, Type, Any

import logging
import requests
import json

from urllib.error import URLError
from mohawk import Sender
from functools import wraps
from time import sleep


def retry(exc: Type[Exception], tries: int =3, delay: float =2.0) -> Callable:
    """
    A general request retry decorator with optional time delay.

    Args:
        exc: exception to catch and retry on.
        tries: number of times to retry the wrapped function call. When `0`, retries indefinitely.
        delay: positive wait period.

    Raises:
        A RetryLimitExceeded exception in the event that the call could not be completed after the
        allotted number of attempts.

    Returns:
        Either the result of a successful function call (be it via retrying or not).
    """
    if tries < 0 or delay < 0:
        raise ValueError('Expected positive `tries` and `delay` values, received: '
                         f'tries {tries}, delay {delay}')

    def _f(f: Callable) -> Callable:

        class RetryLimitExceeded(OSError):
            pass

        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Any:
            res: Any = None

            def call() -> bool:
                nonlocal res
                try:
                    res = f(*args, **kwargs)
                    return True
                except exc as msg:
                    logging.info(f'Retrying: {msg} ~ {res}')
                    sleep(delay)
                    return False

            if tries > 0:
                for _ in range(tries):
                    if call():
                        return res
                else:
                    raise RetryLimitExceeded(
                        f'Exceeded max of {tries} tries. Raise the delay limit of {delay} or number of tries'
                    )
            else:
                while not call():
                    pass
                else:
                    return res

        return new_f

    return _f


class API:
    """
    API object that provides an interface to the remote organizations' state.
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

    def _update_sender(self, url: str) -> None:
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
            method='GET',
            always_hash_content=False,
            content_type='application/json',
            ext=self._ext
        )
        self._header = self._sender.request_header

    @retry(URLError, tries=3, delay=30.0)
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
            raise URLError(
                'Did not get valid JSON in response: '
                f'{response.text if response.text else response.reason} '
                f'{response.status_code}'
            )

    def get_rulesets(self) -> Dict:
        """
        Return a list of rulesets and rules thereunder.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/list-ruleset

        Returns:
            A dictionary of rulesets and their rules.
        """
        data = self._get('https://api.threatstack.com/v2/rulesets')
        return data

    def get_ruleset(self, ruleset_id: str) -> Dict:
        """
        Return a particular ruleset and rules thereunder.

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
        filtered_data = []
        print(data)
        for rule in data['rules']:
            rule_id = rule['id']
            # Remove non-POSTable fields by
            # https://apidocs.threatstack.com/v2/rule-sets-and-rules/create-rule-endpoint
            for field in ('rulesetId', 'updatedAt', 'createdAt'):
                if field in data[rule_id]:
                    data['rules'][rule].pop(field)
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

        return data

    @retry(URLError, tries=3, delay=30.0)
    def _put(self) -> Optional[Dict]:
        ...

    @retry(URLError, tries=3, delay=30.0)
    def _delete(self) -> Optional[Dict]:
        ...

    @retry(URLError, tries=3, delay=30.0)
    def _post(self) -> Optional[Dict]:
        ...


def paginate(f: Callable) -> Optional[Dict]:
    """
    For rules and rulesets, I don't think pagination is yet necessary. When I eventually implement a tasks subparser,
    I could implement this on the GET endpoint.
    """
    raise NotImplementedError
