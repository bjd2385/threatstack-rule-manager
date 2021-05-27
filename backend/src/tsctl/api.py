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
    A request retry decorator. If singledispatch becomes compatible with `typing`, it'd be cool to duplicate this
    registering another dispatch on `f`, essentially removing a layer.

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


def paginate(aggregate_field: str) -> Callable:
    """
    For rules and rulesets, I don't think pagination is yet necessary. When I eventually implement a tasks subparser,
    I could add this on the GET endpoint wrapping the retry.

    Args:
        aggregate_field: on endpoints that have pagination, like GET servers, they usually have a field pointing to a
            list of returned items (objects themselves), such as 'alerts', 'servers', etc. For rule managementm, there
            aren't typically enough returned rules for pagination to count, but eventually this will need to be applied
            on additional methods to allow tsctl.tasks to work.

    Returns:
        Dictionary of the concatenated/aggregated results, with a null token.
    """
    def _f(f: Callable) -> Callable:
        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Dict:
            aggregate = {
                aggregate_field: [],
                'token': None
            }
            while True:
                res = f(*args, **kwargs)
                if aggregate_field in res:
                    aggregate[aggregate_field] += res[aggregate_field]
                    if res['token'] == '' or res['token'] is None:
                        break
                else:
                    raise KeyError(f'Fatal - aggregate field \'{aggregate_field}\' doesn\'t exist on this endpoint.')
            return aggregate
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

    def _update_sender(self, url: str, method: str, data: Optional[Dict] =None) -> None:
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
            method=method,
            always_hash_content=False,
            content_type='application/json',
            ext=self._ext
        )
        self._header = self._sender.request_header

    @retry(tries=5)
    def _get(self, url: str) -> Optional[Dict]:
        """
        GET request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, 'GET')

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

    def get_rulesets(self) -> Optional[Dict]:
        """
        Return a list of rulesets and rules thereunder. This isn't meant to return an object in a POSTable format,
        unlike other methods.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/list-ruleset

        Returns:
            A dictionary of rulesets and their rules.
        """
        response = self._get('https://api.threatstack.com/v2/rulesets')

        return response

    def get_ruleset(self, ruleset_id: str) -> Optional[Dict]:
        """
        Return a particular ruleset and rule IDs thereunder.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-a-ruleset

        Args:
            ruleset_id: ruleset ID we'd like to retrieve.

        Returns:
            The ruleset and rule IDs thereunder.
        """
        if response := self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}'):
            for field in ('updatedAt', 'createdAt'):
                if field in response:
                    response.pop(field)
            # FIXME: Fix a weird problem with our API field names. Again, I want to store these data in POSTable format.
            #
            if 'rules' in response:
                response['ruleIds'] = response['rules']
                response.pop('rules')
        return response

    def get_ruleset_rules(self, ruleset_id: str) -> Optional[Dict]:
        """
        List out all rules under a ruleset verbosely.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/list-all-rules-for-a-ruleset

        Args:
            ruleset_id: ruleset under which to retrieve all rules.

        Returns:
            The ruleset and a verbose listing of the rules underneath it.
        """
        if response := self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules'):
            # Filter rules' fields.
            for i, rule in enumerate(response['rules']):
                # Remove non-POSTable fields by
                # https://apidocs.threatstack.com/v2/rule-sets-and-rules/create-rule-endpoint
                for field in ('rulesetId', 'updatedAt', 'createdAt'):
                    if field in response['rules'][i]:
                        response['rules'][i].pop(field)

        return response

    def get_rule(self, ruleset_id: str, rule_id: str) -> Optional[Dict]:
        """
        Get a particular rule from a ruleset.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-a-rule-for-a-ruleset

        Args:
            ruleset_id: ruleset ID from which to retrieve the rule.
            rule_id: rule ID to retrieve from this ruleset.

        Returns:
            The rule data.
        """
        if response := self._get(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules/{rule_id}'):
            for field in ('id', 'rulesetId', 'updatedAt', 'createdAt'):
                if field in response:
                    response.pop(field)

        return response

    def get_rule_tags(self, rule_id) -> Optional[Dict]:
        """
        Get tags on a rule.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/get-tags-for-a-rule-endpoint

        Args:
            rule_id: rule ID on which to retrieve the assigned EC2 tags.

        Returns:
            The tag data.
        """
        if response := self._get(f'https://api.threatstack.com/v2/rules/{rule_id}/tags'):
            for field in ('errors',):
                if field in response:
                    response.pop(field)

        return response

    @retry(tries=5)
    def _put(self, url: str, data: Dict) -> Optional[Dict]:
        """
        PUT request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, 'PUT', data)

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

    def put_ruleset(self, ruleset_id: str, data: Dict) -> Optional[Dict]:
        """
        Update a ruleset that already exists in the platform.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/update-rule-set-endpoint

        Args:
            ruleset_id: ruleset ID to update in the remote platform.
            data: ruleset data to send and use to overwrite the ruleset in the remote platform.

        Returns:
            The response from the platform when the request is successful, nothing otherwise.
        """
        if response := self._put(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}', data):
            for field in ('createdAt', 'updatedAt'):
                if field in response:
                    data.pop(field)

        return response

    def put_rule(self, ruleset_id: str, rule_id: str, data: Dict) -> Optional[Dict]:
        """
        Update a rule that already exists in the platform.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/update-rule-endpoint

        Args:
            ruleset_id: ruleset ID within which to update this rule in the remote platform.
            rule_id: rule ID to update in the remote platform.
            data: rule data to send and use to overwrite the rule in the remote platform.

        Returns:
            The response from the platform when the request is successful, nothing otherwise.
        """
        if response := self._put(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules/{rule_id}', data):
            for field in ('createdAt', 'updatedAt', 'rulesetId'):
                if field in response:
                    response.pop(field)

        return response

    # I am purposely skipping `put_suppressions`, since they can be updated via put_rule.

    @retry(tries=5)
    def _delete(self, url: str) -> Optional[Dict]:
        """
        DELETE request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, 'DELETE')

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

    def delete_rule(self, ruleset_id: str, rule_id: str) -> Optional[Dict]:
        """
        Delete a rule from the platform.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/delete-rule-endpoint

        Args:
            ruleset_id: ruleset ID within which this rule resides.
            rule_id: rule ID we wish to delete.

        Returns:
            An empty dict if the rule deletion was successful.
        """
        response = self._delete(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules/{rule_id}')

        return response

    def delete_ruleset(self, ruleset_id: str) -> Optional[Dict]:
        """
        Delete a ruleset from the platform.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/delete-ruleset

        Args:
            ruleset_id: ruleset ID to delete.

        Returns:
            A dict containing a list of server_ids that were assigned this ruleset.
        """
        response = self._delete(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}')

        return response

    @retry(tries=5)
    def _post(self, url: str, data: Dict) -> Optional[Dict]:
        """
        POST request on a TS API endpoint using Hawk Auth.

        Args:
            url: the url (including endpoint and content) on which to make the request.
            data: payload to submit to the endpoint.

        Returns:
            A response on that endpoint, or nothing if an error is returned.
        """
        self._update_sender(url, 'POST', data)

        response = requests.post(
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

    def post_rule(self, ruleset_id: str, data: Dict) -> Optional[Dict]:
        """
        Create a new rule in the platform based on the data provided.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/create-rule-endpoint

        Args:
            ruleset_id: ruleset ID within which to create this new rule.
            data: rule data to submit to the platform.

        Returns:
            The newly-generated rule's JSON, including its platform-assigned ID that should be propagated back through
            local directory structure (through renaming the directories).
        """
        response = self._post(f'https://api.threatstack.com/v2/rulesets/{ruleset_id}/rules', data)

        for field in ('createdAt', 'updatedAt', 'rulesetId'):
            if field in response:
                response.pop(field)

        return response

    def post_ruleset(self, data: Dict) -> Optional[Dict]:
        """
        Create a new ruleset in the platform based on the data provided.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/create-ruleset

        Args:
            data: ruleset data to submit to the platform.

        Returns:
            The newly-generated rulesets JSON, including its platform-assigned ID that should be propagated back
            through local directory structure (through renaming the directories).
        """
        if response := self._post(f'https://api.threatstack.com/v2/rulesets', data):
            for field in ('createdAt', 'updatedAt'):
                if field in response:
                    response.pop(field)

        return response

    def post_tags(self, rule_id: str, data: Dict) -> Optional[Dict]:
        """
        Create or update tags on a rule.

        https://apidocs.threatstack.com/v2/rule-sets-and-rules/edit-tags-for-a-rule

        Args:
            rule_id: rule ID on which to update the tags.https://api.threatstack.com/v2/rules/{ruleId}/tags
            data: tag data to submit to the platform.

        Returns:
            The same object as was submitted, if the request was successful.
        """
        response = self._post(f'https://api.threatstack.com/v2/rules/{rule_id}/tags', data)

        return response
