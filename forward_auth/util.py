import urllib.request
import json
import time
import logging

class Util:

    @staticmethod
    def urljson(url):
        response = urllib.request.urlopen(url)
        if response.code >= 200 or response <= 299:
            encoding = response.info().get_content_charset('utf-8')
            return json.loads(response.read().decode(encoding))
        else:
            raise (Exception(f"Could not load data from {url} code={response.code}"))

    @staticmethod
    def user_info_as_cache_key(user_info):
        """Return username from request_info to be used as cache key"""
        return user_info["username"]

    @staticmethod
    def get_request_info(request):
        request_info = {
            "uri": "",
            "resource": "",
            "method": request.method,
            "fields": {},
            "start": time.time()
        }
        try:
            uri = request.headers.get('X-Forwarded-Uri', '')
            if not uri:
                uri = request.url
            request_info['uri'] = uri

            # TODO simplified logic need to add back later
            pieces = uri.split('/')
            if len(pieces) == 2:
                request_info['resource'] = pieces[1]
            else:
                request_info['resource'] = pieces[1]
                if request_info['resource'] == "doc" and len(pieces) > 2:
                    request_info['fields']['manual'] = pieces[2]
                if request_info['resource'] == "playbook" and len(pieces) > 2:
                    request_info['fields']['playbook'] = pieces[2]
                if request_info['resource'] == "data" and len(pieces) > 4 and uri.endswith('blob'):
                    request_info['fields']['dataset'] = pieces[4]
                if request_info['resource'] == "dfr3" and len(pieces) > 4:
                    request_info['fields']['fragility'] = pieces[4]
        except IndexError:
            logging.info("No / found in path.")
            request_info['resource'] = 'NA'

        return request_info

