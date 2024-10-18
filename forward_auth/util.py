import urllib.request
import json


class Util:

    @staticmethod
    def urljson(url):
        response = urllib.request.urlopen(url)
        if response.code >= 200 or response <= 299:
            encoding = response.info().get_content_charset('utf-8')
            return json.loads(response.read().decode(encoding))
        else:
            raise (Exception(f"Could not load data from {url} code={response.code}"))
