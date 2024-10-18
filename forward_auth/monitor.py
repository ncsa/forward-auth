from abc import ABC, abstractmethod
import logging
import time
import geohash2
import influxdb_client
import IP2Location
from dotenv import load_dotenv


class MonitorInterface(ABC):
    @abstractmethod
    def record_request(self, request):
        pass

    @abstractmethod
    def setup(self):
        pass


class IncoreMonitor(MonitorInterface):
    def __init__(self, geolocation_db_name='data/IP2LOCATION-LITE-DB5.BIN', track_resources=()):
        self.geolocation_db_name = geolocation_db_name
        self.geolocation = None
        self.geoserver = {}
        self.geoserver_delta = 2
        self.influxdb_writer = None
        self.tracked_resources = track_resources

    def setup(self):
        # load env
        load_dotenv()

        # set up geolocation database
        try:
            self.geolocation = IP2Location.IP2Location(self.geolocation_db_name)
        except Exception:
            logging.exception("No IP2Location database found.")

        # set up influxdb client
        try:
            client = influxdb_client.InfluxDBClient.from_env_properties()
            writer = client.write_api()
            self.influxdb_writer = writer
        except:
            logging.exception("Could not setup influxdb writer")

    def record_request(self, request):
        # get some handy variables
        request_info = IncoreMonitor.get_request_info(request)
        resource = request_info.get("resource")
        uri = request_info['uri']

        # only track frontpage once
        if resource == "frontpage" and not (uri.endswith(".html") or uri.endswith("/")):
            return

        # only track manual once
        if resource == "doc" and not (uri.endswith(".html") or uri.endswith("/")):
            return

        # TODO fix logic: only track geoserver once every second
        if resource == "geoserver":
            return

        # skip non-tracked resources
        if resource not in self.tracked_resources:
            logging.debug(f"not tracking resource {resource}")
            return

        logging.debug(f"tracking resource {resource}")
        remote_ip = request.headers.get('X-Forwarded-For', '')
        if not remote_ip:
            remote_ip = request.remote_addr

        server = request.headers.get('X-Forwarded-Host', '')
        if not server:
            server = request.host

        # find the group
        if "incore_ncsa" in request_info["groups"]:
            group = "NCSA"
        elif "incore_coe" in request_info["groups"]:
            group = "CoE"
        else:
            group = "public"

        # basic information for all endpoints
        tags = {
            "server": server,
            "http_method": request.method,
            "resource": resource,
            "group": group
        }
        fields = {
            "url": uri,
            "ip": remote_ip,
            "elapsed": time.time() - request_info.get('start')
        }

        # store specific information
        fields.update(request_info['fields'])
        fields.update(request_info['tags'])

        # calculate geo location
        if self.geolocation:
            try:
                rec = self.geolocation.get_all(remote_ip)
                tags["country_code"] = rec.country_short
                tags["country"] = rec.country_long
                tags["region"] = rec.region
                tags["city"] = rec.city
                fields["latitude"] = rec.latitude
                fields["longitude"] = rec.longitude
                fields["geohash"] = geohash2.encode(rec.latitude, rec.longitude)
            except Exception:
                logging.error("Could not lookup IP address")

        # create the datapoint that is written to influxdb
        datapoint = {
            "measurement": "auth",
            "tags": tags,
            "fields": fields,
            "time": int(time.time() * 10 ** 9)
        }

        # either write to influxdb, or to console
        if self.influxdb_writer:
            self.influxdb_writer.write("incore", "incore", datapoint)
        else:
            logging.info(datapoint)

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
