import urllib3
import json
import ssl
import logging


ENV_DICT = {'test': {'target_prom': 'localhost:9090',
                     'target_cred': 'YWRtaW46YWRtaW4='},
            'prod': {'target_prom': 'localhost:9090',
                     'target_cred': ''}
            }

STATUS = 'status'
SUCCESS = 'success'
ERROR = 'error'
ERROR_TYPE = 'errorType'
WARNINGS = 'warnings'
DATA = 'data'
RESULT = 'result'
RESULT_TYPE = 'resultType'
MATRIX = 'matrix'
VECTOR = 'vector'
SCALAR = 'scalar'
STRING = 'string'
METRIC = 'metric'
ID = 'id'


class PrometheusAdapter(object):
    def __init__(self,
                 credentials,
                 prometheus,
                 api_version='',
                 protocol='https',
                 verbose=False):
        self.verbose = verbose
        self.prometheus = prometheus
        self.api_version = api_version
        self.protocol = protocol
        self.headers = {'Content-Type': 'application/json', 'Authorization': 'Basic %s' % credentials}
        self.base_url = prometheus
        # create logger
        self.logger = logging.getLogger('prom_adapter')
        self.logger.setLevel(logging.DEBUG)

    def test(self):
        info = self.prom_query('container_cpu_usage_seconds_total{cpu="cpu07"}')
        print('rmi data: %r' % info)
        data = info['info']
        if data:
            if data[RESULT_TYPE] == VECTOR:
                for item in data[RESULT]:
                    print('id: %s' % item[METRIC][ID])

    def prom_query(self, query):
        service = 'query?query=%s' % query
        return self._get_json_data(service)

    def get_running_containers(self):
        qresult = self.prom_query('container_memory_usage_bytes{image!=""}')
        result_list = []
        if qresult:
            result = qresult[RESULT]
            # modify result
            for item in result:
                # remove key '__name__' from metric dict
                if '__name__' in item['metric'].keys():
                    del item['metric']['__name__']
                # filter for containers with value > 0 and the label 'image' in the metrics
                if int(item['value'][1]) > 0 and 'image' in item['metric'].keys():
                    result_list.append(item)
        return dict(info=result_list)

    def _get_json_data(self, service):
        data_json = None
        r = self._call_prometheus_api(service)
        if r:
            if r.status == 200:
                data_json = json.loads(r.data.decode('utf-8'))
                if data_json:
                    try:
                        status = data_json[STATUS]
                        if status == SUCCESS:
                            data_json = data_json[DATA]
                        elif status == ERROR:
                            if WARNINGS in data_json[DATA].keys():
                                self.logger.warning('%s' % data_json[DATA][WARNINGS])
                            if ERROR in data_json[DATA].keys():
                                if ERROR_TYPE in data_json[DATA].keys():
                                    self.logger.error('%s: %s' % (data_json[DATA][ERROR_TYPE], data_json[DATA][ERROR]))
                                else:
                                    self.logger.error('%s' % data_json[DATA][ERROR])
                            data_json = None
                        else:
                            data_json = None
                    except KeyError as e:
                        self.logger.error('KeyError: %s' % e)
                        data_json = None
            else:
                self.logger.error('status: %s headers: %s' % (r.status, r.headers))
        return data_json

    def _call_prometheus_api(self, service, ssl_verify=False):
        url = '%s://%s/api/%s/%s' % (self.protocol,
                                     self.prometheus,
                                     self.api_version,
                                     service)
        if ssl_verify:
            cert_reqs = ssl.CERT_REQUIRED
        else:
            cert_reqs = ssl.CERT_NONE
            urllib3.disable_warnings()
        urllib3.disable_warnings()
        http = urllib3.PoolManager(cert_reqs=cert_reqs)
        try:
            return http.request('GET', url, headers=self.headers)
        except urllib3.exceptions.MaxRetryError as e:
            self.logger.error('MaxRetryError: %s' % e)
            return None


def main():
    stage = 'test'
    prom = PrometheusAdapter(credentials=ENV_DICT[stage]['target_cred'],
                             prometheus=ENV_DICT[stage]['target_prom'],
                             api_version='v1',
                             protocol='http')
    prom.test()


if __name__ == "__main__":
    main()
