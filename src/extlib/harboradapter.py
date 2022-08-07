from __future__ import print_function
import time
import swagger_client
from swagger_client.rest import ApiException
import argparse
import logging
import base64
import binascii
import ast
import functools
import sys

ENV_DICT = {'test': {'source_reg': 'rmiharbor.ch',
                     'target_reg': '',
                     'source_cred': '',
                     'target_cred': '',
                     'source_protocol': '',
                     'target_protocol': '',
                     'source_api': '',
                     'target_api': ''},
            'prod': {'source_reg': '',
                     'target_reg': '',
                     'source_cred': '',
                     'target_cred': '',
                     'source_protocol': '',
                     'target_protocol': '',
                     'source_api': '',
                     'target_api': ''},
            }

# code to url encode '/'
SLASH_URL_ENCODED = '%2F'
# slash
SLASH = '/'
# pagination options
MAX_PAGE_SIZE = 100
# logging options
log = logging.getLogger(__file__)


class HarborAdapter(object):
    def __init__(self,
                 credentials,
                 cache_maxsize,
                 registry,
                 api_version='',
                 protocol='https',
                 stage_dev=False,
                 log_level=logging.INFO):
        # TODO: find solution to use cache_maxsize in __api_call
        self.cache_maxsize = int(cache_maxsize)
        self.stage_dev = stage_dev
        logging.basicConfig(format='%(asctime)s %(levelname)s:%(filename)s >>> %(message)s', level=log_level)
        self.log = logging.getLogger(__file__)
        cred_dict = self.__get_credentials(credentials)
        # Configure HTTP basic authorization and host
        configuration = swagger_client.Configuration()
        configuration.username = cred_dict['username']
        configuration.password = cred_dict['password']
        # TODO remove next line in production
        configuration.verify_ssl = False
        configuration.host = '%s://%s/api%s' % (protocol, registry, api_version)

        config = swagger_client.ApiClient(configuration)

        # create an instances of the API classes
        self.artifact_api = swagger_client.ArtifactApi(config)
        self.project_api = swagger_client.ProjectApi(config)
        self.repository_api = swagger_client.RepositoryApi(config)

    def __get_credentials(self, credentials):
        username = ''
        password = ''
        try:
            credential_list = base64.b64decode(credentials).decode("utf-8").split(':')
            if credential_list and len(credential_list) == 2:
                username = credential_list[0]
                password = credential_list[1]
            else:
                self.log.error('wrong credential format, missing or too many ":"')
        except binascii.Error as e:
            self.log.error('wrong credential format: %s' % e)
        return dict(username=username, password=password)

    @functools.lru_cache(maxsize=600)
    def __api_call(self, pagination, func, *args, **kwargs):
        self.log.info('calling harbor api %s' % func)
        page_size = MAX_PAGE_SIZE
        results = []
        if pagination:
            i = 1
            # get all pages containing results
            while True:
                page = func(*args, **kwargs, page_size=page_size, page=i)
                if len(page) > 0:
                    results.extend(page)
                    i += 1
                else:
                    break
        else:
            try:
                results = func(*args, **kwargs)
            except ApiException as e:
                self.log.error("Exception when calling Api: %s\n" % e)
        return results

    def clear_cache(self):
        cache_info = self.__api_call.cache_info()
        self.__api_call.cache_clear()
        return dict(info=cache_info)

    @staticmethod
    def _short_tag(tag):
        if tag.startswith('sha256:'):
            return tag[:16]
        else:
            return tag

    def _get_scan_report(self, repo_name, tag, scan_report, severity_level='', cve_id=''):
        """
        extracts the selected information from a scan report and returns a list of information
        :param repo_name:
        :param tag:
        :param scan_report:
        :param severity_level:
        :param cve_id:
        :return: list of lines of information
        """
        v_detected = False
        if cve_id:
            report = []
        else:
            report = {}
        # detect the first key in the  scan report
        try:
            first_key = list(scan_report.keys())[0]
            # if the key 'vulnerabilities' is there loop through the contents
            if scan_report[first_key]['vulnerabilities']:
                for v in scan_report[first_key]['vulnerabilities']:
                    if cve_id:
                        if cve_id == v['id']:
                            report.append({})
                            report[-1]['cve_id'] = cve_id
                            report[-1]['severity'] = v['severity']
                            report[-1]['fixed'] = v['fix_version']
                            report[-1]['links'] = v['links']
                            report[-1]['image'] = '%s:%s' % (repo_name, self._short_tag(tag))
                            report[-1]['package'] = v['package']
                    elif severity_level:
                        if severity_level == v['severity']:
                            # add report header with repo and tag for the first detected vulnerability
                            if not v_detected:
                                v_detected = True
                                report['image'] = '%s:%s' % (repo_name, self._short_tag(tag))
                                report['vlist'] = []
                            report['vlist'].append({'v_id': v['id'],
                                                    'severity': v['severity'],
                                                    'fixed': v['fix_version'],
                                                    'description': v['description'],
                                                    'links': v['links'],
                                                    'package': v['package']})
                    else:
                        # add report header with repo and tag for the first detected vulnerability
                        if not v_detected:
                            v_detected = True
                            report['image'] = '%s:%s' % (repo_name, self._short_tag(tag))
                            report['vlist'] = []
                        report['vlist'].append({'v_id': v['id'],
                                                'severity': v['severity'],
                                                'fixed': v['fix_version'],
                                                'description': v['description'],
                                                'links': v['links'],
                                                'package': v['package']})
        except IndexError:
            pass
        return report

    def get_projects(self, key_map, p_id=0):
        project_list = []
        projects = self.__api_call(True, self.project_api.list_projects)
        try:
            p_id = int(p_id)
        except ValueError:
            self.log.warning('project_id is not an integer')
            p_id = 0
        for item in projects:
            if item.project_id == p_id or p_id == 0:
                pro_dict = {}
                for key in key_map:
                    try:
                        pro_dict[key[0]] = item.__getattribute__(key[1])
                    except AttributeError as e:
                        self.log.info('get_projects: %a' % e)
                project_list.append(pro_dict)
        return project_list

    def get_repos(self, project_name):
        repo_list = self.__api_call(True, self.repository_api.list_repositories, project_name)
        return repo_list

    def get_tags(self, project_name, repository_name, tags_key, short_digest=True):
        # modify repository_name by removing project name and url encode '/' e.g.:
        # <project_name>/<repo_name_part1>/<repo_name_part2> -> <repo_name_part1><SLASH_URL_ENCODED><repo_name_part2>
        # adfinis/ebau/frontend -> ebau<SLASH_URL_ENCODED>frontend
        repo_name = SLASH_URL_ENCODED.join(repository_name.split(SLASH)[1:])
        # init the list of tags
        tag_list = []
        # get all artifacts of a repository
        artifacts = self.__api_call(True, self.artifact_api.list_artifacts, project_name, repo_name)
        # if the repository contains artifacts return their tags or their digest
        if artifacts:
            for artifact in artifacts:
                try:
                    # if the artifact has tags, get their names
                    if artifact.__getattribute__(tags_key):
                        for tag in artifact.__getattribute__(tags_key):
                            tag_list.append('%s:%s' % (repository_name, tag.name))
                    # if the artifact has no tags, get the short digest of the artifact
                    else:
                        if short_digest:
                            tag_list.append('%s:%s' % (repository_name, artifact.__getattribute__('digest')[:15]))
                        else:
                            tag_list.append('%s:%s' % (repository_name, artifact.__getattribute__('digest')))
                except AttributeError as e:
                    self.log.info('get_tags: %a' % e)
        return tag_list

    def get_vulnerabilities(self,
                            project_name,
                            repository_name,
                            reference,
                            x_accept_vulnerabilities):
        v_addition = []
        try:
            # Get the vulnerabilities addition of the specific artifact
            # v_addition = self.artifact_api.get_vulnerabilities_addition(project_name,
            #                                                         repository_name,
            #                                                         reference,
            #                                                         x_accept_vulnerabilities=x_accept_vulnerabilities)
            v_addition = self.__api_call(False, self.artifact_api.get_vulnerabilities_addition,
                                         project_name,
                                         repository_name,
                                         reference,
                                         x_accept_vulnerabilities=x_accept_vulnerabilities)
        except ApiException as e:
            self.log.error("Exception when calling ArtifactApi->get_vulnerabilities_addition: %s\n" % e)
        return v_addition

    def get_harbor_projects(self, p_id=0):
        project_key_map = [('name', 'name'), ('id', 'project_id')]
        tags_key = 'tags'
        project_list = self.get_projects(project_key_map, p_id=p_id)
        # add repositories and tags to every project
        for project in project_list:
            repos = []
            repo_list = self.get_repos(project['name'])
            for item in repo_list:
                repos.append(dict(name=item.name,
                                  tags=self.get_tags(project['name'],
                                                     item.name,
                                                     tags_key,
                                                     short_digest=False)))
            project['repos'] = repos
        return project_list

    def get_harbor_scans(self,
                         project_id=0,
                         severity_level='',
                         cve_id=''):
        # set x_accept_vulnerabilities option
        x_accept_vulnerabilities = 'application/vnd.security.vulnerability.report; version=1.1'
        # init scan_list
        scan_list = []
        # init cve_report that is used when a cve_id is provided
        cve_report = {'cve_id': '', 'severity': '', 'fixed': '', 'links': '',
                      'found': 0, 'images': [], 'packages': []}
        # get information about projects
        project_info = self.get_harbor_projects(p_id=project_id)
        # get vulnerabilities
        for project in project_info:
            for repo in project['repos']:
                repo_name_encoded = SLASH_URL_ENCODED.join(repo['name'].split(SLASH)[1:])
                for tag in repo['tags']:
                    tag_end = tag.split(':', 1)[-1]
                    vulnerabilities = self.get_vulnerabilities(project['name'],
                                                               repo_name_encoded,
                                                               tag_end,
                                                               x_accept_vulnerabilities)
                    if vulnerabilities:
                        # ensure we get a dict by using ast.literal_eval
                        v_dict = ast.literal_eval(vulnerabilities)
                        custom_report = self._get_scan_report(repo['name'],
                                                              tag_end,
                                                              v_dict,
                                                              severity_level=severity_level,
                                                              cve_id=cve_id)
                        if custom_report:
                            if cve_id:
                                for item in custom_report:
                                    cve_report['cve_id'] = cve_id
                                    cve_report['severity'] = item['severity']
                                    cve_report['fixed'] = item['fixed']
                                    cve_report['links'] = item['links']
                                    cve_report['images'].append(item['image'])
                                    cve_report['packages'].append(item['package'])
                            else:
                                scan_list.append(custom_report)
        if cve_id:
            found = len(cve_report['images'])
            if found > 0:
                cve_report['found'] = found
                scan_list.append(cve_report)

        return scan_list

    def get_harbor_info(self,
                        info_type='projects',
                        project_id=0,
                        severity_level='',
                        cve_id=''):
        self.log.info('info start computing %s' % info_type)
        start = time.time()
        if info_type == 'projects':
            info = dict(info=self.get_harbor_projects())
            end = time.time()
            self.log.info('info projects computed: %s' % (end-start))
            return info
        elif info_type == 'scan':
            info = dict(info=self.get_harbor_scans(project_id=project_id,
                                                   severity_level=severity_level,
                                                   cve_id=cve_id))
            end = time.time()
            self.log.info('info scan computed: %s' % (end-start))
            return info


def _exit_with_info(parser, item, choice):
    print('%s must be %s' % (item, '|'.join(choice)))
    parser.print_help()
    sys.exit(1)


def main():
    logging.basicConfig(format='%(levelname)s:%(filename)s> %(message)s', level=logging.INFO)

    actions = ['info']
    info_types = ['projects', 'images', 'users', 'scan']
    severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']
    # default values
    protocol = 'https'
    api_version = '/v2.0'
    cache_maxsize = 512
    stage = 'test'
    action = 'info'
    info_type = 'projects'
    project_id = ''
    severity_level = ''
    cve_id = ''
    # parse arguments
    parser = argparse.ArgumentParser(description="""harbor management extension""")
    parser.add_argument('-s', '--stage',
                        help='stage in range ' + '|'.join(ENV_DICT.keys()))
    parser.add_argument('-a', '--action',
                        help='action in range ' + '|'.join(actions))
    parser.add_argument('-i', '--info',
                        help='type of info in range ' + '|'.join(info_types))
    parser.add_argument('-p', '--project',
                        help='id of project must be an integer')
    parser.add_argument('-l', '--level',
                        help='severity level in range ' + '|'.join(severity_levels))
    parser.add_argument('-e', '--cve',
                        help='cve id of vulnerability')
    args = parser.parse_args()

    if args.stage:
        if args.stage in ENV_DICT.keys():
            stage = args.stage
        else:
            _exit_with_info(parser, 'stage', ENV_DICT.keys())
    if args.action:
        if args.action in actions:
            action = args.action
        else:
            _exit_with_info(parser, 'action', actions)
    if args.info:
        if args.info in info_types:
            info_type = args.info
        else:
            _exit_with_info(parser, 'info', info_types)
    if args.level:
        if args.level in severity_levels:
            severity_level = args.level
        else:
            _exit_with_info(parser, 'severity level', severity_levels)
    if args.project:
        try:
            project_id = int(args.project)
        except ValueError:
            print('id of project must be an integer')
            parser.print_help()
            sys.exit(1)
    if args.cve:
        if args.cve != 'no_value':
            cve_id = args.cve

    log.info('args -> stage: %s, action: %s, info_type: %s, severity_level: %s, project_id: %s, cve_id: %s'
             % (stage, action, info_type, severity_level, project_id, cve_id))

    # continue according to action
    if action == 'info':
        harbor = HarborAdapter(credentials=ENV_DICT[stage]['source_cred'],
                               registry=ENV_DICT[stage]['source_reg'],
                               protocol=protocol,
                               api_version=api_version,
                               cache_maxsize=cache_maxsize)
        info = harbor.get_harbor_info(project_id=project_id,
                                      info_type=info_type,
                                      severity_level=severity_level,
                                      cve_id=cve_id)
        print('info: %s' % info)


if __name__ == "__main__":
    main()
