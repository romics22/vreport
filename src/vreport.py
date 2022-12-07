import flask
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_mongoengine import MongoEngine
from flask_mongoengine.wtf import model_form
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_encode
from wtforms import Form, validators, StringField, BooleanField
from extlib import harboradapter
from extlib import promadapter
from waitress import serve
from datetime import datetime
from email.message import EmailMessage
from itertools import filterfalse
from functools import wraps
from urllib3.exceptions import MaxRetryError
import mongoengine.errors
import json
import smtplib
import sys
import os
import logging
import time

# log configuration
LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
LOG_LEVEL_DEFAULT = 'WARNING'
# get log_level from environment or set default
log_level = os.getenv('LOG_LEVEL', LOG_LEVEL_DEFAULT)
if log_level.upper() not in LOG_LEVELS:
    log_level = LOG_LEVEL_DEFAULT
    logging.critical('LOG_LEVEL must be in range %s' % LOG_LEVELS)
    sys.exit(0)
logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s %(filename)s > %(message)s',
                    datefmt="%Y-%m-%d %H:%M:%S",
                    level=logging.getLevelName(log_level.upper()))
log = logging.getLogger(__file__)

# App configuration
DEBUG = False
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
# login manager
login_manager = LoginManager()
login_manager.login_view = "user_login"
login_manager.login_message = u"Please log in to access this page."
login_manager.login_message_category = "info"
login_manager.init_app(app)
# database settings
db_name = os.getenv('DB_NAME', 'vreport')
db_host = os.getenv('DB_HOST', 'localhost')
db_port = os.getenv('DB_PORT', 27017)
try:
    db_port = int(db_port)
except ValueError as e:
    log.error('environment variable DB_PORT must be integer: %s' % e)
    sys.exit(0)
app.config['MONGODB_SETTINGS'] = {
    'db': db_name,
    'host': db_host,
    'port': db_port
}
db = MongoEngine()
db.init_app(app)


class User(db.Document):
    active = db.BooleanField(default=True)
    # User authentication information
    username = db.StringField(default='')
    password = db.StringField(required=True)
    # User information
    email = db.StringField(required=True, max_length=30)
    first_name = db.StringField(required=True, default='')
    last_name = db.StringField(required=True, default='')
    # Relationships
    roles = db.ListField(db.StringField(), default=[])

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.active

    @property
    def is_anonymous(self):
        return False

    @property
    def name(self):
        return self.username

    def get_id(self):
        return str(self.id)

    def get_hashpass(self):
        return self.password


class Content(db.EmbeddedDocument):
    text = db.StringField(max_length=1024)
    category = db.StringField(max_length=3)
    updated_at = db.DateTimeField(default=datetime.utcnow)


class Project(db.Document):
    last_seen = db.DateTimeField()
    number = db.IntField(min_value=0, max_value=99)
    name = db.StringField(max_length=80)


class Assessment(db.Document):
    last_seen = db.DateTimeField()
    author = db.ReferenceField(User, reverse_delete_rule=mongoengine.NULLIFY)
    project = db.ReferenceField(Project, reverse_delete_rule=mongoengine.NULLIFY)
    image = db.StringField(max_length=150)
    package = db.StringField(max_length=100)
    cve_id = db.StringField(max_length=50)
    cve_link = db.StringField(max_length=150)
    severity = db.StringField(max_length=30)
    content = db.EmbeddedDocumentField(Content)


class Vulnerability(db.Document):
    project = db.ReferenceField(Project, reverse_delete_rule=mongoengine.NULLIFY)
    assessment = db.ReferenceField(Assessment, reverse_delete_rule=mongoengine.NULLIFY)
    assessment_bool = db.BooleanField(default=False)
    assessment_text = db.StringField()
    last_seen = db.DateTimeField()
    image = db.StringField(max_length=150)
    package = db.StringField(max_length=100)
    cve_id = db.StringField(max_length=50)
    cve_link = db.StringField(max_length=150)
    severity = db.StringField(max_length=30)
    fixed = db.StringField(max_length=150)
    fixed_bool = db.BooleanField(default=False)
    running = db.BooleanField(default=False)
    running_in_gz = db.BooleanField(default=False)
    running_in_pz = db.BooleanField(default=False)
    meta = {
        'index_background': True,
        'indexes': [
            {'name': 'v_search',
             'fields': ['project', 'image', 'package', 'cve_id', 'severity']}
        ]
    }


class Update(db.Document):
    datetime = db.DateTimeField()
    registry = db.StringField(max_length=50)
    updated = db.IntField()
    created = db.IntField()


class State(db.Document):
    warning = db.StringField(max_length=150)


AssessForm = model_form(Assessment)
UserForm = model_form(User)


class ReportsForm(Form):
    severity = StringField('Severity ID:', validators=[validators.DataRequired()])
    projects = StringField('Projects ID:', validators=[validators.DataRequired()])
    cve = StringField('CVE ID:', validators=[validators.DataRequired()])
    fixed = BooleanField('Fixed')
    gzrunning = BooleanField('Gzrunning')
    pzrunning = BooleanField('Pzrunning')
    notassessed = BooleanField('Notassessed')


class MailForm(Form):
    recipient = StringField('Empfänger:', validators=[validators.DataRequired()])


# environment settings
# user-name and password of registry user
arg_credentials = os.getenv('CREDENTIALS')
# size of cache for api requests
arg_cache_maxsize = os.getenv('CACHE_MAXSIZE')
# fqn of internal registry
arg_registry = os.getenv('REGISTRY')
# api version of internal registry
arg_api = os.getenv('API', '')
# option to skip ssl verification of api requests
arg_verify_ssl = os.getenv('VERIFY_SSL')
if arg_verify_ssl == 'False':
    arg_verify_ssl = False
else:
    arg_verify_ssl = True
# fqn of prometheus
arg_prometheus = os.getenv('PROMETHEUS')
# secret url to initialise the admin user
arg_admin_route = os.getenv('ADMIN_URL')

# connect to internal registry
harbor = harboradapter.HarborAdapter(credentials=arg_credentials,
                                     cache_maxsize=arg_cache_maxsize,
                                     registry=arg_registry,
                                     api_version=arg_api,
                                     stage_dev=False,
                                     verify_ssl=arg_verify_ssl)
# connect to prometheus
prom = promadapter.PrometheusAdapter(credentials='',
                                     prometheus=arg_prometheus,
                                     api_version='v1',
                                     protocol='http')

VERSION = '2.3.3'

# local timezone
LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo
# file path to mailing configuration
CONFIG_PATH_MAIL = '../config/mailing_data_json.txt'

GLOBALE_ZONE = '193.135.'
PRIVATE_ZONE = '10.36.'

# url paths
PATH_ASSESS_CREATE = '/assess/create'
PATH_ASSESS_UPDATE = '/assess/update'
# views and arguments in session
VREPORT = 'vreport'
VREPORT_ARGS = 'vreport_args'
ASSESSMENT = 'assess_query'
ASSESSMENT_ARGS = 'assessment_args'


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.objects(id=user_id).first()
    except mongoengine.errors.ValidationError:
        return None


def admin_required(func):
    # check if current user is 'admin', if not show "forbidden"
    @wraps(func)
    # required for 'url_for' see
    # https://stackoverflow.com/questions/14114296/why-does-flasks-url-for-throw-an-error-when-using-a-decorator-on-that-item-in-p
    def wrapper(*args, **kwargs):
        if current_user.name == 'admin':
            return func(*args, **kwargs)
        else:
            return render_template('403.html'), 403
    return wrapper


@app.route('/user', methods=['GET'])
@login_required
@admin_required
def user_query():
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    return render_template('user_list.html', users=users)


@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    form = UserForm(request.form)
    if request.method == 'POST':  # and form.validate():
        existing_user = User.objects(username=request.form['username']).first()
        if existing_user:
            if check_password_hash(existing_user.get_hashpass(), request.form['password']):
                login_user(existing_user)
                flash('Logged in successfully.')
                next_page = request.args.get('next')
                # TODO
                # is_safe_url should check if the url is safe for redirects.
                # See http://flask.pocoo.org/snippets/62/ for an example.
                # if not is_safe_url(next):
                #     return flask.abort(400)
                #
                return redirect(next_page or url_for('vreport'))
            else:
                log.info('wrong password for user "%s"' % request.form['username'])
        else:
            log.info('user "%s" does not exist' % request.form['username'])
    return render_template('user_login.html', form=form)


@app.route("/user/logout")
@login_required
def user_logout():
    logout_user()
    return redirect('/')


@app.route('/user/create', methods=['GET', 'POST'])
@login_required
@admin_required
def user_create():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        existing_user = User.objects(username=request.form['username']).first()
        if existing_user is None:
            hashpass = generate_password_hash(request.form['password'], method='sha256')
            user = User(username=request.form['username'],
                        password=hashpass,
                        email=request.form['email'],
                        first_name=request.form['first_name'],
                        last_name=request.form['last_name'])
            user.save()
        else:
            flash('User "%s" already exists, nothing updated' % request.form['username'])
        redirect('done')
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    return render_template('user_create.html', form=form, users=users)


@app.route('/user/update', methods=['GET', 'POST'])
@login_required
@admin_required
def user_update():
    form = UserForm(request.form)
    # update user by id, e.g ?user_id=62ea78573656869bd50f5a7d
    try:
        user = User.objects(id=request.args.get('user_id')).first()
    except mongoengine.errors.ValidationError:
        user = None
    if not user:
        flash('no user exists with id=%s' % request.args.get('user_id'))
        return redirect(url_for('user_query'))
    # set form fields to values of user fields
    for field in ['username', 'email', 'first_name', 'last_name']:
        setattr(form, field, getattr(user, field, ''))
    if request.method == 'POST' and form.validate():
        if request.form.get('delete'):
            user.delete()
            return redirect(url_for('user_query'))
        existing_user = User.objects(username=request.form['username']).first()
        # make sure the username is unique
        if existing_user is None or existing_user.id == user.id:
            hashpass = generate_password_hash(request.form['password'], method='sha256')
            user.username = request.form['username']
            user.password = hashpass
            user.email = request.form['email']
            user.first_name = request.form['first_name']
            user.last_name = request.form['last_name']
            user.save()
            return redirect(url_for('user_query'))
        else:
            flash('User "%s" already exists, nothing updated' % request.form['username'])
            return redirect(url_for('user_update', **dict(request.args)))
    else:
        return render_template('user_update.html', form=form)


@app.route('/user/%s' % arg_admin_route, methods=['GET', 'POST'])
def user_create_admin():
    # create admin user with a secret url
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        existing_user = User.objects(username='admin').first()
        if existing_user is None:
            hashpass = generate_password_hash(request.form['password'], method='sha256')
            user = User(username='admin',
                        password=hashpass,
                        email=request.form['email'],
                        first_name=request.form['first_name'],
                        last_name=request.form['last_name'])
            user.save()
        else:
            flash('User "%s" already exists, nothing updated' % request.form['username'])
        redirect('done')
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    return render_template('user_create_admin.html', form=form, users=users)


@app.route('/user/change_pw', methods=['GET', 'POST'])
@login_required
def user_change_pw():
    form = UserForm(request.form)
    if request.method == 'POST':
        existing_user = User.objects(username=current_user.name).first()
        if existing_user:
            if request.form['new_password'] == request.form['new_confirmed_password']:
                hashpass = generate_password_hash(request.form['new_password'], method='sha256')
                existing_user.password = hashpass
                existing_user.save()
                flash('Password for user "%s" successfully updated' % current_user.name)
                return redirect(url_for('reports'))
            else:
                flash('New passwords do not match, nothing changed')
        else:
            # this should not happen
            flash('User "%s" does not exist, nothing updated' % current_user.name)
        redirect('done')
    return render_template('user_change_pw.html', form=form)


@app.route('/assess', methods=['GET'])
def assess_query():
    valid_filters = ['image', 'package', 'cve_id', 'severity']
    filter_dict = dict(request.args)
    # when there are no request arguments
    # set filter to arguments in session
    # or restrict results to nonexistent severity level
    if len(filter_dict) == 0:
        # do 'or isinstance' dict in case the assessment args are {} which means 'All Levels'
        if flask.session.get(ASSESSMENT_ARGS) or isinstance(flask.session.get(ASSESSMENT_ARGS), dict):
            filter_dict = flask.session.get(ASSESSMENT_ARGS)
        else:
            filter_dict['severity'] = 'not_defined'
    # remove empty values and not valid keys
    filter_dict = {k: v for k, v in filter_dict.items() if v and k in valid_filters}
    # set return_to
    flask.session['return_to'] = ASSESSMENT
    flask.session[ASSESSMENT_ARGS] = filter_dict.copy()
    assess = Assessment.objects(**filter_dict)
    assess_list = []
    if not assess:
        flash('No assessments available!')
    else:
        assessments = json.loads(assess.to_json())
        for a_dict in assessments:
            ts = a_dict['content']['updated_at']['$date']
            a_dict['content']['updated_at'] = datetime.fromtimestamp(ts/1000,
                                                                     LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M:%S')
            assess_list.append(a_dict)
    filter_param = url_encode(filter_dict)
    return render_template('assess_list.html',
                           assessments=assess_list,
                           users=User,
                           filters=filter_dict,
                           filter_param=filter_param)


@app.route(PATH_ASSESS_CREATE, methods=['GET', 'POST'])
@login_required
def assess_create():
    form = AssessForm(request.form)
    for field in ['project_id', 'image', 'package', 'cve_id', 'cve_link', 'severity']:
        if request.args.get(field):
            setattr(form, field, request.args.get(field))
        else:
            setattr(form, field, '')
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    if request.method == 'POST':  # and form.validate():
        if request.form['author']:
            author_id = request.form['author']
        else:
            author_id = None
        content = Content(text=request.form['text'],
                          category=request.form['category'])
        asses = Assessment(project=request.form['project_id'],
                           image=request.form['image'],
                           package=request.form['package'],
                           cve_id=request.form['cve_id'],
                           cve_link=request.form['cve_link'],
                           severity=request.form['severity'],
                           content=content,
                           author=author_id
                           )
        new_assess = asses.save()
        v_record = Vulnerability.objects(id=request.args.get('v_id')).first()
        # update vulnerability record
        if v_record:
            v_record.assessment = new_assess.id
            v_record.assessment_bool = True
            v_record.assessment_text = new_assess.content.text
            v_record.save()
        else:
            log.warning('vulnerability with id "%s" not found' % request.args.get('v_id'))
        args = flask.session.get(VREPORT_ARGS)
        if args:
            return redirect(url_for(VREPORT, **args))
        else:
            return redirect(url_for(VREPORT))
    return render_template('assess_create.html', form=form, users=users)


@app.route(PATH_ASSESS_UPDATE, methods=['GET', 'POST'])
@login_required
def assess_update():
    form = AssessForm(request.form)
    # get assessment object from request.args
    if request.args.get('assess_id'):
        assess = Assessment.objects(id=request.args.get('assess_id')).first()
    else:
        assess = Assessment.objects(image=request.args.get('image'),
                                    package=request.args.get('package'),
                                    cve_id=request.args.get('cve_id'),
                                    severity=request.args.get('severity')).first()
    if not assess:
        return jsonify({'error': 'no assessment object found'})
    else:
        # set form fields to values of assessment fields
        for field in ['image', 'package', 'cve_id', 'cve_link', 'severity']:
            setattr(form, field, getattr(assess, field, ''))
        if assess.author:
            # str is not available in template so convert author id here to string
            setattr(form, 'author', str(assess.author.id))
        for field in ['text', 'category']:
            setattr(form, field, getattr(assess.content, field, ''))

        users = User.objects
        if not users:
            users = None
        else:
            users = json.loads(users.to_json())
        if request.method == 'POST':
            if request.form.get('delete'):
                assess.delete()
            else:
                assess.content.text = request.form['text']
                assess.content.category = request.form['category']
                assess.content.updated_at = datetime.utcnow
                assess.author = User.objects(id=request.form['author']).first().id
                assess.save()
                # update vulnerability record
                if request.args.get('v_id'):
                    v_record = Vulnerability.objects(id=request.args.get('v_id')).first()
                else:
                    v_record = Vulnerability.objects(project=assess.project,
                                                     image=assess.image,
                                                     package=assess.package,
                                                     cve_id=assess.cve_id,
                                                     severity=assess.severity).first()
                if v_record:
                    v_record.assessment_text = assess.content.text
                    v_record.save()
                else:
                    log.warning('in assess_update: vulnerability with id "%s" not found' % request.args.get('v_id'))
            # return to last location
            if flask.session.get('return_to') == 'vreport':
                return redirect(url_for(VREPORT, **flask.session.get(VREPORT_ARGS)))
            return_to = flask.session.get('return_to', ASSESSMENT)
            return redirect(url_for(return_to, **dict(request.args)))
        return render_template('assess_update.html', form=form, users=users)


def update_project(data, last_seen):
    for item in data['info']:
        project = Project.objects(name=item['name'], number=item['id']).first()
        if project:
            project.last_seen = last_seen
        else:
            project = Project(name=item['name'],
                              number=item['id'],
                              last_seen=last_seen)
        project.save()


def get_projects(last_seen):
    p_data = []
    projects = Project.objects(last_seen=last_seen).order_by('name')
    if projects:
        for pro in projects:
            log.info('project: %s %s %s %s' % (pro.name, pro.number, pro.last_seen, pro.id))
            p_data.append(dict(number=pro.number, id=pro.id, name=pro.name))
    else:
        log.warning('no projects available')
    return p_data


def get_running_images(container_info):
    network = dict(gz=GLOBALE_ZONE, pz=PRIVATE_ZONE)
    running_images = dict(gz=set(), pz=set(), all=set())
    for item in container_info['info']:
        image_full = item['metric']['image']
        # remove repo name from image
        image = '/'.join(image_full.split('/')[1:])
        hostaddr = item['metric']['hostaddr']
        # image can be '' if it is not in harbor or in another registry than docker hub
        if image:
            for key in network.keys():
                if hostaddr.startswith(network[key]):
                    running_images[key].add(image)
        # combine both zones to all
        running_images['all'] = running_images['gz'].union(running_images['pz'])
    return running_images


def get_running_in_zone(running_images, zone, image):
    if image in running_images[zone]:
        return True
    else:
        return False


def update_vulnerability(data, project_id, last_seen, running_images):
    # update or create vulnerability objects
    update_count = 0
    create_count = 0
    start = time.time()
    for item in data['info']:
        for v in item['vlist']:
            # log.debug('rmi explain: %r' % Vulnerability.objects(project=project_id,
            #                                                     image=item['image'],
            #                                                     package=v['package'],
            #                                                     cve_id=v['v_id'],
            #                                                     severity=v['severity']).explain())
            vulnerability = Vulnerability.objects(project=project_id,
                                                  image=item['image'],
                                                  package=v['package'],
                                                  cve_id=v['v_id'],
                                                  severity=v['severity']).first()
            if vulnerability:
                # update values that might have changed since previous update
                vulnerability.last_seen = last_seen
                vulnerability.cve_link = v['links'][0]
                vulnerability.fixed = v['fixed']
                vulnerability.fixed_bool = True if v['fixed'] else False
                vulnerability.running = get_running_in_zone(running_images, 'all', item['image'])
                vulnerability.running_in_gz = get_running_in_zone(running_images, 'gz', item['image'])
                vulnerability.running_in_pz = get_running_in_zone(running_images, 'pz', item['image'])
                update_count += 1
            else:
                # create new vulnerability object
                vulnerability = Vulnerability(project=project_id,
                                              last_seen=last_seen,
                                              image=item['image'],
                                              package=v['package'],
                                              cve_id=v['v_id'],
                                              cve_link=v['links'][0],
                                              severity=v['severity'],
                                              fixed=v['fixed'],
                                              fixed_bool=True if v['fixed'] else False,
                                              running=get_running_in_zone(running_images, 'all', item['image']),
                                              running_in_gz=get_running_in_zone(running_images, 'gz', item['image']),
                                              running_in_pz=get_running_in_zone(running_images, 'pz', item['image']))
                create_count += 1
            vulnerability.save()
    end = time.time()
    return dict(updated=update_count, created=create_count, duration=end - start)


def create_vulnerability(data, project_id, last_seen, running_images):
    # create vulnerability objects from scratch
    create_count = 0
    start = time.time()
    for item in data['info']:
        for v in item['vlist']:
            # create new vulnerability object
            vulnerability = Vulnerability(project=project_id,
                                          last_seen=last_seen,
                                          image=item['image'],
                                          package=v['package'],
                                          cve_id=v['v_id'],
                                          cve_link=v['links'][0],
                                          severity=v['severity'],
                                          fixed=v['fixed'],
                                          fixed_bool=True if v['fixed'] else False,
                                          running=get_running_in_zone(running_images, 'all', item['image']),
                                          running_in_gz=get_running_in_zone(running_images, 'gz', item['image']),
                                          running_in_pz=get_running_in_zone(running_images, 'pz', item['image']))
            create_count += 1
            vulnerability.save()
    end = time.time()
    return dict(updated=0, created=create_count, duration=end - start)


@app.route('/test', methods=['GET'])
def test_report():
    last_seen = Update.objects.all().order_by('-datetime')[0].datetime
    filter_dict = dict(request.args)
    filter_dict['last_seen'] = last_seen
    # test projects
    # get_projects(last_seen)
    vulnerabilities = Vulnerability.objects(**filter_dict)
    if not vulnerabilities:
        flash('No vulnerabilities available!')
        return jsonify({'error': 'data not found'})
    else:
        v = json.loads(vulnerabilities.to_json())
        return jsonify(v)


@app.route('/test/delete_v', methods=['GET'])
@login_required
@admin_required
def test_delete_vulnerabilities():
    num = Vulnerability.objects.delete()
    log.info('rmi deleted vulnerabilities: %s' % num)
    return jsonify({'deleted': num})


@app.route('/test/delete_a', methods=['GET'])
@login_required
@admin_required
def test_delete_assessments():
    num = Assessment.objects.delete()
    log.info('rmi deleted assessments: %s' % num)
    return jsonify({'deleted': num})


@app.route('/', methods=['GET'])
def vreport():
    if State.objects().first():
        state_warning = State.objects().first().warning
    else:
        state_warning = 0
    if Update.objects().first():
        last_seen = Update.objects.all().order_by('-datetime')[0].datetime
    else:
        last_seen = datetime.utcnow()
    last_import = Update.objects(datetime=last_seen).first()
    valid_filters = ['image', 'package', 'cve_id', 'fixed_bool', 'severity',
                     'project', 'assessment_bool', 'running', 'running_in_gz', 'running_in_pz']
    filter_dict = dict(request.args)
    # when there are no request arguments
    # set filter to arguments in session
    # or restrict results to severity Critical
    if len(filter_dict) == 0:
        if flask.session.get(VREPORT_ARGS):
            filter_dict = flask.session.get(VREPORT_ARGS)
        else:
            # show no results by setting invalid severity level
            filter_dict['severity'] = 'not_defined'
    # remove empty values, not valid keys and remove whitespace left of value
    filter_dict = {k: v.lstrip() for k, v in filter_dict.items() if v and k in valid_filters}
    # store query in session
    # set return_to and args for navigation back to vreport
    flask.session['return_to'] = VREPORT
    flask.session[VREPORT_ARGS] = filter_dict.copy()
    # add last_seen to restrict every query to the latest update of the vulnerabilities
    filter_dict['last_seen'] = last_seen
    # change string to Boolean for Boolean Filters
    for key in ['fixed_bool', 'assessment_bool']:
        if key in filter_dict.keys():
            if filter_dict[key] == 'True':
                filter_dict[key] = True
            else:
                filter_dict[key] = False
    for key in ['running', 'running_in_gz', 'running_in_pz']:
        if key in filter_dict.keys():
            if filter_dict[key] == 'on':
                filter_dict[key] = True
            else:
                filter_dict[key] = False
    # prepare query for vulnerabilities
    v_query = filter_dict.copy()
    # change keys to key__startswith for a search by a partial string
    for key in ['image']:
        if key in v_query.keys():
            value = v_query[key]
            v_query.pop(key)
            v_query['__'.join([key, 'startswith'])] = value
    # get vulnerabilities
    vulnerabilities = Vulnerability.objects(**v_query)
    if not vulnerabilities:
        flash('No vulnerabilities available!')
        v = []
    else:
        v = json.loads(vulnerabilities.to_json())
    # get projects
    projects = Project.objects(last_seen=last_seen).order_by('name')
    p = json.loads(projects.to_json())
    filter_param = url_encode(filter_dict)
    return render_template('vreport.html',
                           vulnerabilities=v,
                           projects=p,
                           filters=filter_dict,
                           filter_param=filter_param,
                           version=VERSION,
                           last_import=last_import,
                           warning=state_warning)


def _set_state_warning(message):
    state = State.objects().first()
    if state:
        state.warning = message
    else:
        state = State(warning=message)
    state.save()


@app.route('/import/v_scan_data', methods=['GET'])
def import_data_from_harbor():
    # set warning during import
    _set_state_warning('import of vulnerability data ist running, reports may be inconsistent!')
    if request.args.get('create'):
        # delete all vulnerabilities
        deleted_count = Vulnerability.objects.delete()
        log.info('deleted vulnerabilities: %s' % deleted_count)
    # clear cache in harbor adapter
    log.info('clear cache: %r' % harbor.clear_cache())
    # set time of update
    up_datetime = datetime.utcnow()
    # get projects from harbor
    try:
        project_info = harbor.get_harbor_info(info_type='projects')
    except MaxRetryError:
        log.error('Connection to "%s" failed, no project info received' % arg_registry)
        _set_state_warning('last import of project data at %s failed,'
                           ' data is not up-to-date!' % up_datetime.strftime('%Y-%m-%d %H:%M:%S'))
        return redirect(url_for('vreport'))
    # get running containers from prometheus
    try:
        container_info = prom.get_running_containers()
    except MaxRetryError:
        log.error('Connection to "%s" failed, no container info received' % arg_prometheus)
        _set_state_warning('last import of container data at %s failed,'
                           ' data is not up-to-date!' % up_datetime.strftime('%Y-%m-%d %H:%M:%S'))
        return redirect(url_for('vreport'))
    running_images = get_running_images(container_info)
    update_project(project_info, up_datetime)
    updated = created = 0
    duration = 0.0
    try:
        # get vulnerability scan data from harbor api by project
        for p in get_projects(up_datetime):
            report_info = harbor.get_harbor_info(info_type='scan',
                                                 project_id=p['number'],
                                                 severity_level='',
                                                 cve_id='')
            log.info('start update for project  %s %s' % (p['number'], p['name']))
            if request.args.get('create'):
                stats = create_vulnerability(report_info, p['id'], up_datetime, running_images)
            else:
                stats = update_vulnerability(report_info, p['id'], up_datetime, running_images)
            updated += stats['updated']
            created += stats['created']
            duration += stats['duration']
            log.info('project nr: %s updated: %s created: %s duration: %s' % (p['number'],
                                                                              stats['updated'],
                                                                              stats['created'],
                                                                              stats['duration']))
    except MaxRetryError:
        log.error('Connection to "%s" failed, vulnerability data is not up-to-date!' % arg_registry)
        _set_state_warning('last import of vulnerability data at %s failed,'
                           ' data is not consistent!' % up_datetime.strftime('%Y-%m-%d %H:%M:%S'))
        return redirect(url_for('vreport'))
    log.info('------------- import of vulnerabilities finished -------------')
    log.info('update vulnerabilities duration: %s' % duration)
    log.info('updated: %s, created: %s' % (updated, created))
    # store update time and registry in database
    Update(registry=arg_registry,
           datetime=up_datetime,
           updated=updated,
           created=created).save()
    log.debug('update time: %s' % up_datetime)
    # clear warning after import
    _set_state_warning('')
    return redirect(url_for('vreport'))


@app.route('/reports_old', methods=['GET', 'POST'])
def reports():
    form = ReportsForm(request.form)
    # get projects from harbor
    project_info = harbor.get_harbor_info(info_type='projects')
    # get running containers from prometheus
    container_info = prom.get_running_containers()
    # handle information from html form
    if request.method == 'POST':
        severity = request.form.get('severity', '')
        projects = request.form.get('projects', '')
        cve = request.form['cve'].strip()
        # preserve state of checkbox 'fixed'
        if 'fixed' in request.form:
            fixed_check = 'checked'
        else:
            fixed_check = ''
        # preserve state of checkbox 'gzrunning'
        if 'gzrunning' in request.form:
            gzrunning_check = 'checked'
        else:
            gzrunning_check = ''
        # preserve state of checkbox 'pzrunning'
        if 'pzrunning' in request.form:
            pzrunning_check = 'checked'
        else:
            pzrunning_check = ''
        # preserve state of checkbox 'notassessed'
        if 'notassessed' in request.form:
            notassessed_check = 'checked'
        else:
            notassessed_check = ''

        # store query in session
        if '_user_id' in flask.session.keys():
            flask.session['severity'] = severity
            flask.session['projects'] = projects
            flask.session['cve'] = cve
            flask.session['fixed_check'] = fixed_check
            flask.session['gzrunning_check'] = gzrunning_check
            flask.session['pzrunning_check'] = pzrunning_check
            flask.session['notassessed_check'] = notassessed_check
            # set return_to for navigation
            flask.session['return_to'] = 'reports'

            # get vulnerability report from harbor
        report_info = harbor.get_harbor_info(info_type='scan',
                                             project_id=projects,
                                             severity_level=severity,
                                             cve_id=cve)
        # filter results if 'fixed' is checked
        if fixed_check:
            if cve == '':
                def determine(item):
                    return True if len(item['fixed']) < 1 else False

                for report in report_info['info']:
                    report['vlist'][:] = filterfalse(determine, report['vlist'])
        # filter results if 'gzrunning' or 'pzrunning' is checked
        if gzrunning_check or pzrunning_check:
            running_images = []
            running_hostaddr = []
            for item in container_info['info']:
                image = item['metric']['image']
                # remove repo name from image
                running_images.append('/'.join(image.split('/')[1:]))
                running_hostaddr.append(item['metric']['hostaddr'])

            if gzrunning_check and pzrunning_check:
                network = ''
            elif gzrunning_check:
                network = '193.135.'
            else:
                network = '10.36.'

            def image_running(value, network):
                if isinstance(value, dict):
                    item = value['image']
                else:
                    item = value
                if item in running_images:
                    if not network:
                        return True
                    else:
                        # find indices of running_images
                        i_images = [i for i, image in enumerate(running_images) if image == item]
                        for i in i_images:
                            if running_hostaddr[i].startswith(network):
                                return True
                        return False
                else:
                    return False

            if cve == '':
                report_info['info'] = list(filter(lambda x: image_running(x, network), report_info['info']))
            else:
                for report in report_info['info']:
                    image_list = []
                    package_list = []
                    severity_list = []
                    for count, value in enumerate(report['images']):
                        if image_running(value, network):
                            image_list.append(value)
                            package_list.append(report['packages'][count])
                            severity_list.append(report['severity'][count])
                    report['images'][:] = image_list
                    report['packages'][:] = package_list
                    report['severity'][:] = severity_list

        if cve == '':
            # add Assessment information
            a_report_info = []
            for item in report_info['info']:
                a_report = {}
                image = item['image']
                a_report['image'] = image
                a_vlist = []
                for v in item['vlist']:
                    assess = Assessment.objects(image=image,
                                                package=v['package'],
                                                cve_id=v['v_id'],
                                                severity=v['severity']).first()
                    if assess:
                        v['assess'] = dict(action='Update', path=PATH_ASSESS_UPDATE, text=assess.content.text)
                    else:
                        v['assess'] = dict(action='Create', path=PATH_ASSESS_CREATE, text='')
                    if assess and notassessed_check:
                        pass  # filter for not assessed vulnerabilities
                    else:
                        a_vlist.append(v)
                a_report['vlist'] = a_vlist
                a_report_info.append(a_report)
            report_info = dict(info=a_report_info)
            # count results
            results = sum(1 for x in report_info['info'] if len(x['vlist']) > 0)
        else:
            # add Assessment information
            a_report_info = []
            filtered = 0
            for item in report_info['info']:
                # list of indices where an assessment exists for an image and package
                assess_indices = []
                # list of paths with parameters to create or update an assessment
                assess_list = []
                for i, image in enumerate(item['images']):
                    assess = Assessment.objects(image=image,
                                                package=item['packages'][i],
                                                cve_id=item['cve_id'],
                                                severity=item['severity'][i]).first()
                    param = '?image=%s&package=%s&cve_id=%s&cve_link=%s&severity=%s' % (image,
                                                                                        item['packages'][i],
                                                                                        item['cve_id'],
                                                                                        item['links'][0],
                                                                                        item['severity'][i])
                    if assess:
                        assess_indices.append(i)
                        assess_list.append(dict(path='%s%s' % (PATH_ASSESS_UPDATE, param),
                                                action='Update', text=assess.content.text))
                    else:
                        assess_list.append(dict(path='%s%s' % (PATH_ASSESS_CREATE, param),
                                                action='Create', text=''))
                item['assess'] = assess_list
                # filter for vulnerabilities that have no assessment
                if notassessed_check:
                    # remove image, package and asses information when assessment exists
                    assess_indices.reverse()
                    for index in assess_indices:
                        del item['severity'][index]
                        del item['images'][index]
                        del item['packages'][index]
                        del item['assess'][index]
                a_report_info.append(item)
            report_info = dict(info=a_report_info)
            if report_info['info']:
                results = len(report_info['info'][0]['images'])
            else:
                results = 0
    else:
        report_info = dict(info={})
        results = 0
        if '_user_id' in flask.session.keys():
            projects = flask.session.get('projects', 0)
            severity = flask.session.get('severity', '')
            cve = flask.session.get('cve', '')
            fixed_check = flask.session.get('fixed_check', '')
            gzrunning_check = flask.session.get('gzrunning_check', '')
            pzrunning_check = flask.session.get('pzrunning_check', '')
            notassessed_check = flask.session.get('notassessed_check', '')
        else:
            projects = 0
            severity = ''
            cve = ''
            fixed_check = ''
            gzrunning_check = ''
            pzrunning_check = ''
            notassessed_check = ''

    return render_template('vreport_old.html', form=form, report_info=report_info, cve=cve, project_info=project_info,
                           version=VERSION, results=results,
                           selected=dict(projects=projects,
                                         severity=severity,
                                         fixed=fixed_check,
                                         gzrunning=gzrunning_check,
                                         pzrunning=pzrunning_check,
                                         notassessed=notassessed_check))


@app.route("/containers", methods=['GET', 'POST'])
def containers():
    report_info = prom.get_running_containers()
    return render_template('container.html', report_info=report_info)


@app.route("/clearcache", methods=['GET'])
def clear_cache():
    report_info = harbor.clear_cache()
    return render_template('clearcache.html', report_info=report_info)


@app.route("/infocache", methods=['GET'])
def info_cache():
    report_info = harbor.get_cache_info()
    return render_template('infocache.html', report_info=report_info)


@app.route("/reportmail", methods=['GET'])
def report_mail():
    with open(CONFIG_PATH_MAIL) as mailing_file:
        data = json.load(mailing_file)
    recipient = data['recipient']
    pw = data['pw']
    sender = data['sender']
    server = data['server']
    port = data['port']
    to = ", ".join(recipient)
    mail_message(sender, server, to, pw, port)
    text = 'Mail versendet!'
    return str(text)


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


def mailing(sender, server, to, pw, port, vsum, isum):
    try:
        link = 'https://%s' % os.environ['VIRTUAL_HOST']
    except KeyError:
        link = '* sorry, no link available *'
    subject = "Vreport"
    date = datetime.now(LOCAL_TIMEZONE).strftime("Date/Time: %d.%m.%Y/%H:%M")

    text = "Vulnerability Report for Docker Images" + "\n" + date + "\n" + "Critical Vulnerabilities: "\
           + str(vsum) + "\n" + "Affected images: " + str(isum) + "\n" + "Get more Information at " + link
    # Prepare actual message
    msg = EmailMessage()
    msg.set_content(text)
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject

    # Send the mail
    server = smtplib.SMTP(server, port)
    server.starttls()
    if pw:
        server.login(sender, pw)
    server.send_message(msg)
    server.quit()


def mail_message(sender, server, to, pw, port):
    v_list = []
    report_info = harbor.get_harbor_info(info_type='scan',
                                         severity_level='Critical')
    isum = len(report_info['info'])
    for image in report_info['info']:
        for v in image['vlist']:
            v_list.append(v['v_id'])

    vsum = len(set(v_list))
    mailing(sender, server, to, pw, port, vsum, isum)


if __name__ == "__main__":
    serve(app, host='0.0.0.0', port=5002)

