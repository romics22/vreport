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
import mongoengine.errors
import json
import smtplib
import sys
import os
import logging

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
    text = db.StringField()
    category = db.StringField(max_length=3)
    updated_at = db.DateTimeField(default=datetime.utcnow)


class Assessment(db.Document):
    author = db.ReferenceField(User, reverse_delete_rule=1)
    image = db.StringField(max_length=150)
    package = db.StringField(max_length=100)
    cve_id = db.StringField(max_length=50)
    cve_link = db.StringField(max_length=150)
    severity = db.StringField(max_length=30)
    content = db.EmbeddedDocumentField(Content)


AssesForm = model_form(Assessment)
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

VERSION = '2.3.0'

# local timezone
LOCAL_TIMEZONE = datetime.now().astimezone().tzinfo
# file path to mailing configuration
CONFIG_PATH_MAIL = '../config/mailing_data_json.txt'

# url paths
PATH_ASSESS_CREATE = '/assess/create'
PATH_ASSESS_UPDATE = '/assess/update'


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.objects(id=user_id).first()
    except mongoengine.errors.ValidationError:
        return None


@app.route('/user', methods=['GET'])
@login_required
def user_query():
    if current_user.name == 'admin':
        users = User.objects
        if not users:
            users = None
        else:
            users = json.loads(users.to_json())
        return render_template('user_list.html', users=users)
    else:
        return render_template('403.html'), 403


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
                return redirect(next_page or url_for('reports'))
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


@app.route('/user/delete', methods=['GET'])
@login_required
def user_delete():
    # delete user by id, e.g ?user_id=62ea78573656869bd50f5a7d
    user_id = request.args.get('user_id')
    if user_id:
        user = User.objects(id=user_id).first()
        if not user:
            return jsonify({'error': 'data not found'})
        else:
            user.delete()
        # return jsonify(user.to_json())
        return redirect(url_for('user_create'))
    else:
        return jsonify({'error': 'data not found'})


@app.route('/assess', methods=['GET'])
def assess_query():
    # log.info('rmi args: %s' % list(request.args.keys()))
    valid_filters = ['image', 'package', 'cve_id', 'severity']
    filter_dict = dict(request.args)
    # remove empty values and not valid keys
    filter_dict = {k: v for k, v in filter_dict.items() if v and k in valid_filters}
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
    # set return_to if user is logged in
    if '_user_id' in flask.session.keys():
        flask.session['return_to'] = 'assess_query'
    return render_template('assess_list.html',
                           assessments=assess_list,
                           users=User,
                           filters=filter_dict,
                           filter_param=filter_param)


@app.route(PATH_ASSESS_CREATE, methods=['GET', 'POST'])
@login_required
def assess_create():
    form = AssesForm(request.form)
    for field in ['image', 'package', 'cve_id', 'cve_link', 'severity']:
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
        asses = Assessment(image=request.form['image'],
                           package=request.form['package'],
                           cve_id=request.form['cve_id'],
                           cve_link=request.form['cve_link'],
                           severity=request.form['severity'],
                           content=content,
                           author=author_id
                           )
        asses.save()
        return redirect(url_for('reports'))
    return render_template('assess_create.html', form=form, users=users)


@app.route(PATH_ASSESS_UPDATE, methods=['GET', 'POST'])
@login_required
def assess_update():
    form = AssesForm(request.form)
    # get assessment object from request.args
    if request.args.get('assess_id'):
        assess = Assessment.objects(id=request.args.get('assess_id')).first()
    else:
        assess = Assessment.objects(image=request.args.get('image'),
                                    package=request.args.get('package'),
                                    cve_id=request.args.get('cve_id'),
                                    severity=request.args.get('severity')).first()
    if not assess:
        return jsonify({'error': 'data not found'})
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
                return redirect(url_for('assess_query'))
            else:
                assess.content.text = request.form['text']
                assess.content.category = request.form['category']
                assess.content.updated_at = datetime.utcnow
                assess.author = User.objects(id=request.form['author']).first().id
                assess.save()
                if flask.session.get('return_to') == 'reports':
                    return redirect(url_for(flask.session.get('return_to')))
                return_to = flask.session.get('return_to', 'assess_query')
                return redirect(url_for(return_to, **dict(request.args)))
        return render_template('assess_update.html', form=form, users=users)


@app.route('/assess/delete', methods=['GET'])
@login_required
def assess_delete():
    # delete assessment by id, e.g ?assess_id=62ea78573656869bd50f5a7d
    assess_id = request.args.get('assess_id')
    if assess_id:
        assess = Assessment.objects(id=assess_id).first()
        if not assess:
            return jsonify({'error': 'data not found'})
        else:
            assess.delete()
        return redirect(url_for('assess_query'))
    else:
        return jsonify({'error': 'data not found'})


@app.route("/", methods=['GET', 'POST'])
def reports():
    form = ReportsForm(request.form)
    # get projects from harbor
    project_info = harbor.get_harbor_info(info_type='projects')
    # get running containers from prometheus
    container_info = prom.get_running_containers()
    # handle information from html form
    if request.method == 'POST':
        severity = request.form['severity']
        projects = request.form['projects']
        cve = request.form['cve']
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

    return render_template('vreport.html', form=form, report_info=report_info, cve=cve, project_info=project_info,
                           version=VERSION, results=results,
                           selected=dict(projects=projects,
                                         severity=severity,
                                         fixed=fixed_check,
                                         gzrunning=gzrunning_check,
                                         pzrunning=pzrunning_check,
                                         notassessed=notassessed_check))


@app.route("/test", methods=['GET', 'POST'])
def test():
    report_info = harbor.get_harbor_info(info_type='scan',
                                         project_id='2',
                                         severity_level='Critical',
                                         cve_id='')

    return report_info


@app.route("/containers", methods=['GET', 'POST'])
def containers():
    report_info = prom.get_running_containers()
    return render_template('container.html', report_info=report_info)


@app.route("/clearcache", methods=['GET'])
def clear_cache():
    report_info = harbor.clear_cache()
    return render_template('clearcache.html', report_info=report_info)


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

