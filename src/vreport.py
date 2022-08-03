from email.message import EmailMessage
from itertools import filterfalse
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_mongoengine import MongoEngine
from flask_mongoengine.wtf import model_form
from wtforms import Form, validators, StringField, BooleanField
from extlib import harboradapter
from extlib import promadapter
from waitress import serve
import json
import smtplib
from datetime import datetime
import pytz
import sys
import os
import logging

log = logging.getLogger(__file__)

# App config.
DEBUG = False
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
app.config['MONGODB_SETTINGS'] = {
    'db': 'vreport',
    'host': 'localhost',
    'port': 27017
}
db = MongoEngine()
db.init_app(app)


class User(db.Document):
    email = db.StringField(required=True)
    first_name = db.StringField(max_length=50)
    last_name = db.StringField(max_length=50)


class Content(db.EmbeddedDocument):
    text = db.StringField()
    category = db.StringField(max_length=3)


class Assessment(db.Document):
    author = db.ReferenceField(User, reverse_delete_rule=1)
    image = db.StringField(max_length=150)
    package = db.StringField(max_length=30)
    cve_id = db.StringField(max_length=30)
    severity = db.StringField(max_length=30)
    content = db.EmbeddedDocumentField(Content)


PostForm = model_form(Assessment)


class ReportsForm(Form):
    severity = StringField('Severity ID:', validators=[validators.DataRequired()])
    projects = StringField('Projects ID:', validators=[validators.DataRequired()])
    cve = StringField('CVE ID:', validators=[validators.DataRequired()])
    fixed = BooleanField('Fixed')
    gzrunning = BooleanField('Gzrunning')
    pzrunning = BooleanField('Pzrunning')


class MailForm(Form):
    recipient = StringField('Empfänger:', validators=[validators.DataRequired()])


if len(sys.argv) < 6:
    print('run with -e CREDENTIALS=secret -e CACHE_MAXSIZE=600 -e REGISTRY=harbor-aio.so.ch -e API="" '
          '-e PROMETHEUS=dockprom.rootso.org')
    sys.exit(0)

arg_credentials = sys.argv[1]
arg_cache_maxsize = sys.argv[2]
arg_registry = sys.argv[3]
if sys.argv[4] == 'none':
    arg_api = ''
else:
    arg_api = sys.argv[4]
arg_prometheus = sys.argv[5]

harbor = harboradapter.HarborAdapter(credentials=arg_credentials,
                                     cache_maxsize=arg_cache_maxsize,
                                     registry=arg_registry,
                                     api_version=arg_api,
                                     stage_dev=False)

prom = promadapter.PrometheusAdapter(credentials='',
                                     prometheus=arg_prometheus,
                                     api_version='v1',
                                     protocol='http')

VERSION = '2.2.0'


@app.route('/user', methods=['GET'])
def user_query():
    test_c = User(email='ron.miller@romics.ch',
                  first_name='Ron',
                  last_name='Miller')
    test_c.save()
    users = User.objects
    if not users:
        return jsonify({'error': 'data not found'})
    else:
        return jsonify(users.to_json())


@app.route('/user/create', methods=['GET', 'POST'])
def user_create():
    form = PostForm(request.form)
    if request.method == 'POST':
        user = User(email=request.form['email'],
                    first_name=request.form['first_name'],
                    last_name=request.form['last_name'])
        user.save()
        redirect('done')
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    return render_template('user_create.html', form=form, users=users)


@app.route('/user/delete', methods=['GET'])
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
    if request.args.get('image'):
        image = request.args.get('image')
        assess = Assessment.objects(image=image).first()
    else:
        assess = Assessment.objects
    if not assess:
        return jsonify({'error': 'data not found'})
    else:
        assessments = json.loads(assess.to_json())
        return render_template('assess_list.html', assessments=assessments)


@app.route('/assess/create', methods=['GET', 'POST'])
def assess_create():
    form = PostForm(request.form)
    users = User.objects
    if not users:
        users = None
    else:
        users = json.loads(users.to_json())
    log.info('rmi validate: %r' % form.validate())
    if request.method == 'POST':  # and form.validate():
        if request.form['author']:
            log.info('rmi author: %r' % request.form['author'])
            author_id = request.form['author']
        else:
            author_id = None
        content = Content(text=request.form['text'],
                          category=request.form['category'])
        asses = Assessment(image=request.form['image'],
                           package=request.form['package'],
                           cve_id=request.form['cve_id'],
                           severity=request.form['severity'],
                           content=content,
                           author=author_id
                           )
        asses.save()
        redirect('done')
    return render_template('assess_create.html', form=form, users=users)


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
                        i_images = [i for i,image in enumerate(running_images) if image==item]
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
                    for count, value in enumerate(report['images']):
                        if image_running(value, network):
                            image_list.append(value)
                            package_list.append(report['packages'][count])
                    report['images'][:] = image_list
                    report['packages'][:] = package_list

        if cve == '':
            results = sum(1 for x in report_info['info'] if len(x['vlist']) > 0)
        else:
            results = len(report_info['info'])
    else:
        report_info = dict(info={})
        projects = 0
        results = 0
        severity = ''
        cve = ''
        fixed_check = ''
        gzrunning_check = ''
        pzrunning_check = ''

    return render_template('vreport.html', form=form, report_info=report_info, cve=cve, project_info=project_info,
                           version=VERSION, results=results,
                           selected=dict(projects=projects,
                                         severity=severity,
                                         fixed=fixed_check,
                                         gzrunning=gzrunning_check,
                                         pzrunning=pzrunning_check))


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


@app.route("/mailing", methods=['GET', 'POST'])
def mailing_form():
    form = MailForm(request.form)
    global recipient
    global data
    global pw
    global sender
    global server
    global port
    global to

    with open('config/mailing_data_json.txt') as mailing_file:
        data = json.load(mailing_file)
        pw = data['pw']
        sender = data['sender']
        server = data['server']
        port = data['port']

    if request.method == 'POST':
        recipient = request.form['recipient']
        to = recipient
        mail_message()

    return render_template('mailing.html', form=form, data=data)


@app.route("/reportmail", methods=['GET'])
def report_mail():
    with open('config/mailing_data_json.txt') as mailing_file:
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


def mailing(sender, server, to, pw, port, vsum, isum):
    link = 'https://%s' % os.environ['VIRTUAL_HOST']
    subject = "Vreport"
    date = datetime.now(pytz.timezone('Europe/Zurich')).strftime("Date/Time: %d.%m.%Y/%H:%M")

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
    # return


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
    log_level = "INFO"
    logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s %(filename)s > %(message)s',
                        datefmt="%Y-%m-%d %H:%M:%S",
                        level=logging.getLevelName(log_level))  # filename='myapp.log'
    serve(app, host='0.0.0.0', port=5002)

