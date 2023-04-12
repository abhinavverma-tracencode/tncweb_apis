import os
import re
import json
import base64
import inspect
import logging
import tempfile
import datetime
import traceback

import werkzeug
from werkzeug import urls
from werkzeug import utils
from werkzeug import exceptions
from werkzeug.urls import iri_to_uri

import odoo
from odoo import _
from odoo import api
from odoo import tools
from odoo import http
from odoo import models
from odoo import release
from odoo.http import request
from odoo.http import Response
from odoo.tools.misc import str2bool
from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)

REST_VERSION = {
    'server_version': release.version,
    'server_version_info': release.version_info,
    'server_serie': release.serie,
    'api_version': 2,
}

NOT_FOUND = {
    'error': 'unknown_command',
}

DB_INVALID = {
    'error': 'invalid_db',
}

FORBIDDEN = {
    'error': 'token_invalid',
}

NO_API = {
    'error': 'rest_api_not_supported',
}

LOGIN_INVALID = {
    'error': 'invalid_login',
}

DBNAME_PATTERN = '^[a-zA-Z0-9][a-zA-Z0-9_.-]+$'

def abort(message, rollback=False, status=403):
    response = Response(json.dumps(message,
        sort_keys=True, indent=4, cls=LoginController),
        content_type='application/json;charset=utf-8', status=status) 
    if request._cr and rollback:
        request._cr.rollback()
    exceptions.abort(response)
    
def check_access_token():
    token = request.params.get('token') and request.params.get('token').strip()
    if not token:
        abort(FORBIDDEN)
    env = api.Environment(request.cr, odoo.SUPERUSER_ID, {})
    uid = env['web_apis.token'].check_access_token(token)
    if not uid:
        abort(FORBIDDEN)
    request._uid = uid
    request._env = api.Environment(request.cr, uid, request.session.context or {})


def ensure_database():
    db = request.params.get('db') and request.params.get('db').strip()
    if db and db not in http.db_filter([db]):
        db = None
    if not db and request.session.db and http.db_filter([request.session.db]):
        db = request.session.db
    if not db:
        db = http.db_monodb(request.httprequest)
    if not db:
        abort(DB_INVALID, status=404)
    if db != request.session.db:
        request.session.logout()
    request.session.db = db
    try:
        env = api.Environment(request.cr, odoo.SUPERUSER_ID, {})
        module = env['ir.module.module'].search([['name', '=', "web_apis"]], limit=1)
        if module.state != 'installed':
            abort(NO_API, status=500)
    except Exception as error:
        _logger.error(error)
        abort(DB_INVALID, status=404)


    
def check_params(params):
    missing = []
    for key, value in params.items():
        if not value:
            missing.append(key)
    if missing:
        abort({'error': "arguments_missing %s" % str(missing)}, status=400)


class LoginController(json.JSONEncoder):
    def default(self, obj):
        def encode(item):
            if isinstance(item, models.BaseModel):
                vals = {}
                for name, field in item._fields.items():
                    if name in item:
                        if isinstance(item[name], models.BaseModel):
                            records = item[name]
                            if len(records) == 1:
                                # try:
                                #     vals[name] = (records.id, records.sudo().display_name, records.sudo().state, records.sudo().lat, records.sudo().lng, records.sudo().flexibility)
                                # except:
                                #     vals[name] = (records.id, records.sudo().display_name)
                                val = []
                                for record in records:
                                    try:
                                        val.append((record.id, record.sudo().display_name, record.sudo().state, record.sudo().lat, record.sudo().lng, record.sudo().flexibility, record.sudo().description))
                                    except:
                                        val.append((record.id, record.sudo().display_name))
                                vals[name] = val
                            else:
                                val = []
                                for record in records:
                                    try:
                                        val.append((record.id, record.sudo().display_name, record.sudo().state, record.sudo().lat, record.sudo().lng, record.sudo().flexibility, record.sudo().description))
                                    except:
                                        val.append((record.id, record.sudo().display_name))
                                vals[name] = val
                        else:
                            try:
                                vals[name] = item[name].decode()
                            except UnicodeDecodeError:
                                vals[name] = item[name].decode('latin-1')
                            except AttributeError:
                                vals[name] = item[name]
                    else:
                        vals[name] = None
                return vals
            if inspect.isclass(item):
                return item.__dict__
            try:
                return json.JSONEncoder.default(self, item)
            except TypeError:
                return "error"
        try:
            try:
                result = {}
                for key, value in obj.items():
                    result[key] = encode(item)
                return result
            except AttributeError:
                result = []
                for item in obj:
                    result.append(encode(item))
                return result
        except TypeError:
            return encode(item)


class WebTokenAccess(http.Controller):
    
    
    @http.route('/api/database/create', auth="none", type='http', methods=['POST'], csrf=False)
    def api_database_create(self, master_password="admin", lang="en_US", database_name=None, 
                        admin_login=None, admin_password=None, **kw):
        check_params({
            'database_name': database_name,
            'admin_login': admin_login,
            'admin_password': admin_password})
        try:
            if not re.match(DBNAME_PATTERN, database_name):
                raise Exception(_('Invalid database name.'))
            http.dispatch_rpc('db', 'create_database', [
                master_password,
                database_name,
                bool(kw.get('demo')),
                lang,
                admin_password,
                admin_login,
                kw.get('country_code') or False])
            return Response(json.dumps(True,
                sort_keys=True, indent=4, cls=LoginController),
                content_type='application/json;charset=utf-8', status=200)
        except Exception as error:
            _logger.error(error)
            abort({'error': traceback.format_exc()}, status=400)


    
    @http.route('/api/authenticate',  auth="none", type='json', methods=['POST'], csrf=False)
    def api_authenticate(self, db=None, login=None, password=None, **kw):    
        check_params({'db': db, 'login': login, 'password': password})

        ensure_database()
        uid = request.session.authenticate(db, login, password)
        if uid:
            env = api.Environment(request.cr, odoo.SUPERUSER_ID, {})
            token = env['web_apis.token'].generate_token(uid)
            return Response(json.dumps({'token': token.token, 'uid':uid},
                sort_keys=True, indent=4, cls=LoginController),
                content_type='application/json;charset=utf-8', status=200) 
        else:
            abort(LOGIN_INVALID, status=401) 
        
class Registration(http.Controller):

    @http.route('/create_user_webform',auth="public", type='http' ,website=True)
    def create_webform(self, **kw):
        return http.request.render('web_apis.Create_User',{})
        
        
    @http.route('/Create/User/Register',auth="public", type='http' )
    def create_user_register(self, **kw):
        vals = {
            'Addrese':kw.get('Addrese'),
            'email_id':kw.get('email_id'),
            'password' :kw.get('password'),
            'mobile_number':kw.get('mobile_number'),

        }
        request.env['registration.api'].sudo().create(vals)
        
        #return request.render('web_apis.patient_thanks',{})
